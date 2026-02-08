from collections import deque
import json
import queue
import signal
import threading
import time
import datetime
import subprocess
import re
from typing import Any, Deque, Dict, Optional, Set

from .config import ServiceConfig
from .detector import Alert, Detector
from .events import LogParser, extract_timestamp
from .history import HistoryStore, should_store_event
from .sources import spawn_source_threads
from .telegram import TelegramNotifier
from .web import DashboardServer

ALERT_SEVERITY_RANK = {
    "info": 10,
    "warning": 20,
    "critical": 30,
}


class MonitoringService:
    def __init__(self, config: ServiceConfig) -> None:
        self.config = config
        signer_names = self._load_signer_names(config.signer_names_path)
        self.detector = Detector(config.detector, signer_names=signer_names)
        self.parser = LogParser()
        self.stop_event = threading.Event()
        self.queue: "queue.Queue[tuple]" = queue.Queue(maxsize=10000)
        self.finished_sources = 0
        self.expected_sources = 0
        self.latest_event_ts: Optional[float] = None
        self.replay_clock_enabled = (
            config.mode == "files" and config.from_beginning and not config.run_once
        )
        self.replay_wall_base_ts: float = time.time()
        self.replay_event_base_ts: Optional[float] = None
        self.latest_event_ts_by_source: Dict[str, float] = {}
        self.replay_sources: Set[str] = set()
        self.suppress_notifications: bool = False
        self.prefetch_sources: Set[str] = set()
        if config.mode == "files":
            if config.node_log_path:
                self.replay_sources.add("node")
            if config.signer_log_path:
                self.replay_sources.add("signer")
        elif config.mode == "journalctl":
            self.prefetch_sources = {"node", "signer"}
        self.state_lock = threading.Lock()
        self.recent_alerts: Deque[Dict[str, Any]] = deque(maxlen=200)
        self.recent_reports: Deque[Dict[str, Any]] = deque(maxlen=200)
        self.history_store: Optional[HistoryStore] = None
        if config.history.enabled:
            self.history_store = HistoryStore(
                path=config.history.path,
                retention_hours=config.history.retention_hours,
            )

        self.notifier: Optional[TelegramNotifier] = None
        if config.telegram.enabled:
            self.notifier = TelegramNotifier(config.telegram.token, config.telegram.chat_id)

        self.dashboard_server: Optional[DashboardServer] = None
        if config.web.enabled:
            self.dashboard_server = DashboardServer(
                host=config.web.host,
                port=config.web.port,
                state_provider=self._dashboard_state,
                history_provider=self._history_api if self.history_store else None,
                history_window_provider=self._history_window_api if self.history_store else None,
                schema_provider=self._schema_api if self.history_store else None,
                alerts_provider=self._alerts_api if self.history_store else None,
                reports_provider=self._reports_api if self.history_store else None,
                report_provider=self._report_api if self.history_store else None,
                report_logs_provider=self._report_logs_api if self.history_store else None,
                sql_provider=self._sql_api if self._sql_api_enabled() else None,
            )

        signal.signal(signal.SIGINT, self._handle_stop)
        signal.signal(signal.SIGTERM, self._handle_stop)

    def run(self) -> int:
        try:
            if self.dashboard_server is not None:
                try:
                    self.dashboard_server.start()
                    print(
                        "[INFO] Dashboard listening on http://%s:%d"
                        % (self.config.web.host, self.config.web.port),
                        flush=True,
                    )
                except OSError as exc:
                    print(
                        "[WARN] Dashboard disabled (failed to bind %s:%d): %s"
                        % (self.config.web.host, self.config.web.port, exc),
                        flush=True,
                    )
                    self.dashboard_server = None

            if self.config.mode == "files" and self.config.run_once:
                return self._run_files_once_merged()

            self.expected_sources = spawn_source_threads(
                mode=self.config.mode,
                node_log_path=self.config.node_log_path,
                signer_log_path=self.config.signer_log_path,
                node_journal_unit=self.config.node_journal_unit,
                signer_journal_unit=self.config.signer_journal_unit,
                out_queue=self.queue,
                stop_event=self.stop_event,
                from_beginning=self.config.from_beginning,
                run_once=self.config.run_once,
                poll_interval_seconds=self.config.poll_interval_seconds,
            )

            if self.expected_sources == 0:
                raise RuntimeError("No log sources configured.")

            while not self.stop_event.is_set():
                try:
                    self._drain_queue_once()
                except queue.Empty:
                    pass
                self._run_periodic()

                if self.config.run_once and self.finished_sources >= self.expected_sources:
                    # Flush any final queued lines and emit a final report.
                    while True:
                        try:
                            self._drain_queue_once(wait_timeout=0.0)
                        except queue.Empty:
                            break
                    self._run_periodic(force_report=True)
                    self.stop_event.set()

            return 0
        finally:
            if self.dashboard_server is not None:
                self.dashboard_server.stop()
            if self.history_store is not None:
                self.history_store.close()

    def _run_files_once_merged(self) -> int:
        node_handle = (
            open(self.config.node_log_path, "r", encoding="utf-8", errors="replace")
            if self.config.node_log_path
            else None
        )
        signer_handle = (
            open(self.config.signer_log_path, "r", encoding="utf-8", errors="replace")
            if self.config.signer_log_path
            else None
        )
        try:
            node_line = node_handle.readline() if node_handle else ""
            signer_line = signer_handle.readline() if signer_handle else ""

            while node_line or signer_line:
                if node_line and not signer_line:
                    self._process_line("node", node_line)
                    node_line = node_handle.readline() if node_handle else ""
                elif signer_line and not node_line:
                    self._process_line("signer", signer_line)
                    signer_line = signer_handle.readline() if signer_handle else ""
                else:
                    node_ts = extract_timestamp(node_line)
                    signer_ts = extract_timestamp(signer_line)
                    if node_ts <= signer_ts:
                        self._process_line("node", node_line)
                        node_line = node_handle.readline() if node_handle else ""
                    else:
                        self._process_line("signer", signer_line)
                        signer_line = signer_handle.readline() if signer_handle else ""

                self._run_periodic()

            self._run_periodic(force_report=True)
            return 0
        finally:
            if node_handle:
                node_handle.close()
            if signer_handle:
                signer_handle.close()

    def _drain_queue_once(self, wait_timeout: float = 1.0) -> None:
        source, line = self.queue.get(timeout=wait_timeout)
        if line is None:
            self.finished_sources += 1
            return

        self._process_line(source, line)

    def _process_line(self, source: str, line: str) -> None:
        if line == "__meta__prefetch_start__":
            self.suppress_notifications = True
            with self.state_lock:
                self.detector.suppress_alerts = True
            return
        if line == "__meta__prefetch_end__":
            if source in self.prefetch_sources:
                self.prefetch_sources.discard(source)
            if not self.prefetch_sources:
                self.suppress_notifications = False
                with self.state_lock:
                    self.detector.suppress_alerts = False
            return

        events = self.parser.parse_line(source, line)
        alert_batch = []
        with self.state_lock:
            self.detector.process_line(source)
            for event in events:
                if self.latest_event_ts is None:
                    self.latest_event_ts = event.ts
                else:
                    self.latest_event_ts = max(self.latest_event_ts, event.ts)
                previous_source_ts = self.latest_event_ts_by_source.get(source)
                if previous_source_ts is None:
                    self.latest_event_ts_by_source[source] = event.ts
                else:
                    self.latest_event_ts_by_source[source] = max(
                        previous_source_ts, event.ts
                    )
                if self.replay_clock_enabled and self.replay_event_base_ts is None:
                    self.replay_event_base_ts = event.ts
                alert_batch.extend(self.detector.process_event(event))
        if self.history_store is not None:
            for event in events:
                if should_store_event(event.kind, event.fields):
                    self.history_store.record_event(
                        ts=event.ts,
                        source=event.source,
                        kind=event.kind,
                        data=event.fields,
                        line=event.line,
                    )
                if event.kind in ("node_sortition_winner_selected", "node_sortition_winner_rejected"):
                    self._record_sortition_event(event)
        self._publish_alerts(alert_batch)

    def _run_periodic(self, force_report: bool = False) -> None:
        now = self._state_now()
        with self.state_lock:
            if self.detector.start_ts > now:
                self.detector.start_ts = now
            alerts, report = self.detector.tick(now=now)
            if force_report and report is None:
                report = self.detector.build_report(now)
        self._publish_alerts(alerts)

        if report:
            print(report, flush=True)
            self._write_report(report)
            if (
                self.notifier
                and not self.suppress_notifications
                and self.config.telegram.send_reports
            ):
                self.notifier.send(report)

    def _write_report(self, report: str) -> None:
        if not self.config.report_output_path:
            return
        with open(self.config.report_output_path, "a", encoding="utf-8") as handle:
            handle.write(report)
            handle.write("\n")

    def _publish_alerts(self, alerts: list) -> None:
        for alert in alerts:
            self._publish_alert(alert)

    def _publish_alert(self, alert: Alert) -> None:
        snapshot: Optional[Dict[str, Any]] = None
        recent_rejections: Optional[list] = None
        with self.state_lock:
            self.recent_alerts.append(
                {
                    "ts": alert.ts,
                    "severity": alert.severity,
                    "key": alert.key,
                    "message": alert.message,
                }
            )
            if self.history_store is not None and alert.severity in ("warning", "critical"):
                snapshot = self.detector.snapshot(now=alert.ts)
                recent_rejections = list(self.detector.recent_rejections)
        rendered = "[ALERT][%s] %s" % (alert.severity.upper(), alert.message)
        print(rendered, flush=True)
        if self.history_store is not None:
            alert_id = self.history_store.record_alert(
                ts=alert.ts,
                severity=alert.severity,
                key=alert.key,
                message=alert.message,
            )
            if alert.severity in ("warning", "critical"):
                recent_events = self.history_store.report_context_events(alert.ts)
                proposal_timeline = None
                signature_hash = self._extract_signature_hash(alert)
                if signature_hash:
                    proposal_timeline = self._build_proposal_timeline(
                        signature_hash, recent_events
                    )
                report_payload = {
                    "alert": {
                        "ts": alert.ts,
                        "severity": alert.severity,
                        "key": alert.key,
                        "message": alert.message,
                    },
                    "snapshot": snapshot,
                    "recent_events": recent_events,
                    "recent_alerts": list(self.recent_alerts)[-20:],
                    "recent_rejections": recent_rejections,
                    "proposal_timeline": proposal_timeline,
                }
                report_id = self.history_store.create_report(
                    ts=alert.ts,
                    severity=alert.severity,
                    alert_key=alert.key,
                    summary=alert.message,
                    data=report_payload,
                )
                self.history_store.attach_report(alert_id, report_id)
                with self.state_lock:
                    self.recent_reports.append(
                        {
                            "ts": alert.ts,
                            "report_id": report_id,
                            "alert_key": alert.key,
                            "severity": alert.severity,
                            "summary": alert.message,
                        }
                    )
        if (
            self.notifier
            and not self.suppress_notifications
            and self._should_notify_telegram_for_alert(alert)
        ):
            self.notifier.send(rendered)

    def _history_api(self, params: Dict[str, list]) -> Dict[str, Any]:
        if self.history_store is None:
            return {"events": []}
        from_ts = _float_query_param(params, "from")
        to_ts = _float_query_param(params, "to")
        kinds = params.get("kind") or params.get("kinds")
        limit = _int_query_param(params, "limit", 200)
        events = self.history_store.query_events(
            from_ts=from_ts,
            to_ts=to_ts,
            kinds=kinds,
            limit=limit,
        )
        return {"events": events}

    def _history_window_api(self, params: Dict[str, list]) -> Dict[str, Any]:
        if self.history_store is None:
            return {
                "start_ts": None,
                "stop_ts": None,
                "duration_seconds": 0,
                "summary": {},
                "alerts": [],
                "reports": [],
                "timeline": [],
                "anomalous_proposals": [],
                "event_kind_counts": {},
            }

        now = self._state_now()
        start_ts = _float_query_param(params, "start")
        if start_ts is None:
            start_ts = _float_query_param(params, "from")
        stop_ts = _float_query_param(params, "stop")
        if stop_ts is None:
            stop_ts = _float_query_param(params, "to")
        if stop_ts is None:
            stop_ts = now
        if start_ts is None:
            start_ts = max(0.0, float(stop_ts) - 600.0)
        if start_ts > stop_ts:
            start_ts, stop_ts = stop_ts, start_ts

        events_limit = max(100, min(5000, _int_query_param(params, "events_limit", 1600) or 1600))
        alerts_limit = max(50, min(1000, _int_query_param(params, "alerts_limit", 300) or 300))
        reports_limit = max(20, min(500, _int_query_param(params, "reports_limit", 200) or 200))
        timeline_limit = max(50, min(1200, _int_query_param(params, "timeline_limit", 400) or 400))
        proposal_limit = max(10, min(300, _int_query_param(params, "proposal_limit", 80) or 80))

        alerts = self.history_store.query_alerts(
            from_ts=start_ts,
            to_ts=stop_ts,
            limit=alerts_limit,
        )
        reports = self.history_store.list_reports(
            from_ts=start_ts,
            to_ts=stop_ts,
            limit=reports_limit,
        )
        events_desc = self.history_store.query_events(
            from_ts=start_ts,
            to_ts=stop_ts,
            limit=events_limit,
        )
        events = list(reversed(events_desc))

        event_kind_counts: Dict[str, int] = {}
        for event in events:
            kind = str(event.get("kind") or "unknown")
            event_kind_counts[kind] = event_kind_counts.get(kind, 0) + 1

        timeline_kinds = {
            "node_consensus",
            "node_burnchain_reorg",
            "node_sortition_winner_selected",
            "node_sortition_winner_rejected",
            "node_tenure_change",
            "signer_block_proposal",
            "signer_block_rejection",
            "signer_rejection_threshold_reached",
            "signer_threshold_reached",
            "signer_block_pushed",
            "signer_new_block_event",
        }
        timeline = []
        for event in events:
            kind = str(event.get("kind") or "")
            if kind not in timeline_kinds:
                continue
            timeline.append(self._summarize_history_event(event))
        if len(timeline) > timeline_limit:
            timeline = timeline[-timeline_limit:]

        proposal_groups: Dict[str, Dict[str, Any]] = {}
        for event in events:
            kind = str(event.get("kind") or "")
            if kind not in {
                "signer_block_proposal",
                "signer_block_acceptance",
                "signer_block_rejection",
                "signer_rejection_threshold_reached",
                "signer_threshold_reached",
                "signer_block_pushed",
                "signer_new_block_event",
            }:
                continue
            data = event.get("data") or {}
            sig = data.get("signer_signature_hash")
            if not isinstance(sig, str) or not sig:
                continue
            entry = proposal_groups.get(sig)
            if entry is None:
                entry = {
                    "signature_hash": sig,
                    "block_height": data.get("block_height"),
                    "burn_height": data.get("burn_height"),
                    "first_ts": event.get("ts"),
                    "last_ts": event.get("ts"),
                    "proposal_ts": None,
                    "approved_ts": None,
                    "rejected_ts": None,
                    "pushed_ts": None,
                    "accept_count": 0,
                    "reject_count": 0,
                    "threshold_seen": False,
                    "rejection_threshold_seen": False,
                    "reject_reasons": {},
                }
                proposal_groups[sig] = entry
            event_ts = float(event.get("ts") or 0.0)
            first_ts = float(entry.get("first_ts") or event_ts)
            last_ts = float(entry.get("last_ts") or event_ts)
            entry["first_ts"] = min(first_ts, event_ts)
            entry["last_ts"] = max(last_ts, event_ts)
            if entry.get("block_height") is None and data.get("block_height") is not None:
                entry["block_height"] = data.get("block_height")
            if entry.get("burn_height") is None and data.get("burn_height") is not None:
                entry["burn_height"] = data.get("burn_height")
            if kind == "signer_block_proposal":
                proposal_ts = entry.get("proposal_ts")
                entry["proposal_ts"] = event_ts if proposal_ts is None else min(float(proposal_ts), event_ts)
            elif kind == "signer_block_acceptance":
                entry["accept_count"] = int(entry.get("accept_count") or 0) + 1
            elif kind == "signer_block_rejection":
                entry["reject_count"] = int(entry.get("reject_count") or 0) + 1
                reason = data.get("reject_reason")
                if isinstance(reason, str) and reason:
                    reasons = entry.get("reject_reasons") or {}
                    reasons[reason] = int(reasons.get(reason) or 0) + 1
                    entry["reject_reasons"] = reasons
            elif kind == "signer_threshold_reached":
                entry["threshold_seen"] = True
                approved_ts = entry.get("approved_ts")
                entry["approved_ts"] = event_ts if approved_ts is None else min(float(approved_ts), event_ts)
            elif kind == "signer_rejection_threshold_reached":
                entry["rejection_threshold_seen"] = True
                rejected_ts = entry.get("rejected_ts")
                entry["rejected_ts"] = event_ts if rejected_ts is None else min(float(rejected_ts), event_ts)
            elif kind in ("signer_block_pushed", "signer_new_block_event"):
                pushed_ts = entry.get("pushed_ts")
                entry["pushed_ts"] = event_ts if pushed_ts is None else min(float(pushed_ts), event_ts)

        proposal_summaries = []
        for entry in proposal_groups.values():
            threshold_seen = bool(entry.get("threshold_seen"))
            rejection_threshold_seen = bool(entry.get("rejection_threshold_seen"))
            pushed_ts = entry.get("pushed_ts")
            if rejection_threshold_seen:
                status = "rejected"
            elif threshold_seen or pushed_ts is not None:
                status = "approved"
            else:
                status = "in_progress"
            reject_count = int(entry.get("reject_count") or 0)
            if reject_count <= 0 and not rejection_threshold_seen:
                continue
            reasons = entry.get("reject_reasons") or {}
            top_reason = None
            if reasons:
                top_reason = sorted(
                    reasons.items(),
                    key=lambda item: (-int(item[1]), str(item[0])),
                )[0][0]
            proposal_summaries.append(
                {
                    "signature_hash": entry.get("signature_hash"),
                    "block_height": entry.get("block_height"),
                    "burn_height": entry.get("burn_height"),
                    "status": status,
                    "first_ts": entry.get("first_ts"),
                    "last_ts": entry.get("last_ts"),
                    "proposal_ts": entry.get("proposal_ts"),
                    "approved_ts": entry.get("approved_ts"),
                    "rejected_ts": entry.get("rejected_ts"),
                    "pushed_ts": entry.get("pushed_ts"),
                    "accept_count": int(entry.get("accept_count") or 0),
                    "reject_count": reject_count,
                    "top_reject_reason": top_reason,
                }
            )
        proposal_summaries.sort(key=lambda item: float(item.get("last_ts") or 0.0), reverse=True)
        if len(proposal_summaries) > proposal_limit:
            proposal_summaries = proposal_summaries[:proposal_limit]

        severity_counts = {"info": 0, "warning": 0, "critical": 0}
        for alert in alerts:
            sev = str(alert.get("severity") or "").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        summary = {
            "events": len(events),
            "alerts": len(alerts),
            "reports": len(reports),
            "burn_blocks": event_kind_counts.get("node_consensus", 0),
            "sortitions": (
                event_kind_counts.get("node_sortition_winner_selected", 0)
                + event_kind_counts.get("node_sortition_winner_rejected", 0)
            ),
            "tenure_extends": event_kind_counts.get("node_tenure_change", 0),
            "anomalous_proposals": len(proposal_summaries),
            "severity_counts": severity_counts,
        }
        return {
            "start_ts": start_ts,
            "stop_ts": stop_ts,
            "duration_seconds": max(0.0, float(stop_ts) - float(start_ts)),
            "summary": summary,
            "alerts": alerts,
            "reports": reports,
            "timeline": timeline,
            "anomalous_proposals": proposal_summaries,
            "event_kind_counts": event_kind_counts,
        }

    def _summarize_history_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        kind = str(event.get("kind") or "")
        data = event.get("data") or {}
        message = kind
        if kind == "node_consensus":
            burn = data.get("burn_height")
            stx = data.get("stacks_block_height")
            consensus = data.get("consensus_hash")
            message = "Consensus advanced"
            details = []
            if burn is not None:
                details.append("burn=%s" % burn)
            if stx is not None:
                details.append("stx=%s" % stx)
            if isinstance(consensus, str) and consensus:
                details.append("consensus=%s" % self._short_id(consensus, 12))
            if details:
                message = "%s | %s" % (message, " ".join(details))
        elif kind == "node_burnchain_reorg":
            height = data.get("ancestor_height")
            message = "Burnchain reorg detected"
            if height is not None:
                message = "%s | ancestor_height=%s" % (message, height)
        elif kind == "node_sortition_winner_selected":
            burn = data.get("burn_height")
            winner = data.get("winner_txid")
            message = "Sortition winner selected"
            parts = []
            if burn is not None:
                parts.append("burn=%s" % burn)
            if isinstance(winner, str) and winner:
                parts.append("winner_txid=%s" % self._short_id(winner, 12))
            if parts:
                message = "%s | %s" % (message, " ".join(parts))
        elif kind == "node_sortition_winner_rejected":
            burn = data.get("burn_height")
            message = "Sortition selected null miner"
            if burn is not None:
                message = "%s | burn=%s" % (message, burn)
        elif kind == "node_tenure_change":
            change_kind = data.get("tenure_change_kind")
            block_height = data.get("block_height")
            burn_height = data.get("burn_height")
            message = "Tenure change"
            parts = []
            if isinstance(change_kind, str) and change_kind:
                parts.append("kind=%s" % change_kind)
            if block_height is not None:
                parts.append("stx=%s" % block_height)
            if burn_height is not None:
                parts.append("burn=%s" % burn_height)
            if parts:
                message = "%s | %s" % (message, " ".join(parts))
        elif kind == "signer_block_proposal":
            sig = data.get("signer_signature_hash")
            block_height = data.get("block_height")
            message = "Proposal seen"
            parts = []
            if isinstance(sig, str) and sig:
                parts.append(self._short_id(sig, 12))
            if block_height is not None:
                parts.append("height=%s" % block_height)
            if parts:
                message = "%s | %s" % (message, " ".join(parts))
        elif kind == "signer_block_rejection":
            sig = data.get("signer_signature_hash")
            reason = data.get("reject_reason")
            message = "Signer rejection"
            parts = []
            if isinstance(sig, str) and sig:
                parts.append(self._short_id(sig, 12))
            if isinstance(reason, str) and reason:
                parts.append("reason=%s" % reason)
            if parts:
                message = "%s | %s" % (message, " ".join(parts))
        elif kind == "signer_rejection_threshold_reached":
            sig = data.get("signer_signature_hash")
            message = "Proposal reached rejection threshold"
            if isinstance(sig, str) and sig:
                message = "%s | %s" % (message, self._short_id(sig, 12))
        elif kind == "signer_threshold_reached":
            sig = data.get("signer_signature_hash")
            message = "Proposal reached approval threshold"
            if isinstance(sig, str) and sig:
                message = "%s | %s" % (message, self._short_id(sig, 12))
        elif kind in ("signer_block_pushed", "signer_new_block_event"):
            sig = data.get("signer_signature_hash")
            block_height = data.get("block_height")
            message = "Confirmed block observed"
            parts = []
            if isinstance(sig, str) and sig:
                parts.append(self._short_id(sig, 12))
            if block_height is not None:
                parts.append("height=%s" % block_height)
            if parts:
                message = "%s | %s" % (message, " ".join(parts))
        return {
            "id": event.get("id"),
            "ts": event.get("ts"),
            "source": event.get("source"),
            "kind": kind,
            "message": message,
            "data": data,
        }

    @staticmethod
    def _short_id(value: str, size: int = 12) -> str:
        text = str(value)
        if len(text) <= size:
            return text
        return text[:size]

    def _extract_signature_hash(self, alert: Alert) -> Optional[str]:
        for value in (alert.key, alert.message):
            if not isinstance(value, str):
                continue
            match = re.search(r"([0-9a-f]{64})", value)
            if match:
                return match.group(1)
        return None

    def _build_proposal_timeline(
        self, signature_hash: str, recent_events: list
    ) -> Optional[Dict[str, Any]]:
        proposal_events: list = []
        context_events: list = []
        related_hashes: Set[str] = set()
        meta: Dict[str, Any] = {
            "signature_hash": signature_hash,
        }

        for event in recent_events:
            data = event.get("data") or {}
            if data.get("signer_signature_hash") == signature_hash:
                proposal_events.append(event)
                for key in ("block_height", "burn_height", "consensus_hash", "block_id"):
                    if key not in meta and data.get(key) is not None:
                        meta[key] = data.get(key)

        if not proposal_events:
            return None

        block_height = meta.get("block_height")
        for event in recent_events:
            data = event.get("data") or {}
            if block_height is not None and data.get("block_height") == block_height:
                if event.get("kind") in (
                    "signer_block_proposal",
                    "signer_block_acceptance",
                    "signer_block_rejection",
                    "signer_rejection_threshold_reached",
                    "signer_threshold_reached",
                    "signer_block_pushed",
                    "signer_new_block_event",
                ):
                    proposal_events.append(event)
                    other_hash = data.get("signer_signature_hash")
                    if isinstance(other_hash, str) and other_hash:
                        related_hashes.add(other_hash)

        if related_hashes:
            meta["related_signature_hashes"] = sorted(related_hashes)

        burn_height = meta.get("burn_height")
        for event in recent_events:
            if event.get("kind") in (
                "node_consensus",
                "node_tenure_change",
                "node_sortition_winner_selected",
                "node_sortition_winner_rejected",
            ):
                data = event.get("data") or {}
                if burn_height is None or data.get("burn_height") == burn_height:
                    context_events.append(event)

        timeline = sorted(
            proposal_events + context_events,
            key=lambda item: item.get("ts") or 0,
        )
        return {
            "meta": meta,
            "events": timeline,
        }

    def _alerts_api(self, params: Dict[str, list]) -> Dict[str, Any]:
        if self.history_store is None:
            return {"alerts": []}
        from_ts = _float_query_param(params, "from")
        to_ts = _float_query_param(params, "to")
        severities = params.get("severity") or params.get("severities")
        limit = _int_query_param(params, "limit", 200)
        alerts = self.history_store.query_alerts(
            from_ts=from_ts,
            to_ts=to_ts,
            severities=severities,
            limit=limit,
        )
        return {"alerts": alerts}

    def _reports_api(self, params: Dict[str, list]) -> Dict[str, Any]:
        if self.history_store is None:
            return {"reports": []}
        from_ts = _float_query_param(params, "from")
        to_ts = _float_query_param(params, "to")
        severities = params.get("severity") or params.get("severities")
        limit = _int_query_param(params, "limit", 100)
        reports = self.history_store.list_reports(
            from_ts=from_ts,
            to_ts=to_ts,
            severities=severities,
            limit=limit,
        )
        return {"reports": reports}

    def _report_api(self, params: Dict[str, list]) -> Dict[str, Any]:
        if self.history_store is None:
            return {"report": None}
        report_id = _int_query_param(params, "id", None)
        if report_id is None:
            return {"report": None}
        report = self.history_store.get_report(report_id)
        return {"report": report}

    def _report_logs_api(self, params: Dict[str, list]) -> Dict[str, Any]:
        if self.history_store is None:
            return {"status": 404, "content": "history disabled\n"}
        if self.config.mode != "journalctl":
            return {
                "status": 400,
                "content": "log download only supported in journalctl mode\n",
            }
        report_id = _int_query_param(params, "id", None)
        if report_id is None:
            return {"status": 400, "content": "missing report id\n"}
        report = self.history_store.get_report(report_id)
        if report is None:
            return {"status": 404, "content": "report not found\n"}
        before = _int_query_param(
            params,
            "before",
            self.config.history.report_log_window_before_seconds,
        )
        after = _int_query_param(
            params,
            "after",
            self.config.history.report_log_window_after_seconds,
        )
        ts = report.get("ts")
        if not isinstance(ts, (int, float)):
            return {"status": 400, "content": "report missing timestamp\n"}
        start_ts = float(ts) - float(before)
        end_ts = float(ts) + float(after)
        try:
            log_text = self._fetch_journal_logs(start_ts, end_ts)
        except RuntimeError as exc:
            return {"status": 500, "content": "%s\n" % exc}
        filename = "report-%s-logs.txt" % report_id
        return {"status": 200, "filename": filename, "content": log_text}

    def _fetch_journal_logs(self, start_ts: float, end_ts: float) -> str:
        units = []
        if self.config.node_journal_unit:
            units.append(self.config.node_journal_unit)
        if self.config.signer_journal_unit:
            units.append(self.config.signer_journal_unit)
        if not units:
            raise RuntimeError("no journalctl units configured")
        start = datetime.datetime.fromtimestamp(start_ts).strftime("%Y-%m-%d %H:%M:%S")
        end = datetime.datetime.fromtimestamp(end_ts).strftime("%Y-%m-%d %H:%M:%S")
        cmd = ["journalctl"]
        for unit in units:
            cmd.extend(["-u", unit])
        cmd.extend(["--since", start, "--until", end, "--no-pager", "--output=short-iso"])
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=20,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise RuntimeError("failed to run journalctl: %s" % exc)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "journalctl failed")
        header = (
            "journalctl units: %s\nwindow: %s -> %s\n\n"
            % (", ".join(units), start, end)
        )
        return header + result.stdout

    def _sql_api(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        if self.history_store is None or not self._sql_api_enabled():
            return {"error": "sql api disabled"}
        sql = payload.get("sql")
        if not isinstance(sql, str) or not sql.strip():
            return {"error": "missing sql"}
        try:
            safe_sql = self._sanitize_sql(sql, self.config.history.sql_api_max_rows)
        except ValueError as exc:
            return {"error": str(exc)}
        columns, rows = self.history_store.query_sql(
            safe_sql, self.config.history.sql_api_max_rows
        )
        return {"sql": safe_sql, "columns": columns, "rows": rows}

    def _schema_api(self) -> Dict[str, Any]:
        if self.history_store is None:
            return {"schema": {}}
        return {"schema": self.history_store.schema()}

    def _sql_api_enabled(self) -> bool:
        return (
            self.history_store is not None
            and self.config.history.enable_sql_api
        )

    def _sanitize_sql(self, sql: str, max_rows: int) -> str:
        cleaned = sql.strip().rstrip(";").strip()
        lower = cleaned.lower()
        if not lower.startswith("select"):
            raise ValueError("Only SELECT statements are allowed.")
        forbidden = re.compile(
            r"\b(insert|update|delete|drop|alter|pragma|attach|detach|create|replace|truncate)\b",
            re.IGNORECASE,
        )
        if forbidden.search(lower):
            raise ValueError("Disallowed SQL statement.")
        if ";" in cleaned:
            cleaned = cleaned.split(";", 1)[0].strip()
        limit_match = re.search(r"\blimit\s+(\d+)\b", lower)
        if limit_match:
            limit_value = int(limit_match.group(1))
            if limit_value > max_rows:
                cleaned = re.sub(
                    r"\blimit\s+\d+\b",
                    "LIMIT %d" % max_rows,
                    cleaned,
                    flags=re.IGNORECASE,
                    count=1,
                )
        else:
            cleaned = "%s LIMIT %d" % (cleaned, max_rows)
        return cleaned

    def _record_sortition_event(self, event: Any) -> None:
        if self.history_store is None:
            return
        burn_height = event.fields.get("burn_height")
        winner_txid = event.fields.get("winner_txid")
        winning_stacks_block_hash = event.fields.get("winning_stacks_block_hash")
        null_miner = False
        if event.kind == "node_sortition_winner_rejected":
            null_miner = True
        else:
            if isinstance(winner_txid, str) and self._is_zero_hash(winner_txid):
                null_miner = True
            if isinstance(winning_stacks_block_hash, str) and self._is_zero_hash(
                winning_stacks_block_hash
            ):
                null_miner = True
        self.history_store.record_sortition(
            ts=event.ts,
            burn_height=burn_height if isinstance(burn_height, int) else None,
            winner_txid=winner_txid if isinstance(winner_txid, str) else None,
            winning_stacks_block_hash=(
                winning_stacks_block_hash
                if isinstance(winning_stacks_block_hash, str)
                else None
            ),
            null_miner_won=null_miner,
            event_kind=event.kind,
        )

    @staticmethod
    def _is_zero_hash(value: str) -> bool:
        if len(value) != 64:
            return False
        return set(value) == {"0"}


    def _should_notify_telegram_for_alert(self, alert: Alert) -> bool:
        minimum = ALERT_SEVERITY_RANK.get(
            str(self.config.telegram.min_alert_severity).lower(),
            ALERT_SEVERITY_RANK["critical"],
        )
        current = ALERT_SEVERITY_RANK.get(
            str(alert.severity).lower(),
            0,
        )
        return current >= minimum

    def _state_now(self) -> float:
        now = time.time()
        if self.config.run_once and self.latest_event_ts is not None:
            now = self.latest_event_ts
        elif self.replay_clock_enabled and self.replay_event_base_ts is not None:
            replay_now = self.replay_event_base_ts + (time.time() - self.replay_wall_base_ts)
            source_ts_values = [
                self.latest_event_ts_by_source[source]
                for source in self.replay_sources
                if source in self.latest_event_ts_by_source
            ]
            if source_ts_values:
                # Guard against one source getting far ahead while the other backlog is still
                # being replayed; anomaly timers should advance at the slowest active source.
                replay_progress_ts = min(source_ts_values)
                now = max(replay_now, replay_progress_ts)
            elif self.latest_event_ts is not None:
                now = max(replay_now, self.latest_event_ts)
            else:
                now = replay_now
        return now

    def _dashboard_state(self) -> Dict[str, Any]:
        now = self._state_now()
        with self.state_lock:
            if self.detector.start_ts > now:
                self.detector.start_ts = now
            state = self.detector.snapshot(now=now)
            state["recent_alerts"] = list(self.recent_alerts)
            state["recent_reports"] = list(self.recent_reports)
        return state

    def _handle_stop(self, signum: int, _frame: object) -> None:
        _ = signum
        self.stop_event.set()

    def _load_signer_names(self, path: Optional[str]) -> Dict[str, str]:
        if not path:
            return {}
        try:
            with open(path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
            if not isinstance(payload, dict):
                print(
                    "[WARN] signer names file must contain a JSON object (pubkey->name): %s"
                    % path,
                    flush=True,
                )
                return {}
            output: Dict[str, str] = {}
            for key, value in payload.items():
                if isinstance(key, str) and isinstance(value, str):
                    output[key.strip()] = value.strip()
            return output
        except (OSError, ValueError) as exc:
            print(
                "[WARN] failed to load signer names from %s: %s" % (path, exc),
                flush=True,
            )
            return {}


def _float_query_param(params: Dict[str, list], name: str) -> Optional[float]:
    values = params.get(name)
    if not values:
        return None
    try:
        return float(values[0])
    except (TypeError, ValueError):
        return None


def _int_query_param(
    params: Dict[str, list], name: str, default: Optional[int] = None
) -> Optional[int]:
    values = params.get(name)
    if not values:
        return default
    try:
        return int(values[0])
    except (TypeError, ValueError):
        return default
