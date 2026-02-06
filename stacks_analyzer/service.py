from collections import deque
import json
import queue
import signal
import threading
import time
import datetime
import subprocess
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
                alerts_provider=self._alerts_api if self.history_store else None,
                reports_provider=self._reports_api if self.history_store else None,
                report_provider=self._report_api if self.history_store else None,
                report_logs_provider=self._report_logs_api if self.history_store else None,
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
