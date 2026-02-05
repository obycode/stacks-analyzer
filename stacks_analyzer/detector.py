import statistics
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Set, Tuple

from .events import ParsedEvent


@dataclass
class DetectorConfig:
    node_stall_seconds: int = 90
    signer_stall_seconds: int = 120
    proposal_timeout_seconds: int = 45
    stale_chunk_window_seconds: int = 60
    stale_chunk_threshold: int = 250
    report_interval_seconds: int = 300
    alert_cooldown_seconds: int = 300
    large_signer_min_samples: int = 10
    large_signer_top_n: int = 3
    large_signer_window: int = 30
    large_signer_min_participation: float = 0.5
    closed_proposal_retention_seconds: int = 600


@dataclass
class Alert:
    key: str
    severity: str
    message: str
    ts: float


@dataclass
class ProposalState:
    start_ts: float
    block_height: Optional[int] = None
    threshold_ts: Optional[float] = None
    pushed_ts: Optional[float] = None
    signers: Set[str] = field(default_factory=set)
    max_percent: float = 0.0
    total_weight: Optional[int] = None
    last_total_weight_approved: int = 0


class Detector:
    def __init__(
        self,
        config: Optional[DetectorConfig] = None,
        signer_names: Optional[Dict[str, str]] = None,
    ) -> None:
        self.config = config or DetectorConfig()
        self.start_ts = time.time()
        self.last_node_tip_ts: Optional[float] = None
        self.last_signer_proposal_ts: Optional[float] = None
        self.last_report_ts: float = 0.0
        self.current_stacks_block_height: Optional[int] = None
        self.current_bitcoin_block_height: Optional[int] = None
        self.signer_names: Dict[str, str] = signer_names or {}

        self.processed_lines: Dict[str, int] = defaultdict(int)
        self.event_counts: Dict[str, int] = defaultdict(int)

        self.stale_chunks: Deque[float] = deque()
        self.proposals: Dict[str, ProposalState] = {}

        self.signer_weight_samples: Dict[str, Deque[int]] = defaultdict(
            lambda: deque(maxlen=200)
        )
        self.total_weight_samples: Deque[int] = deque(maxlen=200)
        self.seen_signers: Set[str] = set()
        self.signer_participation: Dict[str, Deque[bool]] = defaultdict(
            lambda: deque(maxlen=self.config.large_signer_window)
        )

        self.last_alert_ts: Dict[str, float] = {}
        self.active_stalls: Set[str] = set()
        self.completed_proposals: int = 0
        self.completed_with_threshold: int = 0
        self.closed_proposals: Dict[str, float] = {}

    def process_line(self, source: str) -> None:
        self.processed_lines[source] += 1

    def process_event(self, event: ParsedEvent) -> List[Alert]:
        alerts: List[Alert] = []
        self.event_counts[event.kind] += 1
        self._update_chain_heights(event.fields)

        if event.kind == "node_tip_advanced":
            self.last_node_tip_ts = event.ts
            self._clear_stall("node-stall", event.ts, alerts)

        elif event.kind == "node_stale_chunk":
            self.stale_chunks.append(event.ts)

        elif event.kind == "signer_block_proposal":
            self.last_signer_proposal_ts = event.ts
            self._clear_stall("signer-stall", event.ts, alerts)

            signature_hash = event.fields.get("signer_signature_hash")
            if signature_hash and self._is_recently_closed(signature_hash, event.ts):
                return alerts
            if signature_hash:
                self.proposals.setdefault(
                    signature_hash,
                    ProposalState(
                        start_ts=event.ts, block_height=event.fields.get("block_height")
                    ),
                )

        elif event.kind == "signer_block_acceptance":
            signature_hash = event.fields.get("signer_signature_hash")
            signer_pubkey = event.fields.get("signer_pubkey")
            total_weight_approved = event.fields.get("total_weight_approved")
            total_weight = event.fields.get("total_weight")
            percent = event.fields.get("percent_approved")
            block_height = event.fields.get("block_height")
            if signature_hash:
                if self._is_recently_closed(signature_hash, event.ts):
                    return alerts
                state = self.proposals.setdefault(signature_hash, ProposalState(event.ts))
                if signer_pubkey:
                    self.seen_signers.add(signer_pubkey)
                    state.signers.add(signer_pubkey)
                if block_height is not None:
                    state.block_height = block_height
                if total_weight is not None:
                    state.total_weight = total_weight
                    self.total_weight_samples.append(int(total_weight))
                if percent is not None:
                    state.max_percent = max(state.max_percent, float(percent))
                if total_weight_approved is not None:
                    delta = max(0, total_weight_approved - state.last_total_weight_approved)
                    state.last_total_weight_approved = max(
                        state.last_total_weight_approved, total_weight_approved
                    )
                    if delta > 0 and signer_pubkey:
                        self.signer_weight_samples[signer_pubkey].append(delta)

        elif event.kind == "signer_threshold_reached":
            signature_hash = event.fields.get("signer_signature_hash")
            if signature_hash:
                if self._is_recently_closed(signature_hash, event.ts):
                    return alerts
                state = self.proposals.setdefault(signature_hash, ProposalState(event.ts))
                state.threshold_ts = event.ts
                percent = event.fields.get("percent_approved")
                block_height = event.fields.get("block_height")
                signer_pubkey = event.fields.get("signer_pubkey")
                if percent is not None:
                    state.max_percent = max(state.max_percent, float(percent))
                if block_height is not None:
                    state.block_height = block_height
                if signer_pubkey:
                    self.seen_signers.add(signer_pubkey)
                    state.signers.add(signer_pubkey)

        elif event.kind == "signer_block_pushed":
            signature_hash = event.fields.get("signer_signature_hash")
            if signature_hash:
                if self._is_recently_closed(signature_hash, event.ts):
                    return alerts
                state = self.proposals.setdefault(signature_hash, ProposalState(event.ts))
                state.pushed_ts = event.ts
                block_height = event.fields.get("block_height")
                if block_height is not None:
                    state.block_height = block_height
                alerts.extend(self._finalize_proposal(signature_hash, event.ts))

        elif event.kind == "signer_new_block_event":
            signature_hash = event.fields.get("signer_signature_hash")
            if signature_hash:
                if self._is_recently_closed(signature_hash, event.ts):
                    return alerts
                state = self.proposals.setdefault(signature_hash, ProposalState(event.ts))
                block_height = event.fields.get("block_height")
                if block_height is not None:
                    state.block_height = block_height
                alerts.extend(self._finalize_proposal(signature_hash, event.ts))

        elif event.kind == "signer_block_response":
            reject_reason = event.fields.get("reject_reason")
            if reject_reason and reject_reason != "NotRejected":
                self._emit_alert(
                    alerts=alerts,
                    key="signer-reject-%s" % reject_reason,
                    severity="critical",
                    message="Signer response rejection detected: %s" % reject_reason,
                    ts=event.ts,
                )

        return alerts

    def tick(self, now: Optional[float] = None) -> Tuple[List[Alert], Optional[str]]:
        ts = now if now is not None else time.time()
        alerts: List[Alert] = []

        self._trim_stale_chunks(ts)
        self._trim_closed_proposals(ts)
        self._detect_stalls(ts, alerts)
        self._detect_proposal_timeouts(ts, alerts)
        self._detect_large_signer_participation(ts, alerts)

        report: Optional[str] = None
        if ts - self.last_report_ts >= self.config.report_interval_seconds:
            report = self.build_report(ts)
            self.last_report_ts = ts

        return alerts, report

    def build_report(self, now: Optional[float] = None) -> str:
        ts = now if now is not None else time.time()
        uptime = int(ts - self.start_ts)
        node_age = int(ts - self.last_node_tip_ts) if self.last_node_tip_ts else -1
        signer_age = (
            int(ts - self.last_signer_proposal_ts) if self.last_signer_proposal_ts else -1
        )
        total_weight_estimate = self._total_weight_estimate()

        large_signers = self._current_large_signers()
        large_rows: List[str] = []
        for pubkey, est_weight in large_signers:
            participation = self.signer_participation.get(pubkey, deque())
            if participation:
                ratio = sum(1 for item in participation if item) / float(len(participation))
            else:
                ratio = 1.0
            if total_weight_estimate:
                pct = (est_weight / float(total_weight_estimate)) * 100.0
            else:
                pct = 0.0
            large_rows.append(
                "%s weight~%.1f (%.2f%%) participation=%.0f%%(%d)"
                % (
                    self._signer_label(pubkey),
                    est_weight,
                    pct,
                    ratio * 100.0,
                    len(participation),
                )
            )

        if not large_rows:
            large_summary = "n/a"
        else:
            large_summary = "; ".join(large_rows)

        threshold_ratio = 0.0
        if self.completed_proposals:
            threshold_ratio = (
                self.completed_with_threshold / float(self.completed_proposals)
            ) * 100.0

        return (
            "[REPORT] uptime=%ss | lines(node=%d signer=%d) | tips_age=%ss | "
            "proposal_age=%ss | open_proposals=%d | "
            "completed=%d threshold=%.1f%% | large_signers=%s"
            % (
                uptime,
                self.processed_lines.get("node", 0),
                self.processed_lines.get("signer", 0),
                node_age,
                signer_age,
                len(self.proposals),
                self.completed_proposals,
                threshold_ratio,
                large_summary,
            )
        )

    def _trim_stale_chunks(self, ts: float) -> None:
        window_start = ts - self.config.stale_chunk_window_seconds
        while self.stale_chunks and self.stale_chunks[0] < window_start:
            self.stale_chunks.popleft()

    def _detect_stalls(self, ts: float, alerts: List[Alert]) -> None:
        if self.last_node_tip_ts is not None:
            node_gap = ts - self.last_node_tip_ts
            if node_gap > self.config.node_stall_seconds:
                self._emit_stall(
                    alerts=alerts,
                    key="node-stall",
                    message="No new node tip for %.0fs (threshold=%ds)"
                    % (node_gap, self.config.node_stall_seconds),
                    ts=ts,
                )

        if self.last_signer_proposal_ts is not None:
            signer_gap = ts - self.last_signer_proposal_ts
            if signer_gap > self.config.signer_stall_seconds:
                self._emit_stall(
                    alerts=alerts,
                    key="signer-stall",
                    message="No signer block proposal for %.0fs (threshold=%ds)"
                    % (signer_gap, self.config.signer_stall_seconds),
                    ts=ts,
                )

    def _detect_proposal_timeouts(self, ts: float, alerts: List[Alert]) -> None:
        for signature_hash, state in list(self.proposals.items()):
            age = ts - state.start_ts
            if state.threshold_ts is None and age > self.config.proposal_timeout_seconds:
                if state.block_height is not None:
                    message = (
                        "Proposal %s (height %d) has no threshold confirmation after %.0fs"
                        % (signature_hash[:12], state.block_height, age)
                    )
                else:
                    message = (
                        "Proposal %s has no threshold confirmation after %.0fs"
                        % (signature_hash[:12], age)
                    )
                self._emit_alert(
                    alerts=alerts,
                    key="proposal-timeout-%s" % signature_hash,
                    severity="critical",
                    message=message,
                    ts=ts,
                )

            # Keep memory bounded for older entries even if push lines are missing.
            if age > max(self.config.proposal_timeout_seconds * 4, 300):
                self.proposals.pop(signature_hash, None)

    def _detect_large_signer_participation(self, ts: float, alerts: List[Alert]) -> None:
        for pubkey, _ in self._current_large_signers():
            history = self.signer_participation.get(pubkey)
            if not history:
                continue
            if len(history) < self.config.large_signer_window:
                continue
            ratio = sum(1 for item in history if item) / float(len(history))
            if ratio < self.config.large_signer_min_participation:
                label = self._signer_label(pubkey)
                self._emit_alert(
                    alerts=alerts,
                    key="large-signer-participation-%s" % pubkey,
                    severity="warning",
                    message=(
                        "Large signer %s participation dropped to %.0f%% over last %d blocks"
                        % (
                            label,
                            ratio * 100.0,
                            self.config.large_signer_window,
                        )
                    ),
                    ts=ts,
                )

    def _finalize_proposal(self, signature_hash: str, ts: float) -> List[Alert]:
        alerts: List[Alert] = []
        state = self.proposals.pop(signature_hash, None)
        if state is None:
            self.closed_proposals[signature_hash] = ts
            return alerts

        self.completed_proposals += 1
        if state.threshold_ts is not None:
            self.completed_with_threshold += 1
        self.closed_proposals[signature_hash] = ts

        tracked_signers = set(self.signer_participation.keys())
        tracked_signers.update(self.seen_signers)
        tracked_signers.update(state.signers)
        for pubkey in tracked_signers:
            self.signer_participation[pubkey].append(pubkey in state.signers)

        return alerts

    def snapshot(self, now: Optional[float] = None) -> Dict[str, object]:
        ts = now if now is not None else time.time()
        threshold_ratio = 0.0
        if self.completed_proposals:
            threshold_ratio = (
                self.completed_with_threshold / float(self.completed_proposals)
            ) * 100.0
        total_weight_estimate = self._total_weight_estimate()
        signer_rows = self._all_signer_rows(total_weight_estimate)
        large_pubkeys = {pubkey for pubkey, _ in self._current_large_signers()}
        large_signers = [
            row for row in signer_rows if row["pubkey"] in large_pubkeys
        ]

        open_proposals = []
        for signature_hash, state in self.proposals.items():
            open_proposals.append(
                {
                    "signature_hash": signature_hash,
                    "age_seconds": max(0.0, ts - state.start_ts),
                    "block_height": state.block_height,
                    "max_percent_observed": state.max_percent,
                    "threshold_seen": state.threshold_ts is not None,
                    "unique_signers_seen": len(state.signers),
                }
            )
        open_proposals.sort(key=lambda row: row["age_seconds"], reverse=True)

        return {
            "timestamp": ts,
            "uptime_seconds": max(0, int(ts - self.start_ts)),
            "lines": dict(self.processed_lines),
            "events": dict(self.event_counts),
            "current_stacks_block_height": self.current_stacks_block_height,
            "current_bitcoin_block_height": self.current_bitcoin_block_height,
            "node_tip_age_seconds": (
                None if self.last_node_tip_ts is None else max(0.0, ts - self.last_node_tip_ts)
            ),
            "signer_proposal_age_seconds": (
                None
                if self.last_signer_proposal_ts is None
                else max(0.0, ts - self.last_signer_proposal_ts)
            ),
            "stale_chunks_window_count": len(self.stale_chunks),
            "open_proposals": open_proposals[:50],
            "open_proposals_count": len(self.proposals),
            "completed_proposals": self.completed_proposals,
            "completed_with_threshold": self.completed_with_threshold,
            "threshold_ratio_percent": threshold_ratio,
            "total_weight_estimate": total_weight_estimate,
            "signers": signer_rows,
            "large_signers": large_signers,
            "active_stalls": sorted(self.active_stalls),
        }

    def _current_large_signers(self) -> List[Tuple[str, float]]:
        weighted: List[Tuple[str, float]] = []
        for pubkey, samples in self.signer_weight_samples.items():
            if len(samples) < self.config.large_signer_min_samples:
                continue
            median_weight = statistics.median(samples)
            weighted.append((pubkey, float(median_weight)))

        weighted.sort(key=lambda item: item[1], reverse=True)
        return weighted[: self.config.large_signer_top_n]

    def _total_weight_estimate(self) -> Optional[float]:
        if not self.total_weight_samples:
            return None
        return float(statistics.median(self.total_weight_samples))

    def _signer_display_name(self, pubkey: str) -> Optional[str]:
        return self.signer_names.get(pubkey)

    def _signer_label(self, pubkey: str) -> str:
        display_name = self._signer_display_name(pubkey)
        if display_name:
            return "%s (%s..)" % (display_name, pubkey[:10])
        return "%s.." % pubkey[:12]

    def _all_signer_rows(self, total_weight_estimate: Optional[float]) -> List[Dict[str, object]]:
        rows: List[Dict[str, object]] = []
        all_signers = set(self.seen_signers) | set(self.signer_weight_samples.keys())
        for pubkey in all_signers:
            samples = self.signer_weight_samples.get(pubkey, deque())
            estimated_weight = float(statistics.median(samples)) if samples else 0.0
            if total_weight_estimate and total_weight_estimate > 0:
                weight_percent = (estimated_weight / total_weight_estimate) * 100.0
            else:
                weight_percent = 0.0
            history = self.signer_participation.get(pubkey, deque())
            participation_ratio = (
                sum(1 for item in history if item) / float(len(history))
                if history
                else 1.0
            )
            rows.append(
                {
                    "pubkey": pubkey,
                    "name": self._signer_display_name(pubkey),
                    "label": self._signer_label(pubkey),
                    "estimated_weight": estimated_weight,
                    "weight_percent_of_total": weight_percent,
                    "participation_ratio": participation_ratio,
                    "participation_samples": len(history),
                    "weight_samples": len(samples),
                }
            )

        rows.sort(
            key=lambda row: (
                row["estimated_weight"],
                row["participation_ratio"],
                row["pubkey"],
            ),
            reverse=True,
        )
        return rows

    def _emit_stall(
        self, alerts: List[Alert], key: str, message: str, ts: float
    ) -> None:
        self.active_stalls.add(key)
        self._emit_alert(alerts, key=key, severity="critical", message=message, ts=ts)

    def _clear_stall(self, key: str, ts: float, alerts: List[Alert]) -> None:
        if key in self.active_stalls:
            self.active_stalls.remove(key)
            self._emit_alert(
                alerts=alerts,
                key="%s-recovered" % key,
                severity="info",
                message="%s recovered" % key,
                ts=ts,
            )

    def _emit_alert(
        self, alerts: List[Alert], key: str, severity: str, message: str, ts: float
    ) -> None:
        previous_ts = self.last_alert_ts.get(key)
        if previous_ts is not None and (ts - previous_ts) < self.config.alert_cooldown_seconds:
            return
        self.last_alert_ts[key] = ts
        alerts.append(Alert(key=key, severity=severity, message=message, ts=ts))

    def _update_chain_heights(self, fields: Dict[str, object]) -> None:
        block_height = fields.get("block_height")
        burn_height = fields.get("burn_height")
        if isinstance(block_height, int):
            if self.current_stacks_block_height is None:
                self.current_stacks_block_height = block_height
            else:
                self.current_stacks_block_height = max(
                    self.current_stacks_block_height, block_height
                )
        if isinstance(burn_height, int):
            if self.current_bitcoin_block_height is None:
                self.current_bitcoin_block_height = burn_height
            else:
                self.current_bitcoin_block_height = max(
                    self.current_bitcoin_block_height, burn_height
                )

    def _is_recently_closed(self, signature_hash: str, ts: float) -> bool:
        closed_ts = self.closed_proposals.get(signature_hash)
        if closed_ts is None:
            return False
        return (ts - closed_ts) <= self.config.closed_proposal_retention_seconds

    def _trim_closed_proposals(self, ts: float) -> None:
        cutoff = ts - self.config.closed_proposal_retention_seconds
        for signature_hash in list(self.closed_proposals.keys()):
            if self.closed_proposals[signature_hash] < cutoff:
                self.closed_proposals.pop(signature_hash, None)
