import statistics
import hashlib
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Set, Tuple

from .events import ParsedEvent

ZERO_HASH = "0" * 64
BOUNDARY_REJECTION_REASONS = (
    "NotLatestSortitionWinner",
    "SortitionViewMismatch",
)
EXECUTION_COST_LIMITS = {
    "runtime": 5_000_000_000,
    "write_len": 15_000_000,
    "write_cnt": 15_000,
    "read_len": 100_000_000,
    "read_cnt": 15_000,
}


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
    sortition_history_rounds: int = 64
    sortition_max_commits_per_round: int = 64
    hash_height_map_size: int = 4096
    tenure_extend_history_size: int = 64
    proposal_history_size: int = 400
    burn_block_boundary_window_seconds: int = 15


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
    burn_height: Optional[int] = None
    threshold_ts: Optional[float] = None
    pushed_ts: Optional[float] = None
    signers: Set[str] = field(default_factory=set)
    reject_signers: Set[str] = field(default_factory=set)
    reject_reasons: Set[str] = field(default_factory=set)
    boundary_reason: Optional[str] = None
    signer_responses: Dict[str, str] = field(default_factory=dict)
    accept_then_reject_signers: Set[str] = field(default_factory=set)
    max_percent: float = 0.0
    max_reject_percent: float = 0.0
    total_weight: Optional[int] = None
    last_reject_ts: Optional[float] = None


@dataclass
class SortitionCommitState:
    commit_txid: str
    apparent_sender: str
    stacks_block_hash: Optional[str]
    burn_height: int
    sortition_position: Optional[int]
    parent_burn_block: Optional[int]
    ts: float


@dataclass
class SortitionRoundState:
    burn_height: int
    commits: List[SortitionCommitState] = field(default_factory=list)
    winner_txid: Optional[str] = None
    winner_stacks_block_hash: Optional[str] = None
    winner_ts: Optional[float] = None
    null_miner_won: bool = False
    null_miner_reason: Optional[str] = None
    rejected_txid: Optional[str] = None
    rejected_stacks_block_hash: Optional[str] = None
    rejected_ts: Optional[float] = None


class Detector:
    def __init__(
        self,
        config: Optional[DetectorConfig] = None,
        signer_names: Optional[Dict[str, str]] = None,
    ) -> None:
        self.config = config or DetectorConfig()
        self.start_ts = time.time()
        self.last_node_tip_ts: Optional[float] = None
        self.last_block_interval_seconds: Optional[float] = None
        self.block_interval_total_seconds: float = 0.0
        self.block_interval_samples: int = 0
        self.last_signer_proposal_ts: Optional[float] = None
        self.last_report_ts: float = 0.0
        self.last_mempool_ready_txs: Optional[int] = None
        self.last_mempool_ready_ts: Optional[float] = None
        self.last_mempool_stop_reason: Optional[str] = None
        self.last_mempool_elapsed_ms: Optional[int] = None
        self.last_mempool_ts: Optional[float] = None
        self.last_execution_costs: Optional[Dict[str, int]] = None
        self.last_execution_costs_percent: Optional[Dict[str, float]] = None
        self.last_execution_cost_ts: Optional[float] = None
        self.last_execution_cost_block_height: Optional[int] = None
        self.last_execution_cost_tx_count: Optional[int] = None
        self.last_execution_cost_percent_full: Optional[int] = None
        self.current_stacks_block_height: Optional[int] = None
        self.current_bitcoin_block_height: Optional[int] = None
        self.current_consensus_hash: Optional[str] = None
        self.current_consensus_burn_height: Optional[int] = None
        self.current_miner_apparent_sender: Optional[str] = None
        self.current_miner_pubkey: Optional[str] = None
        self.current_miner_winning_stacks_block_hash: Optional[str] = None
        self.current_miner_last_updated_ts: Optional[float] = None
        self.active_miner_pkh: Optional[str] = None
        self.active_miner_tenure_id: Optional[str] = None
        self.active_miner_parent_tenure_id: Optional[str] = None
        self.active_miner_parent_last_block: Optional[str] = None
        self.active_miner_parent_last_block_height: Optional[int] = None
        self.active_miner_burn_consensus_hash: Optional[str] = None
        self.active_miner_burn_height: Optional[int] = None
        self.active_miner_last_update_ts: Optional[float] = None
        self.last_tenure_extend_kind: Optional[str] = None
        self.last_tenure_extend_txid: Optional[str] = None
        self.last_tenure_extend_origin: Optional[str] = None
        self.last_tenure_extend_ts: Optional[float] = None
        self.last_accepted_proposal_burn_height: Optional[int] = None
        self.last_accepted_proposal_ts: Optional[float] = None
        self.last_burn_block_alert_height: Optional[int] = None
        self.tenure_extend_history: Deque[Dict[str, object]] = deque(
            maxlen=self.config.tenure_extend_history_size
        )
        self.tenure_change_history: Deque[Dict[str, object]] = deque(maxlen=512)
        self.tenure_block_counts: Deque[Dict[str, object]] = deque(maxlen=8)
        self.confirmed_block_history: Deque[Dict[str, object]] = deque(maxlen=4096)
        self.confirmed_block_keys: Set[str] = set()
        self.confirmed_block_key_order: Deque[str] = deque()
        self.execution_cost_history: Deque[Dict[str, object]] = deque(maxlen=720)
        self.pending_execution_cost_by_block_hash: Dict[str, Dict[str, object]] = {}
        self.pending_execution_cost_order: Deque[str] = deque()
        self.signer_names: Dict[str, str] = signer_names or {}

        self.processed_lines: Dict[str, int] = defaultdict(int)
        self.event_counts: Dict[str, int] = defaultdict(int)

        self.stale_chunks: Deque[float] = deque()
        self.proposals: Dict[str, ProposalState] = {}
        self.proposal_activity: Deque[Dict[str, object]] = deque(
            maxlen=self.config.proposal_history_size
        )
        self.sortition_rounds: Dict[int, SortitionRoundState] = {}
        self.sortition_round_order: Deque[int] = deque()
        self.block_height_by_hash: Dict[str, int] = {}
        self.block_height_hash_order: Deque[str] = deque()
        self.block_header_to_consensus: Dict[str, str] = {}
        self.block_header_consensus_order: Deque[str] = deque()
        self.burn_height_by_block_hash: Dict[str, int] = {}
        self.block_burn_height_order: Deque[str] = deque()
        self.burn_height_by_consensus_hash: Dict[str, int] = {}
        self.recent_burn_block_events: Deque[Tuple[float, int]] = deque(maxlen=32)
        self.recent_rejections: Deque[Dict[str, object]] = deque(maxlen=200)
        self.rejection_pattern_alerted: Set[str] = set()

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
        self.proposal_reject_reasons: Dict[str, str] = {}
        self.suppress_alerts: bool = False

    def process_line(self, source: str) -> None:
        self.processed_lines[source] += 1

    def process_event(self, event: ParsedEvent) -> List[Alert]:
        alerts: List[Alert] = []
        self.event_counts[event.kind] += 1
        self._update_chain_heights(event.fields)
        self._index_hash_height_from_event(event)

        if event.kind == "node_tip_advanced":
            if self.last_node_tip_ts is not None:
                interval_seconds = event.ts - self.last_node_tip_ts
                if interval_seconds > 0:
                    self.last_block_interval_seconds = interval_seconds
                    self.block_interval_total_seconds += interval_seconds
                    self.block_interval_samples += 1
            self.last_node_tip_ts = event.ts
            self._record_tenure_block_count(
                consensus_hash=event.fields.get("consensus_hash")
                if isinstance(event.fields.get("consensus_hash"), str)
                else None,
                ts=event.ts,
            )
            self._record_confirmed_block_event(
                ts=event.ts,
                source="node_tip_advanced",
                consensus_hash=event.fields.get("consensus_hash")
                if isinstance(event.fields.get("consensus_hash"), str)
                else None,
                block_height=(
                    self.current_stacks_block_height
                    if isinstance(self.current_stacks_block_height, int)
                    else None
                ),
                block_header_hash=event.fields.get("block_header_hash")
                if isinstance(event.fields.get("block_header_hash"), str)
                else None,
                event_line=event.line,
            )
            self._apply_confirmed_execution_cost(
                ts=event.ts,
                block_header_hash=event.fields.get("block_header_hash")
                if isinstance(event.fields.get("block_header_hash"), str)
                else None,
                consensus_hash=event.fields.get("consensus_hash")
                if isinstance(event.fields.get("consensus_hash"), str)
                else None,
            )
            self._clear_stall("node-stall", event.ts, alerts)

        elif event.kind == "node_nakamoto_block":
            self._record_confirmed_block_event(
                ts=event.ts,
                source="node_nakamoto_block",
                consensus_hash=event.fields.get("consensus_hash")
                if isinstance(event.fields.get("consensus_hash"), str)
                else None,
                block_height=(
                    self.current_stacks_block_height
                    if isinstance(self.current_stacks_block_height, int)
                    else None
                ),
                block_header_hash=event.fields.get("block_header_hash")
                if isinstance(event.fields.get("block_header_hash"), str)
                else None,
                block_id=event.fields.get("block_id")
                if isinstance(event.fields.get("block_id"), str)
                else None,
                event_line=event.line,
            )

        elif event.kind == "node_block_proposal":
            block_header_hash = event.fields.get("block_header_hash")
            if isinstance(block_header_hash, str) and block_header_hash:
                costs, cost_percents = self._extract_costs_from_fields(event.fields)
                if costs:
                    self._remember_pending_execution_cost(
                        block_header_hash=block_header_hash,
                        ts=event.ts,
                        block_height=event.fields.get("block_height")
                        if isinstance(event.fields.get("block_height"), int)
                        else None,
                        tx_count=event.fields.get("tx_count")
                        if isinstance(event.fields.get("tx_count"), int)
                        else None,
                        percent_full=event.fields.get("percent_full")
                        if isinstance(event.fields.get("percent_full"), int)
                        else None,
                        consensus_hash=event.fields.get("consensus_hash")
                        if isinstance(event.fields.get("consensus_hash"), str)
                        else None,
                        costs=costs,
                        cost_percents=cost_percents,
                    )

        elif event.kind == "node_mempool_iteration":
            considered_txs = event.fields.get("considered_txs")
            elapsed_ms = event.fields.get("elapsed_ms")
            stop_reason = event.fields.get("stop_reason")
            self.last_mempool_ts = event.ts
            self.last_mempool_stop_reason = (
                stop_reason if isinstance(stop_reason, str) else None
            )
            if isinstance(elapsed_ms, int):
                self.last_mempool_elapsed_ms = elapsed_ms
            if isinstance(stop_reason, str) and stop_reason == "NoMoreCandidates":
                if isinstance(considered_txs, int):
                    self.last_mempool_ready_txs = considered_txs
                    self.last_mempool_ready_ts = event.ts
            if isinstance(stop_reason, str) and stop_reason == "DeadlineReached":
                details = []
                if isinstance(considered_txs, int):
                    details.append("considered_txs=%d" % considered_txs)
                if isinstance(elapsed_ms, int):
                    details.append("elapsed_ms=%d" % elapsed_ms)
                suffix = " | ".join(details) if details else "deadline reached"
                self._emit_alert(
                    alerts=alerts,
                    key="mempool-iteration-deadline",
                    severity="warning",
                    message="Mempool iteration reached deadline (%s)" % suffix,
                    ts=event.ts,
                )

        elif event.kind == "node_mined_nakamoto_block":
            # Intentionally ignored for execution-cost history. These logs can be mock-miner
            # assembly snapshots; execution costs are only recorded on confirmed tips.
            pass

        elif event.kind == "node_stale_chunk":
            self.stale_chunks.append(event.ts)

        elif event.kind == "node_sortition_winner_selected":
            burn_height = event.fields.get("burn_height")
            winner_txid = event.fields.get("winner_txid")
            winning_stacks_block_hash = event.fields.get("winning_stacks_block_hash")
            if isinstance(burn_height, int):
                round_state = self._get_or_create_sortition_round(burn_height)
                if self._is_zero_hash(winner_txid) or self._is_zero_hash(
                    winning_stacks_block_hash
                ):
                    round_state.null_miner_won = True
                    round_state.null_miner_reason = "Null miner selected"
                    round_state.winner_txid = None
                    round_state.winner_stacks_block_hash = None
                elif isinstance(winner_txid, str) and winner_txid:
                    round_state.null_miner_won = False
                    round_state.null_miner_reason = None
                    round_state.winner_txid = winner_txid
                if isinstance(winning_stacks_block_hash, str) and winning_stacks_block_hash:
                    if not self._is_zero_hash(winning_stacks_block_hash):
                        round_state.winner_stacks_block_hash = winning_stacks_block_hash
                        self.current_miner_winning_stacks_block_hash = (
                            winning_stacks_block_hash
                        )
                round_state.winner_ts = event.ts
                self._refresh_current_miner_from_latest_round(event.ts)
                self._warn_on_sortition_parent_burn_mismatch(
                    round_state=round_state,
                    burn_height=burn_height,
                    alerts=alerts,
                    ts=event.ts,
                )

        elif event.kind == "node_sortition_winner_rejected":
            burn_height = event.fields.get("burn_height")
            if isinstance(burn_height, int):
                round_state = self._get_or_create_sortition_round(burn_height)
                round_state.null_miner_won = True
                rejection_reason = event.fields.get("rejection_reason")
                if isinstance(rejection_reason, str) and rejection_reason:
                    round_state.null_miner_reason = rejection_reason
                rejected_txid = event.fields.get("rejected_txid")
                if isinstance(rejected_txid, str) and rejected_txid:
                    round_state.rejected_txid = rejected_txid
                rejected_stacks_block_hash = event.fields.get(
                    "rejected_stacks_block_hash"
                )
                if (
                    isinstance(rejected_stacks_block_hash, str)
                    and rejected_stacks_block_hash
                ):
                    round_state.rejected_stacks_block_hash = rejected_stacks_block_hash
                round_state.rejected_ts = event.ts
                round_state.winner_txid = None
                round_state.winner_stacks_block_hash = None
                round_state.winner_ts = event.ts
                self._refresh_current_miner_from_latest_round(event.ts)

        elif event.kind == "node_leader_block_commit":
            burn_height = event.fields.get("burn_height")
            commit_txid = event.fields.get("commit_txid")
            apparent_sender = event.fields.get("apparent_sender")
            stacks_block_hash = event.fields.get("stacks_block_hash")
            if (
                isinstance(burn_height, int)
                and isinstance(commit_txid, str)
                and commit_txid
                and isinstance(apparent_sender, str)
                and apparent_sender
            ):
                round_state = self._get_or_create_sortition_round(burn_height)
                if not any(
                    commit.commit_txid == commit_txid for commit in round_state.commits
                ):
                    round_state.commits.append(
                        SortitionCommitState(
                            commit_txid=commit_txid,
                            apparent_sender=apparent_sender,
                            stacks_block_hash=(
                                stacks_block_hash
                                if isinstance(stacks_block_hash, str)
                                else None
                            ),
                            burn_height=burn_height,
                            sortition_position=event.fields.get("sortition_position")
                            if isinstance(event.fields.get("sortition_position"), int)
                            else None,
                            parent_burn_block=event.fields.get("parent_burn_block")
                            if isinstance(event.fields.get("parent_burn_block"), int)
                            else None,
                            ts=event.ts,
                        )
                    )
                    if len(round_state.commits) > self.config.sortition_max_commits_per_round:
                        round_state.commits = round_state.commits[
                            -self.config.sortition_max_commits_per_round :
                        ]
                self._refresh_current_miner_from_latest_round(event.ts)

        elif event.kind == "node_tenure_notify":
            consensus_hash = event.fields.get("consensus_hash")
            burn_height = event.fields.get("burn_height")
            if isinstance(consensus_hash, str) and consensus_hash:
                self._set_current_consensus(consensus_hash, burn_height)
            winning_stacks_block_hash = event.fields.get("winning_stacks_block_hash")
            if isinstance(winning_stacks_block_hash, str) and winning_stacks_block_hash:
                self.current_miner_winning_stacks_block_hash = winning_stacks_block_hash
                if self._is_zero_hash(winning_stacks_block_hash) and isinstance(
                    burn_height, int
                ):
                    round_state = self._get_or_create_sortition_round(burn_height)
                    round_state.null_miner_won = True
                    if not round_state.null_miner_reason:
                        round_state.null_miner_reason = (
                            "Null miner selected (zero winning stacks hash)"
                        )
                    round_state.winner_txid = None
                    round_state.winner_stacks_block_hash = None
                    round_state.winner_ts = event.ts
                    round_state.rejected_ts = round_state.rejected_ts or event.ts
                self._refresh_current_miner_from_latest_round(event.ts)

        elif event.kind == "node_consensus":
            consensus_hash = event.fields.get("consensus_hash")
            burn_height = event.fields.get("burn_height")
            if isinstance(consensus_hash, str) and consensus_hash:
                self._set_current_consensus(consensus_hash, burn_height)
            if isinstance(burn_height, int):
                if (
                    self.last_burn_block_alert_height is None
                    or burn_height > self.last_burn_block_alert_height
                ):
                    self.last_burn_block_alert_height = burn_height
                    self._record_burn_block_event(event.ts, burn_height, alerts)
                    self._emit_alert(
                        alerts=alerts,
                        key="burn-block-%d" % burn_height,
                        severity="info",
                        message=self._burn_block_alert_message(
                            burn_height=burn_height,
                            event=event,
                        ),
                        ts=event.ts,
                    )

        elif event.kind == "node_burnchain_reorg":
            common_ancestor_height = event.fields.get("common_ancestor_height")
            if isinstance(common_ancestor_height, int):
                message = (
                    "Burnchain reorg detected: highest common ancestor at height %d"
                    % common_ancestor_height
                )
                if isinstance(self.current_bitcoin_block_height, int):
                    message += " | current_burn_height=%d" % self.current_bitcoin_block_height
                self._emit_alert(
                    alerts=alerts,
                    key="burnchain-reorg-%d" % common_ancestor_height,
                    severity="warning",
                    message=message,
                    ts=event.ts,
                )

        elif event.kind == "node_winning_block_commit":
            apparent_sender = event.fields.get("apparent_sender")
            if isinstance(apparent_sender, str) and apparent_sender:
                self.current_miner_apparent_sender = apparent_sender
            miner_pubkey = event.fields.get("miner_pubkey")
            if isinstance(miner_pubkey, str) and miner_pubkey:
                self.current_miner_pubkey = miner_pubkey
            winning_stacks_block_hash = event.fields.get("winning_stacks_block_hash")
            if isinstance(winning_stacks_block_hash, str) and winning_stacks_block_hash:
                self.current_miner_winning_stacks_block_hash = winning_stacks_block_hash
            self.current_miner_last_updated_ts = event.ts

        elif event.kind == "node_tenure_change":
            tenure_change_kind = event.fields.get("tenure_change_kind")
            txid = event.fields.get("txid")
            origin = event.fields.get("origin")
            block_height = event.fields.get("block_height")
            if not isinstance(block_height, int):
                block_height = self.current_stacks_block_height
            burn_height = event.fields.get("burn_height")
            if not isinstance(burn_height, int):
                burn_height = self.current_bitcoin_block_height
            if isinstance(tenure_change_kind, str):
                self.tenure_change_history.append(
                    {
                        "ts": event.ts,
                        "kind": tenure_change_kind,
                        "txid": txid if isinstance(txid, str) else None,
                        "origin": origin if isinstance(origin, str) else None,
                        "block_height": block_height,
                        "burn_height": burn_height,
                    }
                )
            if isinstance(tenure_change_kind, str) and "extend" in tenure_change_kind.lower():
                self.last_tenure_extend_kind = tenure_change_kind
                self.last_tenure_extend_txid = txid if isinstance(txid, str) else None
                self.last_tenure_extend_origin = origin if isinstance(origin, str) else None
                self.last_tenure_extend_ts = event.ts
                self.tenure_extend_history.append(
                    {
                        "ts": event.ts,
                        "kind": tenure_change_kind,
                        "txid": self.last_tenure_extend_txid,
                        "origin": self.last_tenure_extend_origin,
                        "block_height": block_height,
                        "burn_height": burn_height,
                    }
                )
                extend_key = (
                    "tenure-extend-%s" % self.last_tenure_extend_txid
                    if self.last_tenure_extend_txid
                    else "tenure-extend-%s-%s-%s"
                    % (
                        tenure_change_kind,
                        block_height if block_height is not None else "na",
                        burn_height if burn_height is not None else "na",
                    )
                )
                self._emit_alert(
                    alerts=alerts,
                    key=extend_key,
                    severity="info",
                    message=(
                        "Tenure extend observed: kind=%s txid=%s block_height=%s burn_height=%s"
                        % (
                            tenure_change_kind,
                            self.last_tenure_extend_txid or "n/a",
                            block_height if block_height is not None else "n/a",
                            burn_height if burn_height is not None else "n/a",
                        )
                    ),
                    ts=event.ts,
                )

        elif event.kind == "signer_state_machine_update":
            current_miner_pkh = event.fields.get("current_miner_pkh")
            if isinstance(current_miner_pkh, str) and current_miner_pkh:
                self.active_miner_pkh = current_miner_pkh
            tenure_id = event.fields.get("tenure_id")
            if isinstance(tenure_id, str) and tenure_id:
                self.active_miner_tenure_id = tenure_id
            parent_tenure_id = event.fields.get("parent_tenure_id")
            if isinstance(parent_tenure_id, str) and parent_tenure_id:
                self.active_miner_parent_tenure_id = parent_tenure_id
            parent_tenure_last_block = event.fields.get("parent_tenure_last_block")
            if isinstance(parent_tenure_last_block, str) and parent_tenure_last_block:
                self.active_miner_parent_last_block = parent_tenure_last_block
            parent_tenure_last_block_height = event.fields.get(
                "parent_tenure_last_block_height"
            )
            if isinstance(parent_tenure_last_block_height, int):
                self.active_miner_parent_last_block_height = parent_tenure_last_block_height
            burn_block = event.fields.get("burn_block")
            burn_height = event.fields.get("burn_height")
            if isinstance(burn_block, str) and burn_block:
                self.active_miner_burn_consensus_hash = burn_block
                self._set_current_consensus(burn_block, burn_height)
            if isinstance(burn_height, int):
                self.active_miner_burn_height = burn_height
            self.active_miner_last_update_ts = event.ts

        elif event.kind == "signer_block_proposal":
            self.last_signer_proposal_ts = event.ts
            self._clear_stall("signer-stall", event.ts, alerts)

            signature_hash = event.fields.get("signer_signature_hash")
            if signature_hash and self._is_recently_closed(signature_hash, event.ts):
                return alerts
            if signature_hash:
                state = self.proposals.setdefault(
                    signature_hash,
                    ProposalState(
                        start_ts=event.ts,
                        block_height=event.fields.get("block_height"),
                        burn_height=event.fields.get("burn_height"),
                    ),
                )
                self._record_proposal_activity(
                    signature_hash=signature_hash,
                    state=state,
                    ts=event.ts,
                    is_open=True,
                )

        elif event.kind == "signer_block_acceptance":
            signature_hash = event.fields.get("signer_signature_hash")
            signer_pubkey = event.fields.get("signer_pubkey")
            total_weight_approved = event.fields.get("total_weight_approved")
            total_weight = event.fields.get("total_weight")
            signature_weight = event.fields.get("signature_weight")
            percent = event.fields.get("percent_approved")
            block_height = event.fields.get("block_height")
            consensus_hash = event.fields.get("consensus_hash")
            if signature_hash:
                if self._is_recently_closed(signature_hash, event.ts):
                    return alerts
                state = self.proposals.setdefault(signature_hash, ProposalState(event.ts))
                if signer_pubkey:
                    self.seen_signers.add(signer_pubkey)
                    state.signers.add(signer_pubkey)
                if block_height is not None:
                    state.block_height = block_height
                if state.burn_height is None and isinstance(consensus_hash, str):
                    mapped_burn_height = self.burn_height_by_consensus_hash.get(
                        consensus_hash
                    )
                    if isinstance(mapped_burn_height, int):
                        state.burn_height = mapped_burn_height
                if total_weight is not None:
                    state.total_weight = total_weight
                    self.total_weight_samples.append(int(total_weight))
                if percent is not None:
                    state.max_percent = max(state.max_percent, float(percent))
                if isinstance(signature_weight, int) and signature_weight > 0:
                    if signer_pubkey:
                        self.signer_weight_samples[signer_pubkey].append(signature_weight)
                self._record_signer_response(
                    state,
                    signature_hash,
                    signer_pubkey,
                    "accept",
                    event.ts,
                    alerts,
                    block_height=block_height if isinstance(block_height, int) else None,
                )
                self._record_proposal_activity(
                    signature_hash=signature_hash,
                    state=state,
                    ts=event.ts,
                    is_open=True,
                )

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
                consensus_hash = event.fields.get("consensus_hash")
                if percent is not None:
                    state.max_percent = max(state.max_percent, float(percent))
                if block_height is not None:
                    state.block_height = block_height
                if state.burn_height is None and isinstance(consensus_hash, str):
                    mapped_burn_height = self.burn_height_by_consensus_hash.get(
                        consensus_hash
                    )
                    if isinstance(mapped_burn_height, int):
                        state.burn_height = mapped_burn_height
                if signer_pubkey:
                    self.seen_signers.add(signer_pubkey)
                    state.signers.add(signer_pubkey)
                self._record_signer_response(
                    state,
                    signature_hash,
                    signer_pubkey,
                    "accept",
                    event.ts,
                    alerts,
                    block_height=block_height if isinstance(block_height, int) else None,
                )
                self.proposal_reject_reasons.pop(signature_hash, None)
                self._record_proposal_activity(
                    signature_hash=signature_hash,
                    state=state,
                    ts=event.ts,
                    is_open=True,
                )

        elif event.kind in ("signer_block_rejection", "signer_rejection_threshold_reached"):
            signature_hash = event.fields.get("signer_signature_hash")
            if signature_hash:
                if self._is_recently_closed(signature_hash, event.ts):
                    return alerts
                state = self.proposals.setdefault(signature_hash, ProposalState(event.ts))
                self._apply_rejection_event(state, event)
                self._record_signer_response(
                    state,
                    signature_hash,
                    event.fields.get("signer_pubkey"),
                    "reject",
                    event.ts,
                    alerts,
                    block_height=event.fields.get("block_height")
                    if isinstance(event.fields.get("block_height"), int)
                    else None,
                )
                self._record_proposal_activity(
                    signature_hash=signature_hash,
                    state=state,
                    ts=event.ts,
                    is_open=True,
                )

                percent_rejected = event.fields.get("percent_rejected")
                threshold_reached = event.kind == "signer_rejection_threshold_reached"
                if (
                    not threshold_reached
                    and isinstance(percent_rejected, (int, float))
                    and percent_rejected >= 30.0
                ):
                    threshold_reached = True

                if threshold_reached:
                    reject_reason = self._summarize_reject_reason(
                        state, event.fields.get("reject_reason")
                    )
                    if reject_reason:
                        self.proposal_reject_reasons[signature_hash] = reject_reason
                    threshold_key = "proposal-reject-threshold-%s" % signature_hash
                    percent_label = (
                        "%.1f%%" % percent_rejected
                        if isinstance(percent_rejected, (int, float))
                        else "n/a"
                    )
                    reason_label = reject_reason or "unknown"
                    self._emit_alert(
                        alerts=alerts,
                        key=threshold_key,
                        severity="info",
                        message=(
                            "Proposal %s reached rejection threshold (%s rejected, reason=%s)"
                            % (signature_hash[:12], percent_label, reason_label)
                        ),
                        ts=event.ts,
                    )
                    self._record_rejection_insight(
                        signature_hash=signature_hash,
                        state=state,
                        ts=event.ts,
                        reject_reason=reject_reason,
                        alerts=alerts,
                    )
                    alerts.extend(
                        self._finalize_proposal(
                            signature_hash, event.ts, finalize_reason="rejected"
                        )
                    )

        elif event.kind == "signer_block_pushed":
            signature_hash = event.fields.get("signer_signature_hash")
            if signature_hash:
                if self._is_recently_closed(signature_hash, event.ts):
                    return alerts
                state = self.proposals.setdefault(signature_hash, ProposalState(event.ts))
                state.pushed_ts = event.ts
                block_height = event.fields.get("block_height")
                block_id = event.fields.get("block_id")
                consensus_hash = event.fields.get("consensus_hash")
                if block_height is not None:
                    state.block_height = block_height
                if not isinstance(consensus_hash, str) or not consensus_hash:
                    if isinstance(block_id, str) and block_id:
                        mapped_consensus = self.block_header_to_consensus.get(block_id)
                        if isinstance(mapped_consensus, str) and mapped_consensus:
                            consensus_hash = mapped_consensus
                if (not isinstance(consensus_hash, str) or not consensus_hash) and isinstance(
                    self.current_consensus_hash, str
                ):
                    consensus_hash = self.current_consensus_hash
                if isinstance(consensus_hash, str) and consensus_hash:
                    self._record_confirmed_block_event(
                        ts=event.ts,
                        source="signer_block_pushed",
                        consensus_hash=consensus_hash,
                        block_height=(
                            block_height
                            if isinstance(block_height, int)
                            else (
                                self.current_stacks_block_height
                                if isinstance(self.current_stacks_block_height, int)
                                else None
                            )
                        ),
                        block_id=block_id if isinstance(block_id, str) else None,
                        event_line=event.line,
                    )
                alerts.extend(self._finalize_proposal(signature_hash, event.ts))

        elif event.kind == "signer_new_block_event":
            signature_hash = event.fields.get("signer_signature_hash")
            if signature_hash:
                if self._is_recently_closed(signature_hash, event.ts):
                    return alerts
                state = self.proposals.setdefault(signature_hash, ProposalState(event.ts))
                block_height = event.fields.get("block_height")
                block_id = event.fields.get("block_id")
                consensus_hash = event.fields.get("consensus_hash")
                if block_height is not None:
                    state.block_height = block_height
                if (not isinstance(consensus_hash, str) or not consensus_hash) and isinstance(
                    self.current_consensus_hash, str
                ):
                    consensus_hash = self.current_consensus_hash
                self._record_confirmed_block_event(
                    ts=event.ts,
                    source="signer_new_block_event",
                    consensus_hash=consensus_hash if isinstance(consensus_hash, str) else None,
                    block_height=(
                        block_height
                        if isinstance(block_height, int)
                        else (
                            self.current_stacks_block_height
                            if isinstance(self.current_stacks_block_height, int)
                            else None
                        )
                    ),
                    block_id=block_id if isinstance(block_id, str) else None,
                    event_line=event.line,
                )
                alerts.extend(self._finalize_proposal(signature_hash, event.ts))

        elif event.kind == "signer_block_response":
            signature_hash = event.fields.get("signer_signature_hash")
            reject_reason = event.fields.get("reject_reason")
            if (
                isinstance(signature_hash, str)
                and signature_hash
                and reject_reason
                and reject_reason != "NotRejected"
            ):
                self.proposal_reject_reasons[signature_hash] = str(reject_reason)
                if not self._is_recently_closed(signature_hash, event.ts):
                    state = self.proposals.setdefault(signature_hash, ProposalState(event.ts))
                    self._apply_rejection_event(state, event)
                    self._record_proposal_activity(
                        signature_hash=signature_hash,
                        state=state,
                        ts=event.ts,
                        is_open=True,
                    )
            if reject_reason and reject_reason != "NotRejected":
                key = (
                    "signer-reject-%s" % signature_hash
                    if isinstance(signature_hash, str) and signature_hash
                    else "signer-reject-%s" % reject_reason
                )
                message = (
                    "Signer response rejection for proposal %s: %s"
                    % (
                        (signature_hash[:12] if isinstance(signature_hash, str) else "unknown"),
                        reject_reason,
                    )
                )
                self._emit_alert(
                    alerts=alerts,
                    key=key,
                    severity="info",
                    message=message,
                    ts=event.ts,
                )
                if signature_hash and not self._is_recently_closed(signature_hash, event.ts):
                    state = self.proposals.get(signature_hash)
                    if state is not None:
                        self._record_rejection_insight(
                            signature_hash=signature_hash,
                            state=state,
                            ts=event.ts,
                            reject_reason=str(reject_reason),
                            alerts=alerts,
                        )
                    alerts.extend(
                        self._finalize_proposal(
                            signature_hash,
                            event.ts,
                            finalize_reason="rejected",
                        )
                    )

        return alerts

    def tick(self, now: Optional[float] = None) -> Tuple[List[Alert], Optional[str]]:
        ts = now if now is not None else time.time()
        alerts: List[Alert] = []

        self._trim_stale_chunks(ts)
        self._trim_closed_proposals(ts)
        self._trim_recent_rejections(ts)
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
                severity = "critical"
                message = "No new node tip for %.0fs (threshold=%ds)" % (
                    node_gap,
                    self.config.node_stall_seconds,
                )
                if self._mempool_empty_recent(ts):
                    severity = "info"
                    message = (
                        "No new node tip for %.0fs (threshold=%ds) | mempool_ready_txs=0"
                        % (node_gap, self.config.node_stall_seconds)
                    )
                self._emit_stall(
                    alerts=alerts,
                    key="node-stall",
                    message=message,
                    ts=ts,
                    severity=severity,
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
                    severity="critical",
                )

    def _detect_proposal_timeouts(self, ts: float, alerts: List[Alert]) -> None:
        for signature_hash, state in list(self.proposals.items()):
            age = ts - state.start_ts
            if state.threshold_ts is None and age > self.config.proposal_timeout_seconds:
                boundary_match = self._match_boundary_burn_for_state(state)
                if boundary_match is not None:
                    burn_ts, burn_height = boundary_match
                    reason = (
                        state.boundary_reason
                        or self._summarize_reject_reason(state, None)
                        or "unknown"
                    )
                    parts = []
                    if state.block_height is not None:
                        parts.append(
                            "Proposal %s (height %d) delayed near burn-block boundary"
                            % (signature_hash[:12], state.block_height)
                        )
                    else:
                        parts.append(
                            "Proposal %s delayed near burn-block boundary"
                            % signature_hash[:12]
                        )
                    parts.append(
                        "burn_height %s -> %s"
                        % (
                            state.burn_height if state.burn_height is not None else "n/a",
                            burn_height,
                        )
                    )
                    if reason:
                        parts.append("reason=%s" % reason)
                    if state.max_reject_percent > 0:
                        parts.append("rejected~%.1f%%" % state.max_reject_percent)
                    parts.append("age=%.0fs" % age)
                    parts.append("Δt=%.1fs" % (burn_ts - state.start_ts))
                    self._emit_alert(
                        alerts=alerts,
                        key="proposal-timeout-boundary-%s" % signature_hash,
                        severity="warning",
                        message=" | ".join(parts),
                        ts=ts,
                    )
                else:
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
                closed = self.proposals.pop(signature_hash, None)
                if closed is not None:
                    self._record_proposal_activity(
                        signature_hash=signature_hash,
                        state=closed,
                        ts=ts,
                        is_open=False,
                        final_state="timed_out",
                    )

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

    def _record_signer_response(
        self,
        state: ProposalState,
        signature_hash: str,
        signer_pubkey: Optional[object],
        response: str,
        ts: float,
        alerts: List[Alert],
        block_height: Optional[int] = None,
    ) -> None:
        if not isinstance(signer_pubkey, str) or not signer_pubkey:
            return
        prior = state.signer_responses.get(signer_pubkey)
        if (
            prior == "accept"
            and response == "reject"
            and signer_pubkey not in state.accept_then_reject_signers
        ):
            label = self._signer_label(signer_pubkey)
            height = block_height if block_height is not None else state.block_height
            if height is not None:
                message = (
                    "Signer %s accepted then rejected proposal %s (height %d)"
                    % (label, signature_hash[:12], height)
                )
            else:
                message = (
                    "Signer %s accepted then rejected proposal %s"
                    % (label, signature_hash[:12])
                )
            self._emit_alert(
                alerts=alerts,
                key="signer-accept-then-reject-%s-%s"
                % (signature_hash, signer_pubkey[:10]),
                severity="critical",
                message=message,
                ts=ts,
            )
            state.accept_then_reject_signers.add(signer_pubkey)
        state.signer_responses[signer_pubkey] = response

    def _apply_rejection_event(self, state: ProposalState, event: ParsedEvent) -> None:
        signer_pubkey = event.fields.get("signer_pubkey")
        reject_reason = event.fields.get("reject_reason")
        percent_rejected = event.fields.get("percent_rejected")
        total_weight = event.fields.get("total_weight")
        signature_weight = event.fields.get("signature_weight")
        block_height = event.fields.get("block_height")
        consensus_hash = event.fields.get("consensus_hash")

        if isinstance(signer_pubkey, str) and signer_pubkey:
            state.reject_signers.add(signer_pubkey)
            self.seen_signers.add(signer_pubkey)
            if isinstance(signature_weight, int) and signature_weight > 0:
                self.signer_weight_samples[signer_pubkey].append(signature_weight)
        if isinstance(reject_reason, str) and reject_reason:
            state.reject_reasons.add(reject_reason)
            boundary_reason = self._boundary_reject_reason(reject_reason)
            if boundary_reason:
                state.boundary_reason = boundary_reason
        if isinstance(percent_rejected, (int, float)):
            state.max_reject_percent = max(state.max_reject_percent, float(percent_rejected))
        if isinstance(total_weight, int):
            state.total_weight = total_weight
            self.total_weight_samples.append(int(total_weight))
        if isinstance(block_height, int):
            state.block_height = block_height
        if state.burn_height is None and isinstance(consensus_hash, str) and consensus_hash:
            mapped_burn_height = self.burn_height_by_consensus_hash.get(consensus_hash)
            if isinstance(mapped_burn_height, int):
                state.burn_height = mapped_burn_height
        state.last_reject_ts = event.ts

    def _summarize_reject_reason(
        self, state: ProposalState, reject_reason: Optional[object]
    ) -> Optional[str]:
        if isinstance(state.boundary_reason, str) and state.boundary_reason:
            return state.boundary_reason
        if isinstance(reject_reason, str) and reject_reason:
            return reject_reason
        if state.reject_reasons:
            return sorted(state.reject_reasons)[0]
        return None

    def _record_rejection_insight(
        self,
        signature_hash: str,
        state: ProposalState,
        ts: float,
        reject_reason: Optional[str],
        alerts: List[Alert],
    ) -> None:
        entry: Optional[Dict[str, object]] = None
        for existing in self.recent_rejections:
            if existing.get("signature_hash") == signature_hash:
                entry = existing
                break
        if entry is None:
            entry = {
                "signature_hash": signature_hash,
                "alerted": False,
            }
            self.recent_rejections.append(entry)

        reject_reason = reject_reason or state.boundary_reason
        entry.update(
            {
                "ts": ts,
                "start_ts": state.start_ts,
                "block_height": state.block_height,
                "burn_height": state.burn_height,
                "reject_reason": reject_reason,
                "boundary_reason": state.boundary_reason,
                "max_reject_percent": state.max_reject_percent,
                "max_approved_percent": state.max_percent,
                "accept_signers": len(state.signers),
                "reject_signers": len(state.reject_signers),
            }
        )

        self._maybe_emit_boundary_rejection_alert(entry, alerts, burn_event=None)

    def _record_burn_block_event(
        self, ts: float, burn_height: int, alerts: List[Alert]
    ) -> None:
        self.recent_burn_block_events.append((ts, burn_height))
        self._evaluate_boundary_rejections(ts, burn_height, alerts)

    def _evaluate_boundary_rejections(
        self, burn_ts: float, burn_height: int, alerts: List[Alert]
    ) -> None:
        for entry in list(self.recent_rejections):
            if not isinstance(entry, dict):
                continue
            if entry.get("alerted"):
                continue
            self._maybe_emit_boundary_rejection_alert(
                entry,
                alerts,
                burn_event=(burn_ts, burn_height),
            )

    def _maybe_emit_boundary_rejection_alert(
        self,
        entry: Dict[str, object],
        alerts: List[Alert],
        burn_event: Optional[Tuple[float, int]],
    ) -> None:
        signature_hash = entry.get("signature_hash")
        if not isinstance(signature_hash, str) or not signature_hash:
            return
        if signature_hash in self.rejection_pattern_alerted:
            entry["alerted"] = True
            return

        match = self._match_burn_boundary_rejection(entry, burn_event)
        if match is None:
            return
        burn_ts, burn_height = match

        reason = entry.get("boundary_reason") or entry.get("reject_reason") or "unknown"
        proposal_burn_height = entry.get("burn_height")
        max_reject_percent = entry.get("max_reject_percent")
        max_approved_percent = entry.get("max_approved_percent")
        accept_signers = entry.get("accept_signers")
        reject_signers = entry.get("reject_signers")
        delta_seconds = burn_ts - float(entry.get("ts") or burn_ts)

        parts = [
            "Proposal %s rejected near burn-block boundary" % signature_hash[:12],
            "burn_height %s -> %s"
            % (
                proposal_burn_height if proposal_burn_height is not None else "n/a",
                burn_height,
            ),
            "reason=%s" % reason,
        ]
        if isinstance(max_reject_percent, (int, float)):
            parts.append("rejected~%.1f%%" % max_reject_percent)
        if isinstance(max_approved_percent, (int, float)) and max_approved_percent > 0:
            parts.append("approved~%.1f%%" % max_approved_percent)
        if isinstance(accept_signers, int) and isinstance(reject_signers, int):
            parts.append("signers %d accept / %d reject" % (accept_signers, reject_signers))
        parts.append("Δt=%.1fs" % delta_seconds)

        self._emit_alert(
            alerts=alerts,
            key="proposal-reject-boundary-%s" % signature_hash,
            severity="info",
            message=" | ".join(parts),
            ts=burn_ts,
        )
        entry["alerted"] = True
        self.rejection_pattern_alerted.add(signature_hash)

    def _match_burn_boundary_rejection(
        self,
        entry: Dict[str, object],
        burn_event: Optional[Tuple[float, int]],
    ) -> Optional[Tuple[float, int]]:
        reason = entry.get("boundary_reason") or entry.get("reject_reason")
        if not self._boundary_reject_reason(reason):
            return None
        proposal_burn_height = entry.get("burn_height")
        if not isinstance(proposal_burn_height, int):
            return None

        window = float(self.config.burn_block_boundary_window_seconds)
        entry_ts = entry.get("ts")
        entry_start_ts = entry.get("start_ts")

        events = []
        if burn_event is not None:
            events.append(burn_event)
        events.extend(self.recent_burn_block_events)
        for burn_ts, burn_height in events:
            if burn_height < proposal_burn_height:
                continue
            if isinstance(entry_ts, (int, float)) and abs(burn_ts - entry_ts) <= window:
                return burn_ts, burn_height
            if (
                isinstance(entry_start_ts, (int, float))
                and abs(burn_ts - entry_start_ts) <= window
            ):
                return burn_ts, burn_height
        return None

    def _match_boundary_burn_for_state(
        self, state: ProposalState
    ) -> Optional[Tuple[float, int]]:
        if not isinstance(state.boundary_reason, str) or not state.boundary_reason:
            return None
        if not isinstance(state.burn_height, int):
            return None
        window = float(self.config.burn_block_boundary_window_seconds)
        for burn_ts, burn_height in self.recent_burn_block_events:
            if burn_height < state.burn_height:
                continue
            if isinstance(state.last_reject_ts, (int, float)) and abs(
                burn_ts - state.last_reject_ts
            ) <= window:
                return burn_ts, burn_height
            if abs(burn_ts - state.start_ts) <= window:
                return burn_ts, burn_height
        return None

    def _boundary_reject_reason(self, reason: object) -> Optional[str]:
        if isinstance(reason, str) and reason:
            for candidate in BOUNDARY_REJECTION_REASONS:
                if candidate in reason:
                    return candidate
        return None

    def _finalize_proposal(
        self,
        signature_hash: str,
        ts: float,
        finalize_reason: Optional[str] = None,
    ) -> List[Alert]:
        alerts: List[Alert] = []
        state = self.proposals.pop(signature_hash, None)
        if state is None:
            self.closed_proposals[signature_hash] = ts
            return alerts

        self.completed_proposals += 1
        if state.threshold_ts is not None:
            self.completed_with_threshold += 1
        self.closed_proposals[signature_hash] = ts

        if finalize_reason != "rejected":
            if isinstance(state.burn_height, int):
                self.last_accepted_proposal_burn_height = state.burn_height
                self.last_accepted_proposal_ts = ts
            tracked_signers = set(self.signer_participation.keys())
            tracked_signers.update(self.seen_signers)
            tracked_signers.update(state.signers)
            for pubkey in tracked_signers:
                self.signer_participation[pubkey].append(pubkey in state.signers)
            self.proposal_reject_reasons.pop(signature_hash, None)
        self._record_proposal_activity(
            signature_hash=signature_hash,
            state=state,
            ts=ts,
            is_open=False,
            final_state=finalize_reason or "finalized",
        )

        return alerts

    def _record_proposal_activity(
        self,
        signature_hash: str,
        state: ProposalState,
        ts: float,
        is_open: bool,
        final_state: Optional[str] = None,
    ) -> None:
        self.proposal_activity.append(
            {
                "signature_hash": signature_hash,
                "start_ts": state.start_ts,
                "last_update_ts": ts,
                "block_height": state.block_height,
                "max_percent_observed": state.max_percent,
                "max_reject_percent": state.max_reject_percent,
                "threshold_seen": state.threshold_ts is not None,
                "unique_signers_seen": len(state.signers),
                "is_open": is_open,
                "final_state": final_state,
            }
        )

    def _is_zero_hash(self, value: object) -> bool:
        if not isinstance(value, str):
            return False
        if len(value) != len(ZERO_HASH):
            return False
        return value == ZERO_HASH

    def _get_or_create_sortition_round(self, burn_height: int) -> SortitionRoundState:
        round_state = self.sortition_rounds.get(burn_height)
        if round_state is not None:
            return round_state

        round_state = SortitionRoundState(burn_height=burn_height)
        self.sortition_rounds[burn_height] = round_state
        self.sortition_round_order.append(burn_height)
        self._trim_sortition_rounds()
        return round_state

    def _trim_sortition_rounds(self) -> None:
        while len(self.sortition_round_order) > self.config.sortition_history_rounds:
            oldest_burn_height = self.sortition_round_order.popleft()
            self.sortition_rounds.pop(oldest_burn_height, None)

    def _latest_successful_sortition_round(self) -> Optional[SortitionRoundState]:
        for burn_height in reversed(self.sortition_round_order):
            round_state = self.sortition_rounds.get(burn_height)
            if round_state and round_state.winner_txid:
                return round_state
        return None

    def _winner_apparent_sender(self, round_state: SortitionRoundState) -> Optional[str]:
        if not round_state.winner_txid:
            return None
        for commit in round_state.commits:
            if commit.commit_txid == round_state.winner_txid:
                return commit.apparent_sender
        return None

    def _winner_apparent_sender_for_txid(
        self, burn_height: int, winner_txid: str
    ) -> Optional[str]:
        round_state = self.sortition_rounds.get(burn_height)
        if round_state is None:
            return None
        for commit in round_state.commits:
            if commit.commit_txid == winner_txid:
                return commit.apparent_sender
        return None

    def _winner_parent_burn_block(
        self, round_state: SortitionRoundState
    ) -> Optional[int]:
        if not round_state.winner_txid:
            return None
        for commit in round_state.commits:
            if commit.commit_txid == round_state.winner_txid:
                return commit.parent_burn_block
        return None

    def _warn_on_sortition_parent_burn_mismatch(
        self,
        round_state: SortitionRoundState,
        burn_height: int,
        alerts: List[Alert],
        ts: float,
    ) -> None:
        if round_state.null_miner_won or not round_state.winner_txid:
            return
        last_accepted_burn = self.last_accepted_proposal_burn_height
        if not isinstance(last_accepted_burn, int):
            return
        parent_burn_block = self._winner_parent_burn_block(round_state)
        if parent_burn_block is None:
            return
        if parent_burn_block == last_accepted_burn:
            return
        self._emit_alert(
            alerts=alerts,
            key="sortition-parent-burn-mismatch-%d" % burn_height,
            severity="warning",
            message=(
                "Sortition winner at burn height %d committed to parent_burn_block=%d "
                "but last accepted proposal burn height is %d"
                % (burn_height, parent_burn_block, last_accepted_burn)
            ),
            ts=ts,
        )

    def _burn_block_alert_message(self, burn_height: int, event: ParsedEvent) -> str:
        sortition_state = "not_observed"
        new_miner = "n/a"

        if event.kind == "node_sortition_winner_selected":
            winner_txid = event.fields.get("winner_txid")
            winning_stacks_block_hash = event.fields.get("winning_stacks_block_hash")
            if self._is_zero_hash(winner_txid) or self._is_zero_hash(
                winning_stacks_block_hash
            ):
                sortition_state = "null_miner"
                new_miner = "unchanged"
            elif isinstance(winner_txid, str) and winner_txid:
                sortition_state = "winner_selected"
                winner_sender = self._winner_apparent_sender_for_txid(
                    burn_height, winner_txid
                )
                new_miner = winner_sender or ("txid:%s" % winner_txid[:12])
            else:
                sortition_state = "pending"
        elif event.kind == "node_sortition_winner_rejected":
            sortition_state = "null_miner"
            new_miner = "unchanged"
        else:
            round_state = self.sortition_rounds.get(burn_height)
            if round_state is not None:
                if round_state.null_miner_won:
                    sortition_state = "null_miner"
                    new_miner = "unchanged"
                elif round_state.winner_txid:
                    sortition_state = "winner_selected"
                    winner_sender = self._winner_apparent_sender(round_state)
                    new_miner = winner_sender or ("txid:%s" % round_state.winner_txid[:12])
                else:
                    sortition_state = "pending"

        return (
            "New burn block observed at height %d | sortition=%s | new_miner=%s"
            % (burn_height, sortition_state, new_miner)
        )

    def _sortition_commit_to_row(
        self,
        commit: SortitionCommitState,
        winner_txid: Optional[str],
    ) -> Dict[str, object]:
        stacks_block_height = (
            self.block_height_by_hash.get(commit.stacks_block_hash)
            if commit.stacks_block_hash
            else None
        )
        stacks_block_burn_height = self._burn_height_for_block_hash(
            commit.stacks_block_hash
        )
        return {
            "burn_height": commit.burn_height,
            "commit_txid": commit.commit_txid,
            "apparent_sender": commit.apparent_sender,
            "stacks_block_hash": commit.stacks_block_hash,
            "stacks_block_height": stacks_block_height,
            "stacks_block_burn_height": stacks_block_burn_height,
            "sortition_position": commit.sortition_position,
            "parent_burn_block": commit.parent_burn_block,
            "is_winner": bool(winner_txid and commit.commit_txid == winner_txid),
            "ts": commit.ts,
        }

    def _refresh_current_miner_from_latest_round(self, ts: float) -> None:
        round_state = self._latest_successful_sortition_round()
        if round_state is None:
            return
        winner_sender = self._winner_apparent_sender(round_state)
        if winner_sender:
            self.current_miner_apparent_sender = winner_sender
        if round_state.winner_stacks_block_hash:
            self.current_miner_winning_stacks_block_hash = round_state.winner_stacks_block_hash
        self.current_miner_last_updated_ts = ts

    def _remember_block_hash_height(self, block_hash: str, block_height: int) -> None:
        existing_height = self.block_height_by_hash.get(block_hash)
        if existing_height is not None and existing_height >= block_height:
            return

        self.block_height_by_hash[block_hash] = block_height
        self.block_height_hash_order.append(block_hash)
        while len(self.block_height_hash_order) > self.config.hash_height_map_size:
            oldest_hash = self.block_height_hash_order.popleft()
            if oldest_hash in self.block_height_by_hash and oldest_hash != block_hash:
                self.block_height_by_hash.pop(oldest_hash, None)

    def _remember_block_header_consensus(
        self, block_hash: str, consensus_hash: str
    ) -> None:
        existing = self.block_header_to_consensus.get(block_hash)
        if existing == consensus_hash:
            return
        self.block_header_to_consensus[block_hash] = consensus_hash
        self.block_header_consensus_order.append(block_hash)
        while len(self.block_header_consensus_order) > self.config.hash_height_map_size:
            oldest_hash = self.block_header_consensus_order.popleft()
            if (
                oldest_hash in self.block_header_to_consensus
                and oldest_hash != block_hash
            ):
                self.block_header_to_consensus.pop(oldest_hash, None)

    def _remember_block_hash_burn(self, block_hash: str, burn_height: int) -> None:
        existing_height = self.burn_height_by_block_hash.get(block_hash)
        if existing_height is not None and existing_height >= burn_height:
            return

        self.burn_height_by_block_hash[block_hash] = burn_height
        self.block_burn_height_order.append(block_hash)
        while len(self.block_burn_height_order) > self.config.hash_height_map_size:
            oldest_hash = self.block_burn_height_order.popleft()
            if oldest_hash in self.burn_height_by_block_hash and oldest_hash != block_hash:
                self.burn_height_by_block_hash.pop(oldest_hash, None)

    def _burn_height_for_block_hash(self, block_hash: Optional[str]) -> Optional[int]:
        if not isinstance(block_hash, str) or not block_hash:
            return None
        burn_height = self.burn_height_by_block_hash.get(block_hash)
        if isinstance(burn_height, int):
            return burn_height
        consensus_hash = self.block_header_to_consensus.get(block_hash)
        if isinstance(consensus_hash, str):
            burn_height = self.burn_height_by_consensus_hash.get(consensus_hash)
            if isinstance(burn_height, int):
                self._remember_block_hash_burn(block_hash, burn_height)
                return burn_height
        return None

    def _index_hash_height_from_event(self, event: ParsedEvent) -> None:
        block_height = event.fields.get("block_height")
        parent_last_height = event.fields.get("parent_tenure_last_block_height")
        parent_last_block = event.fields.get("parent_tenure_last_block")

        if isinstance(block_height, int):
            block_id = event.fields.get("block_id")
            if isinstance(block_id, str) and block_id:
                self._remember_block_hash_height(block_id, block_height)

        if (
            isinstance(parent_last_block, str)
            and parent_last_block
            and isinstance(parent_last_height, int)
        ):
            self._remember_block_hash_height(parent_last_block, parent_last_height)

        block_header_hash = event.fields.get("block_header_hash")
        consensus_hash = event.fields.get("consensus_hash")
        burn_height = event.fields.get("burn_height")

        if isinstance(block_header_hash, str) and block_header_hash:
            if isinstance(consensus_hash, str) and consensus_hash:
                self._remember_block_header_consensus(block_header_hash, consensus_hash)
            if isinstance(burn_height, int):
                self._remember_block_hash_burn(block_header_hash, burn_height)
            if isinstance(block_height, int):
                self._remember_block_hash_height(block_header_hash, block_height)

        block_id = event.fields.get("block_id")
        if isinstance(block_id, str) and block_id and isinstance(burn_height, int):
            self._remember_block_hash_burn(block_id, burn_height)
        if (
            isinstance(block_id, str)
            and block_id
            and isinstance(consensus_hash, str)
            and consensus_hash
        ):
            self._remember_block_header_consensus(block_id, consensus_hash)

    def _record_confirmed_block_event(
        self,
        ts: float,
        source: str,
        consensus_hash: Optional[str] = None,
        block_height: Optional[int] = None,
        block_id: Optional[str] = None,
        block_header_hash: Optional[str] = None,
        event_line: Optional[str] = None,
    ) -> None:
        key: str
        if isinstance(block_header_hash, str) and block_header_hash:
            key = "header:%s" % block_header_hash
        elif isinstance(block_id, str) and block_id:
            key = "id:%s" % block_id
        elif (
            isinstance(consensus_hash, str)
            and consensus_hash
            and isinstance(block_height, int)
        ):
            key = "tenure-height:%s:%d" % (consensus_hash, block_height)
        elif isinstance(event_line, str) and event_line:
            line_hash = hashlib.sha1(event_line.encode("utf-8")).hexdigest()[:20]
            key = "line:%s:%s" % (source, line_hash)
        else:
            key = "source-ts:%s:%0.9f" % (source, ts)

        if key in self.confirmed_block_keys:
            return

        self.confirmed_block_keys.add(key)
        self.confirmed_block_key_order.append(key)
        while len(self.confirmed_block_key_order) > 16384:
            oldest = self.confirmed_block_key_order.popleft()
            self.confirmed_block_keys.discard(oldest)

        self.confirmed_block_history.append(
            {
                "ts": ts,
                "source": source,
                "consensus_hash": (
                    consensus_hash
                    if isinstance(consensus_hash, str) and consensus_hash
                    else None
                ),
                "block_height": block_height if isinstance(block_height, int) else None,
                "block_id": block_id if isinstance(block_id, str) and block_id else None,
                "block_header_hash": (
                    block_header_hash
                    if isinstance(block_header_hash, str) and block_header_hash
                    else None
                ),
            }
        )

    def _record_tenure_block_count(
        self, consensus_hash: Optional[str], ts: float
    ) -> None:
        normalized_hash = (
            consensus_hash if isinstance(consensus_hash, str) and consensus_hash else None
        )
        if normalized_hash is None and isinstance(self.current_consensus_hash, str):
            normalized_hash = self.current_consensus_hash
        if not isinstance(normalized_hash, str) or not normalized_hash:
            return

        if (
            self.tenure_block_counts
            and self.tenure_block_counts[-1].get("consensus_hash") == normalized_hash
        ):
            current = self.tenure_block_counts[-1]
            current_count = current.get("block_count")
            if isinstance(current_count, int):
                current["block_count"] = current_count + 1
            else:
                current["block_count"] = 1
            current["end_ts"] = ts
            return

        self.tenure_block_counts.append(
            {
                "consensus_hash": normalized_hash,
                "block_count": 1,
                "start_ts": ts,
                "end_ts": ts,
            }
        )

    def _extract_costs_from_fields(
        self, fields: Dict[str, object]
    ) -> Tuple[Dict[str, int], Dict[str, float]]:
        costs: Dict[str, int] = {}
        cost_percents: Dict[str, float] = {}
        for key, limit in EXECUTION_COST_LIMITS.items():
            value = fields.get(key)
            if not isinstance(value, int):
                continue
            costs[key] = value
            cost_percents[key] = max(
                0.0, min(100.0, (float(value) / float(limit)) * 100.0)
            )
        return costs, cost_percents

    def _remember_pending_execution_cost(
        self,
        block_header_hash: str,
        ts: float,
        block_height: Optional[int],
        tx_count: Optional[int],
        percent_full: Optional[int],
        consensus_hash: Optional[str],
        costs: Dict[str, int],
        cost_percents: Dict[str, float],
    ) -> None:
        self.pending_execution_cost_by_block_hash[block_header_hash] = {
            "ts": ts,
            "block_height": block_height,
            "tx_count": tx_count,
            "percent_full": percent_full,
            "consensus_hash": consensus_hash,
            "costs": costs,
            "costs_percent": cost_percents,
        }
        self.pending_execution_cost_order.append(block_header_hash)
        while (
            len(self.pending_execution_cost_order)
            > self.config.hash_height_map_size * 2
        ):
            oldest_hash = self.pending_execution_cost_order.popleft()
            if oldest_hash != block_header_hash:
                self.pending_execution_cost_by_block_hash.pop(oldest_hash, None)

    def _apply_confirmed_execution_cost(
        self,
        ts: float,
        block_header_hash: Optional[str],
        consensus_hash: Optional[str],
    ) -> None:
        if not isinstance(block_header_hash, str) or not block_header_hash:
            return
        pending = self.pending_execution_cost_by_block_hash.pop(block_header_hash, None)
        if not isinstance(pending, dict):
            return
        costs = pending.get("costs")
        cost_percents = pending.get("costs_percent")
        if not isinstance(costs, dict) or not costs:
            return
        if not isinstance(cost_percents, dict):
            return
        self.last_execution_costs = dict(costs)
        self.last_execution_costs_percent = dict(cost_percents)
        self.last_execution_cost_ts = ts
        self.last_execution_cost_block_height = (
            pending.get("block_height")
            if isinstance(pending.get("block_height"), int)
            else None
        )
        self.last_execution_cost_tx_count = (
            pending.get("tx_count")
            if isinstance(pending.get("tx_count"), int)
            else None
        )
        self.last_execution_cost_percent_full = (
            pending.get("percent_full")
            if isinstance(pending.get("percent_full"), int)
            else None
        )
        resolved_consensus_hash = (
            consensus_hash
            if isinstance(consensus_hash, str) and consensus_hash
            else pending.get("consensus_hash")
            if isinstance(pending.get("consensus_hash"), str)
            else None
        )
        self.execution_cost_history.append(
            {
                "ts": ts,
                "block_height": self.last_execution_cost_block_height,
                "tx_count": self.last_execution_cost_tx_count,
                "percent_full": self.last_execution_cost_percent_full,
                "consensus_hash": resolved_consensus_hash,
                "costs": self.last_execution_costs,
                "costs_percent": self.last_execution_costs_percent,
            }
        )

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
                    "max_reject_percent": state.max_reject_percent,
                    "threshold_seen": state.threshold_ts is not None,
                    "unique_signers_seen": len(state.signers),
                }
            )
        open_proposals.sort(key=lambda row: row["age_seconds"], reverse=True)

        recent_proposals: List[Dict[str, object]] = []
        open_hashes = set(self.proposals.keys())
        seen_recent: Set[str] = set()
        for row in reversed(self.proposal_activity):
            signature_hash = row.get("signature_hash")
            if not isinstance(signature_hash, str):
                continue
            if signature_hash in seen_recent:
                continue
            seen_recent.add(signature_hash)
            start_ts = row.get("start_ts")
            if not isinstance(start_ts, (int, float)):
                continue
            recent_proposals.append(
                {
                    "signature_hash": signature_hash,
                    "age_seconds": max(0.0, ts - float(start_ts)),
                    "block_height": row.get("block_height"),
                    "max_percent_observed": row.get("max_percent_observed"),
                    "max_reject_percent": row.get("max_reject_percent"),
                    "threshold_seen": bool(row.get("threshold_seen")),
                    "unique_signers_seen": row.get("unique_signers_seen"),
                    "last_update_ts": row.get("last_update_ts"),
                    "is_open": signature_hash in open_hashes,
                    "reject_reason": self.proposal_reject_reasons.get(signature_hash),
                    "status": self._proposal_status(
                        is_open=(signature_hash in open_hashes),
                        threshold_seen=bool(row.get("threshold_seen")),
                        reject_reason=self.proposal_reject_reasons.get(signature_hash),
                        final_state=row.get("final_state"),
                    ),
                }
            )
            if len(recent_proposals) >= 50:
                break

        latest_successful_round = self._latest_successful_sortition_round()
        winner_stacks_block_height: Optional[int] = None
        winner_apparent_sender: Optional[str] = None
        last_successful_round_commits: List[Dict[str, object]] = []
        if latest_successful_round is not None:
            winner_apparent_sender = self._winner_apparent_sender(latest_successful_round)
            if latest_successful_round.winner_stacks_block_hash:
                winner_stacks_block_height = self.block_height_by_hash.get(
                    latest_successful_round.winner_stacks_block_hash
                )
            last_successful_round_commits = [
                self._sortition_commit_to_row(
                    commit, latest_successful_round.winner_txid
                )
                for commit in sorted(
                    latest_successful_round.commits,
                    key=lambda item: (
                        item.sortition_position
                        if item.sortition_position is not None
                        else 10**9,
                        item.commit_txid,
                    ),
                )
            ]

        commits_since_last_successful: List[Dict[str, object]] = []
        last_successful_burn_height = (
            latest_successful_round.burn_height if latest_successful_round else None
        )
        for burn_height in sorted(self.sortition_rounds.keys()):
            if (
                last_successful_burn_height is not None
                and burn_height <= last_successful_burn_height
            ):
                continue
            round_state = self.sortition_rounds[burn_height]
            for commit in round_state.commits:
                commits_since_last_successful.append(
                    self._sortition_commit_to_row(commit, round_state.winner_txid)
                )
        commits_since_last_successful = commits_since_last_successful[-100:]

        recent_sortition_rounds: List[Dict[str, object]] = []
        for burn_height in list(self.sortition_round_order)[-12:]:
            round_state = self.sortition_rounds.get(burn_height)
            if round_state is None:
                continue
            winner_sender = self._winner_apparent_sender(round_state)
            winner_height = (
                self.block_height_by_hash.get(round_state.winner_stacks_block_hash)
                if round_state.winner_stacks_block_hash
                else None
            )
            recent_sortition_rounds.append(
                {
                    "burn_height": burn_height,
                    "commit_count": len(round_state.commits),
                    "winner_txid": round_state.winner_txid,
                    "winner_apparent_sender": winner_sender,
                    "winner_stacks_block_hash": round_state.winner_stacks_block_hash,
                    "winner_stacks_block_height": winner_height,
                    "winner_seen": bool(round_state.winner_txid),
                    "null_miner_won": round_state.null_miner_won,
                    "null_miner_reason": round_state.null_miner_reason,
                    "rejected_txid": round_state.rejected_txid,
                    "rejected_stacks_block_hash": round_state.rejected_stacks_block_hash,
                }
            )
        recent_sortition_rounds.reverse()

        recent_sortition_details: List[Dict[str, object]] = []
        for burn_height in reversed(list(self.sortition_round_order)[-3:]):
            round_state = self.sortition_rounds.get(burn_height)
            if round_state is None:
                continue
            winner_sender = self._winner_apparent_sender(round_state)
            commits = [
                self._sortition_commit_to_row(commit, round_state.winner_txid)
                for commit in sorted(
                    round_state.commits,
                    key=lambda item: (
                        item.sortition_position
                        if item.sortition_position is not None
                        else 10**9,
                        item.commit_txid,
                    ),
                )
            ]
            recent_sortition_details.append(
                {
                    "burn_height": burn_height,
                    "winner_txid": round_state.winner_txid,
                    "winner_apparent_sender": winner_sender,
                    "winner_stacks_block_hash": round_state.winner_stacks_block_hash,
                    "null_miner_won": round_state.null_miner_won,
                    "null_miner_reason": round_state.null_miner_reason,
                    "rejected_txid": round_state.rejected_txid,
                    "rejected_stacks_block_hash": round_state.rejected_stacks_block_hash,
                    "winner_ts": round_state.winner_ts,
                    "rejected_ts": round_state.rejected_ts,
                    "commits": commits,
                }
            )

        latest_sortition_round = (
            self.sortition_rounds.get(self.sortition_round_order[-1])
            if self.sortition_round_order
            else None
        )
        latest_sortition: Optional[Dict[str, object]] = None
        if latest_sortition_round is not None:
            latest_winner_sender = self._winner_apparent_sender(latest_sortition_round)
            latest_sortition = {
                "burn_height": latest_sortition_round.burn_height,
                "winner_txid": latest_sortition_round.winner_txid,
                "winner_apparent_sender": latest_winner_sender,
                "winner_stacks_block_hash": latest_sortition_round.winner_stacks_block_hash,
                "null_miner_won": latest_sortition_round.null_miner_won,
                "null_miner_reason": latest_sortition_round.null_miner_reason,
                "rejected_txid": latest_sortition_round.rejected_txid,
                "rejected_stacks_block_hash": latest_sortition_round.rejected_stacks_block_hash,
                "winner_ts": latest_sortition_round.winner_ts,
                "rejected_ts": latest_sortition_round.rejected_ts,
            }

        recent_tenure_extends = list(self.tenure_extend_history)[-5:]
        recent_tenure_extends.reverse()
        tenure_extend_history = list(self.tenure_extend_history)
        tenure_change_history = list(self.tenure_change_history)
        avg_block_interval_seconds: Optional[float] = None
        if self.block_interval_samples > 0:
            avg_block_interval_seconds = (
                self.block_interval_total_seconds / float(self.block_interval_samples)
            )

        return {
            "timestamp": ts,
            "uptime_seconds": max(0, int(ts - self.start_ts)),
            "lines": dict(self.processed_lines),
            "events": dict(self.event_counts),
            "current_stacks_block_height": self.current_stacks_block_height,
            "current_bitcoin_block_height": self.current_bitcoin_block_height,
            "current_consensus_hash": self.current_consensus_hash,
            "current_consensus_burn_height": self.current_consensus_burn_height,
            "current_miner_apparent_sender": self.current_miner_apparent_sender,
            "current_miner_pubkey": self.current_miner_pubkey,
            "current_miner_winning_stacks_block_hash": (
                self.current_miner_winning_stacks_block_hash
            ),
            "current_miner_last_updated_ts": self.current_miner_last_updated_ts,
            "current_miner_age_seconds": (
                None
                if self.current_miner_last_updated_ts is None
                else max(0.0, ts - self.current_miner_last_updated_ts)
            ),
            "active_miner": {
                "current_miner_pkh": self.active_miner_pkh,
                "tenure_id": self.active_miner_tenure_id,
                "parent_tenure_id": self.active_miner_parent_tenure_id,
                "parent_tenure_last_block": self.active_miner_parent_last_block,
                "parent_tenure_last_block_height": self.active_miner_parent_last_block_height,
                "burn_block_consensus_hash": self.active_miner_burn_consensus_hash,
                "burn_block_height": self.active_miner_burn_height,
                "last_update_ts": self.active_miner_last_update_ts,
                "age_seconds": (
                    None
                    if self.active_miner_last_update_ts is None
                    else max(0.0, ts - self.active_miner_last_update_ts)
                ),
            },
            "last_successful_sortition": (
                None
                if latest_successful_round is None
                else {
                    "burn_height": latest_successful_round.burn_height,
                    "winner_txid": latest_successful_round.winner_txid,
                    "winner_apparent_sender": winner_apparent_sender,
                    "winner_stacks_block_hash": latest_successful_round.winner_stacks_block_hash,
                    "winner_stacks_block_height": winner_stacks_block_height,
                    "winner_ts": latest_successful_round.winner_ts,
                }
            ),
            "last_successful_sortition_commits": last_successful_round_commits,
            "miners_since_last_successful_sortition": commits_since_last_successful,
            "latest_sortition": latest_sortition,
            "recent_sortition_details": recent_sortition_details,
            "recent_sortition_rounds": recent_sortition_rounds,
            "sortition_rounds_tracked_count": len(self.sortition_rounds),
            "last_tenure_extend_kind": self.last_tenure_extend_kind,
            "last_tenure_extend_txid": self.last_tenure_extend_txid,
            "last_tenure_extend_origin": self.last_tenure_extend_origin,
            "last_tenure_extend_ts": self.last_tenure_extend_ts,
            "last_tenure_extend_age_seconds": (
                None
                if self.last_tenure_extend_ts is None
                else max(0.0, ts - self.last_tenure_extend_ts)
            ),
            "recent_tenure_extends": recent_tenure_extends,
            "tenure_extend_history": tenure_extend_history,
            "tenure_change_history": tenure_change_history,
            "recent_tenure_block_counts": list(self.tenure_block_counts),
            "recent_confirmed_blocks": list(self.confirmed_block_history),
            "recent_confirmed_blocks_capacity": self.confirmed_block_history.maxlen,
            "node_tip_age_seconds": (
                None if self.last_node_tip_ts is None else max(0.0, ts - self.last_node_tip_ts)
            ),
            "avg_block_interval_seconds": avg_block_interval_seconds,
            "avg_block_interval_samples": self.block_interval_samples,
            "last_block_interval_seconds": self.last_block_interval_seconds,
            "mempool_ready_txs": self.last_mempool_ready_txs,
            "mempool_ready_ts": self.last_mempool_ready_ts,
            "mempool_stop_reason": self.last_mempool_stop_reason,
            "mempool_elapsed_ms": self.last_mempool_elapsed_ms,
            "mempool_age_seconds": (
                None
                if self.last_mempool_ts is None
                else max(0.0, ts - self.last_mempool_ts)
            ),
            "execution_cost_limits": dict(EXECUTION_COST_LIMITS),
            "latest_execution_costs": self.last_execution_costs,
            "latest_execution_costs_percent": self.last_execution_costs_percent,
            "latest_execution_cost_block_height": self.last_execution_cost_block_height,
            "latest_execution_cost_tx_count": self.last_execution_cost_tx_count,
            "latest_execution_cost_percent_full": self.last_execution_cost_percent_full,
            "latest_execution_cost_age_seconds": (
                None
                if self.last_execution_cost_ts is None
                else max(0.0, ts - self.last_execution_cost_ts)
            ),
            "recent_execution_costs": list(self.execution_cost_history),
            "signer_proposal_age_seconds": (
                None
                if self.last_signer_proposal_ts is None
                else max(0.0, ts - self.last_signer_proposal_ts)
            ),
            "stale_chunks_window_count": len(self.stale_chunks),
            "open_proposals": open_proposals[:50],
            "recent_proposals": recent_proposals,
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
        self, alerts: List[Alert], key: str, message: str, ts: float, severity: str
    ) -> None:
        self.active_stalls.add(key)
        self._emit_alert(alerts, key=key, severity=severity, message=message, ts=ts)

    def _mempool_empty_recent(self, ts: float) -> bool:
        if self.last_mempool_stop_reason != "NoMoreCandidates":
            return False
        if self.last_mempool_ready_txs != 0:
            return False
        if self.last_mempool_ready_ts is None:
            return False
        window = min(self.config.node_stall_seconds, 120)
        return (ts - self.last_mempool_ready_ts) <= window

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
        if self.suppress_alerts:
            return
        previous_ts = self.last_alert_ts.get(key)
        if previous_ts is not None and (ts - previous_ts) < self.config.alert_cooldown_seconds:
            return
        self.last_alert_ts[key] = ts
        alerts.append(Alert(key=key, severity=severity, message=message, ts=ts))

    def _set_current_consensus(
        self, consensus_hash: str, burn_height: Optional[int] = None
    ) -> None:
        self.current_consensus_hash = consensus_hash
        if isinstance(burn_height, int):
            self.current_consensus_burn_height = burn_height
            self.burn_height_by_consensus_hash[consensus_hash] = burn_height
            self._propagate_burn_height_for_consensus(consensus_hash, burn_height)
            return
        known_burn_height = self.burn_height_by_consensus_hash.get(consensus_hash)
        self.current_consensus_burn_height = known_burn_height

    def _propagate_burn_height_for_consensus(
        self, consensus_hash: str, burn_height: int
    ) -> None:
        for block_hash, mapped_consensus in list(self.block_header_to_consensus.items()):
            if mapped_consensus == consensus_hash:
                self._remember_block_hash_burn(block_hash, burn_height)

    def _update_chain_heights(self, fields: Dict[str, object]) -> None:
        block_height = fields.get("block_height")
        burn_height = fields.get("burn_height")
        consensus_hash = fields.get("consensus_hash")
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
        if isinstance(consensus_hash, str) and consensus_hash:
            self._set_current_consensus(consensus_hash, burn_height)

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
                self.proposal_reject_reasons.pop(signature_hash, None)

    def _trim_recent_rejections(self, ts: float) -> None:
        cutoff = ts - self.config.closed_proposal_retention_seconds
        if not self.recent_rejections:
            return
        kept: Deque[Dict[str, object]] = deque(maxlen=self.recent_rejections.maxlen)
        for entry in self.recent_rejections:
            entry_ts = entry.get("ts") if isinstance(entry, dict) else None
            if isinstance(entry_ts, (int, float)) and entry_ts < cutoff:
                continue
            if isinstance(entry, dict):
                kept.append(entry)
        self.recent_rejections = kept

    def _proposal_status(
        self,
        is_open: bool,
        threshold_seen: bool,
        reject_reason: Optional[str],
        final_state: object,
    ) -> str:
        if threshold_seen:
            return "approved"
        if isinstance(final_state, str) and final_state == "rejected":
            return "rejected"
        if isinstance(final_state, str) and final_state == "timed_out":
            return "rejected"
        if reject_reason:
            return "rejected"
        if is_open:
            return "in_progress"
        return "approved"
