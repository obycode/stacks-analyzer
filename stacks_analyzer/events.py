import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


EPOCH_TS_RE = re.compile(r"\[(?P<epoch>\d{10}(?:\.\d+)?)\]")
STALE_CHUNK_RE = re.compile(
    r"ID\s+(?P<chunk_id>\d+)\s+version\s+(?P<version>\d+).+expected\s+(?P<expected>\d+)\)"
)
WINNING_BLOCK_COMMIT_RE = re.compile(
    r"Received burnchain block #(?P<burn_height>\d+)\s+including block_commit_op "
    r"\(winning\)\s+-\s+(?P<apparent_sender>[^\s]+)\s+\((?P<stacks_block_hash>[0-9a-fA-F]+)\)"
)
CONSENSUS_LINE_RE = re.compile(
    r"CONSENSUS\((?P<burn_height>\d+)\):\s*(?P<consensus_hash>[0-9a-fA-F]+)"
)
TENURE_CHANGE_PAYLOAD_RE = re.compile(r"payload:\s*TenureChange\((?P<kind>[^)]+)\)")
ACCEPTED_BURN_HEIGHT_RE = re.compile(r"ACCEPTED\((?P<burn_height>\d+)\)")
LEADER_BLOCK_COMMIT_RE = re.compile(
    r"leader block commit\s+(?P<txid>[0-9a-fA-F]+)\s+at\s+"
    r"(?P<burn_height>\d+),(?P<sortition_position>\d+)"
)
SORTITION_WINNER_RE = re.compile(
    r"SORTITION\((?P<burn_height>\d+)\):\s+WINNER SELECTED,\s+txid:\s+"
    r"(?P<txid>[0-9a-fA-F]+),\s+stacks_block_hash:\s+(?P<stacks_block_hash>[0-9a-fA-F]+)"
)
SORTITION_WINNER_REJECTED_RE = re.compile(
    r"SORTITION\((?P<burn_height>\d+)\):\s+WINNER REJECTED:\s+\"(?P<reason>[^\"]+)\",\s+"
    r"txid:\s+(?P<txid>[0-9a-fA-F]+),\s+stacks_block_hash:\s+(?P<stacks_block_hash>[0-9a-fA-F]+)"
)
SIGNER_BURN_BLOCK_EVENT_RE = re.compile(
    r"Received a new burn block event for block height\s+(?P<burn_height>\d+)"
)
ADVANCED_TIP_RE = re.compile(
    r"Advanced to new tip!\s+(?P<consensus_hash>[0-9a-fA-F]+)/(?P<block_header_hash>[0-9a-fA-F]+)"
)
NAKAMOTO_BLOCK_RE = re.compile(
    r"Handle incoming Nakamoto block\s+(?P<consensus_hash>[0-9a-fA-F]+)/(?P<block_header_hash>[0-9a-fA-F]+)"
)


def extract_timestamp(line: str) -> float:
    match = EPOCH_TS_RE.search(line)
    if match:
        try:
            return float(match.group("epoch"))
        except ValueError:
            pass
    return time.time()


def extract_field(line: str, name: str) -> Optional[str]:
    pattern = re.compile(r"%s:\s*([^,\s\)]+)" % re.escape(name))
    match = pattern.search(line)
    if not match:
        return None
    return match.group(1)


@dataclass
class ParsedEvent:
    source: str
    kind: str
    ts: float
    fields: Dict[str, Any] = field(default_factory=dict)
    line: str = ""


class LogParser:
    def parse_line(self, source: str, line: str) -> List[ParsedEvent]:
        ts = extract_timestamp(line)
        events: List[ParsedEvent] = []

        if source == "node":
            if "Advanced to new tip!" in line:
                tip_value = line.split("Advanced to new tip!", 1)[-1].strip()
                tip_match = ADVANCED_TIP_RE.search(line)
                events.append(
                    ParsedEvent(
                        source=source,
                        kind="node_tip_advanced",
                        ts=ts,
                        fields={
                            "tip": tip_value,
                            "consensus_hash": (
                                tip_match.group("consensus_hash") if tip_match else None
                            ),
                            "block_header_hash": (
                                tip_match.group("block_header_hash") if tip_match else None
                            ),
                        },
                        line=line,
                    )
                )

            if "Handle incoming Nakamoto block" in line:
                block_match = NAKAMOTO_BLOCK_RE.search(line)
                events.append(
                    ParsedEvent(
                        source=source,
                        kind="node_nakamoto_block",
                        ts=ts,
                        fields={
                            "consensus_hash": (
                                block_match.group("consensus_hash")
                                if block_match
                                else None
                            ),
                            "block_header_hash": (
                                block_match.group("block_header_hash")
                                if block_match
                                else None
                            ),
                            "block_id": extract_field(line, "block_id"),
                        },
                        line=line,
                    )
                )

            if "Received block proposal request" in line or "validated anchored block" in line:
                block_header_hash = extract_field(line, "block_header_hash")
                block_height = extract_field(line, "height")
                burn_height = extract_field(line, "burn_block_height") or extract_field(
                    line, "burn_height"
                )
                events.append(
                    ParsedEvent(
                        source=source,
                        kind="node_block_proposal",
                        ts=ts,
                        fields={
                            "block_header_hash": block_header_hash,
                            "block_height": int(block_height) if block_height else None,
                            "burn_height": int(burn_height) if burn_height else None,
                            "parent_block_id": extract_field(
                                line, "parent_stacks_block_id"
                            ),
                        },
                        line=line,
                    )
                )

            if "PoX reward set loaded from written block state" in line:
                reward_block_id = extract_field(line, "reward_set_block_id")
                burn_header_height = extract_field(line, "burn_header_height")
                stacks_block_height = extract_field(line, "stacks_block_height")
                events.append(
                    ParsedEvent(
                        source=source,
                        kind="node_reward_set_state",
                        ts=ts,
                        fields={
                            "block_id": reward_block_id,
                            "burn_height": (
                                int(burn_header_height) if burn_header_height else None
                            ),
                            "block_height": (
                                int(stacks_block_height) if stacks_block_height else None
                            ),
                        },
                        line=line,
                    )
                )

            if "Received StackerDBChunk" in line and "stale" in line:
                stale_match = STALE_CHUNK_RE.search(line)
                events.append(
                    ParsedEvent(
                        source=source,
                        kind="node_stale_chunk",
                        ts=ts,
                        fields={
                            "chunk_id": stale_match.group("chunk_id")
                            if stale_match
                            else None,
                            "version": stale_match.group("version")
                            if stale_match
                            else None,
                            "expected": stale_match.group("expected")
                            if stale_match
                            else None,
                        },
                        line=line,
                    )
                )

            if "leader block commit" in line and "ACCEPTED(" in line:
                burn_height_match = ACCEPTED_BURN_HEIGHT_RE.search(line)
                commit_match = LEADER_BLOCK_COMMIT_RE.search(line)
                parent_burn_block = extract_field(line, "parent_burn_block")
                events.append(
                    ParsedEvent(
                        source=source,
                        kind="node_leader_block_commit",
                        ts=ts,
                        fields={
                            "burn_height": (
                                int(burn_height_match.group("burn_height"))
                                if burn_height_match
                                else None
                            ),
                            "commit_txid": (
                                commit_match.group("txid") if commit_match else None
                            ),
                            "sortition_position": (
                                int(commit_match.group("sortition_position"))
                                if commit_match
                                else None
                            ),
                            "apparent_sender": extract_field(line, "apparent_sender"),
                            "stacks_block_hash": extract_field(line, "stacks_block_hash"),
                            "parent_burn_block": (
                                int(parent_burn_block) if parent_burn_block else None
                            ),
                        },
                        line=line,
                    )
                )

            if "SORTITION(" in line and "WINNER SELECTED" in line:
                winner_match = SORTITION_WINNER_RE.search(line)
                burn_block_hash = extract_field(line, "burn_block_hash")
                events.append(
                    ParsedEvent(
                        source=source,
                        kind="node_sortition_winner_selected",
                        ts=ts,
                        fields={
                            "burn_height": (
                                int(winner_match.group("burn_height"))
                                if winner_match
                                else None
                            ),
                            "winner_txid": (
                                winner_match.group("txid") if winner_match else None
                            ),
                            "winning_stacks_block_hash": (
                                winner_match.group("stacks_block_hash")
                                if winner_match
                                else None
                            ),
                            "burn_block_hash": burn_block_hash,
                        },
                        line=line,
                    )
                )

            if "SORTITION(" in line and "WINNER REJECTED" in line:
                rejected_match = SORTITION_WINNER_REJECTED_RE.search(line)
                burn_block_hash = extract_field(line, "burn_block_hash")
                events.append(
                    ParsedEvent(
                        source=source,
                        kind="node_sortition_winner_rejected",
                        ts=ts,
                        fields={
                            "burn_height": (
                                int(rejected_match.group("burn_height"))
                                if rejected_match
                                else None
                            ),
                            "rejected_txid": (
                                rejected_match.group("txid") if rejected_match else None
                            ),
                            "rejected_stacks_block_hash": (
                                rejected_match.group("stacks_block_hash")
                                if rejected_match
                                else None
                            ),
                            "rejection_reason": (
                                rejected_match.group("reason")
                                if rejected_match
                                else None
                            ),
                            "burn_block_hash": burn_block_hash,
                        },
                        line=line,
                    )
                )

            if "Tenure: Notify burn block!" in line:
                burn_block_height = extract_field(line, "burn_block_height")
                events.append(
                    ParsedEvent(
                        source=source,
                        kind="node_tenure_notify",
                        ts=ts,
                        fields={
                            "consensus_hash": extract_field(line, "consensus_hash"),
                            "burn_height": (
                                int(burn_block_height) if burn_block_height else None
                            ),
                            "winning_stacks_block_hash": extract_field(
                                line, "winning_stacks_block_hash"
                            ),
                            "sortition_id": extract_field(line, "sortition_id"),
                        },
                        line=line,
                    )
                )

            if "CONSENSUS(" in line:
                consensus_match = CONSENSUS_LINE_RE.search(line)
                if consensus_match:
                    events.append(
                        ParsedEvent(
                            source=source,
                            kind="node_consensus",
                            ts=ts,
                            fields={
                                "consensus_hash": consensus_match.group("consensus_hash"),
                                "burn_height": int(consensus_match.group("burn_height")),
                            },
                            line=line,
                        )
                    )

            if "including block_commit_op (winning) -" in line:
                winning_match = WINNING_BLOCK_COMMIT_RE.search(line)
                if winning_match:
                    events.append(
                        ParsedEvent(
                            source=source,
                            kind="node_winning_block_commit",
                            ts=ts,
                            fields={
                                "burn_height": int(winning_match.group("burn_height")),
                                "apparent_sender": winning_match.group("apparent_sender"),
                                "winning_stacks_block_hash": winning_match.group(
                                    "stacks_block_hash"
                                ),
                                # Some deployments may include one of these fields.
                                "miner_pubkey": (
                                    extract_field(line, "miner_pubkey")
                                    or extract_field(line, "miner_public_key")
                                    or extract_field(line, "public_key")
                                ),
                            },
                            line=line,
                        )
                    )

            if "payload: TenureChange(" in line:
                tenure_match = TENURE_CHANGE_PAYLOAD_RE.search(line)
                block_height_match = re.search(
                    r"(?:^|,\s)block_height:\s*(\d+)", line
                ) or re.search(r"(?:^|,\s)height:\s*(\d+)", line)
                burn_height_match = re.search(
                    r"(?:^|,\s)burn_block_height:\s*(\d+)", line
                )
                events.append(
                    ParsedEvent(
                        source=source,
                        kind="node_tenure_change",
                        ts=ts,
                        fields={
                            "tenure_change_kind": tenure_match.group("kind")
                            if tenure_match
                            else None,
                            "txid": extract_field(line, "tx"),
                            "origin": extract_field(line, "origin"),
                            "block_height": (
                                int(block_height_match.group(1))
                                if block_height_match
                                else None
                            ),
                            "burn_height": (
                                int(burn_height_match.group(1))
                                if burn_height_match
                                else None
                            ),
                        },
                        line=line,
                    )
                )

            if " ERROR " in line or " WARN " in line:
                events.append(
                    ParsedEvent(
                        source=source,
                        kind="node_error_or_warn",
                        ts=ts,
                        fields={},
                        line=line,
                    )
                )

        if source == "signer":
            if "received a block proposal for a new block" in line:
                signature_hash = extract_field(line, "signer_signature_hash")
                block_height = extract_field(line, "block_height")
                burn_height = extract_field(line, "burn_height")
                events.append(
                    ParsedEvent(
                        source=source,
                        kind="signer_block_proposal",
                        ts=ts,
                        fields={
                            "signer_signature_hash": signature_hash,
                            "block_height": int(block_height) if block_height else None,
                            "burn_height": int(burn_height) if burn_height else None,
                            "block_id": extract_field(line, "block_id"),
                            "consensus_hash": extract_field(line, "consensus_hash"),
                        },
                        line=line,
                    )
                )

            if "Received state machine update" in line and "ActiveMiner {" in line:
                burn_block_height = extract_field(line, "burn_block_height")
                parent_tenure_last_block_height = extract_field(
                    line, "parent_tenure_last_block_height"
                )
                events.append(
                    ParsedEvent(
                        source=source,
                        kind="signer_state_machine_update",
                        ts=ts,
                        fields={
                            "burn_block": extract_field(line, "burn_block"),
                            "burn_height": (
                                int(burn_block_height) if burn_block_height else None
                            ),
                            "current_miner_pkh": extract_field(line, "current_miner_pkh"),
                            "tenure_id": extract_field(line, "tenure_id"),
                            "parent_tenure_id": extract_field(line, "parent_tenure_id"),
                            "parent_tenure_last_block": extract_field(
                                line, "parent_tenure_last_block"
                            ),
                            "parent_tenure_last_block_height": (
                                int(parent_tenure_last_block_height)
                                if parent_tenure_last_block_height
                                else None
                            ),
                        },
                        line=line,
                    )
                )

            if "Received a new burn block event for block height" in line:
                burn_match = SIGNER_BURN_BLOCK_EVENT_RE.search(line)
                events.append(
                    ParsedEvent(
                        source=source,
                        kind="signer_burn_block_event",
                        ts=ts,
                        fields={
                            "burn_height": (
                                int(burn_match.group("burn_height"))
                                if burn_match
                                else None
                            )
                        },
                        line=line,
                    )
                )

            if "Received block acceptance" in line:
                signature_hash = extract_field(line, "signer_signature_hash")
                total_weight_approved = extract_field(line, "total_weight_approved")
                total_weight = extract_field(line, "total_weight")
                percent = extract_field(line, "percent_approved")
                block_height = extract_field(line, "block_height")
                events.append(
                    ParsedEvent(
                        source=source,
                        kind="signer_block_acceptance",
                        ts=ts,
                        fields={
                            "signer_signature_hash": signature_hash,
                            "signer_pubkey": extract_field(line, "signer_pubkey"),
                            "total_weight_approved": int(total_weight_approved)
                            if total_weight_approved
                            else None,
                            "total_weight": int(total_weight) if total_weight else None,
                            "percent_approved": float(percent) if percent else None,
                            "block_height": int(block_height) if block_height else None,
                            "consensus_hash": extract_field(line, "consensus_hash"),
                        },
                        line=line,
                    )
                )

            if "Received block rejection and have reached the rejection threshold" in line:
                signature_hash = extract_field(line, "signer_signature_hash")
                total_weight_rejected = extract_field(line, "total_weight_rejected")
                total_weight = extract_field(line, "total_weight")
                percent = extract_field(line, "percent_rejected")
                block_height = extract_field(line, "block_height")
                events.append(
                    ParsedEvent(
                        source=source,
                        kind="signer_rejection_threshold_reached",
                        ts=ts,
                        fields={
                            "signer_signature_hash": signature_hash,
                            "signer_pubkey": extract_field(line, "signer_pubkey"),
                            "total_weight_rejected": int(total_weight_rejected)
                            if total_weight_rejected
                            else None,
                            "total_weight": int(total_weight) if total_weight else None,
                            "percent_rejected": float(percent) if percent else None,
                            "block_height": int(block_height) if block_height else None,
                            "consensus_hash": extract_field(line, "consensus_hash"),
                            "reject_reason": extract_field(line, "reject_reason"),
                        },
                        line=line,
                    )
                )

            elif "Received block rejection" in line:
                signature_hash = extract_field(line, "signer_signature_hash")
                total_weight_rejected = extract_field(line, "total_weight_rejected")
                total_weight = extract_field(line, "total_weight")
                percent = extract_field(line, "percent_rejected")
                block_height = extract_field(line, "block_height")
                events.append(
                    ParsedEvent(
                        source=source,
                        kind="signer_block_rejection",
                        ts=ts,
                        fields={
                            "signer_signature_hash": signature_hash,
                            "signer_pubkey": extract_field(line, "signer_pubkey"),
                            "total_weight_rejected": int(total_weight_rejected)
                            if total_weight_rejected
                            else None,
                            "total_weight": int(total_weight) if total_weight else None,
                            "percent_rejected": float(percent) if percent else None,
                            "block_height": int(block_height) if block_height else None,
                            "consensus_hash": extract_field(line, "consensus_hash"),
                            "reject_reason": extract_field(line, "reject_reason"),
                        },
                        line=line,
                    )
                )

            if "Received block acceptance and have reached the threshold" in line:
                signature_hash = extract_field(line, "signer_signature_hash")
                percent = extract_field(line, "percent_approved")
                block_height = extract_field(line, "block_height")
                events.append(
                    ParsedEvent(
                        source=source,
                        kind="signer_threshold_reached",
                        ts=ts,
                        fields={
                            "signer_signature_hash": signature_hash,
                            "signer_pubkey": extract_field(line, "signer_pubkey"),
                            "percent_approved": float(percent) if percent else None,
                            "block_height": int(block_height) if block_height else None,
                            "consensus_hash": extract_field(line, "consensus_hash"),
                        },
                        line=line,
                    )
                )

            if "Got block pushed message" in line:
                signature_hash = extract_field(line, "signer_signature_hash")
                block_height = extract_field(line, "block_height")
                events.append(
                    ParsedEvent(
                        source=source,
                        kind="signer_block_pushed",
                        ts=ts,
                        fields={
                            "signer_signature_hash": signature_hash,
                            "block_height": int(block_height) if block_height else None,
                            "block_id": extract_field(line, "block_id"),
                        },
                        line=line,
                    )
                )

            if "Received a new block event." in line:
                signature_hash = extract_field(line, "signer_signature_hash")
                block_height = extract_field(line, "block_height")
                events.append(
                    ParsedEvent(
                        source=source,
                        kind="signer_new_block_event",
                        ts=ts,
                        fields={
                            "signer_signature_hash": signature_hash,
                            "block_height": int(block_height) if block_height else None,
                            "block_id": extract_field(line, "block_id"),
                        },
                        line=line,
                    )
                )

            if "Broadcasting block response to stacks node:" in line:
                signature_hash = extract_field(line, "signer_signature_hash")
                reject_reason = extract_field(line, "reject_reason")
                events.append(
                    ParsedEvent(
                        source=source,
                        kind="signer_block_response",
                        ts=ts,
                        fields={
                            "signer_signature_hash": signature_hash,
                            "reject_reason": reject_reason,
                            "accepted": "Accepted(" in line,
                        },
                        line=line,
                    )
                )

            if " ERROR " in line or " WARN " in line:
                events.append(
                    ParsedEvent(
                        source=source,
                        kind="signer_error_or_warn",
                        ts=ts,
                        fields={},
                        line=line,
                    )
                )

        return events
