import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


EPOCH_TS_RE = re.compile(r"\[(?P<epoch>\d{10}(?:\.\d+)?)\]")
STALE_CHUNK_RE = re.compile(
    r"ID\s+(?P<chunk_id>\d+)\s+version\s+(?P<version>\d+).+expected\s+(?P<expected>\d+)\)"
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
                events.append(
                    ParsedEvent(
                        source=source,
                        kind="node_tip_advanced",
                        ts=ts,
                        fields={"tip": tip_value},
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
