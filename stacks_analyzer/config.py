import json
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from .detector import DetectorConfig


@dataclass
class TelegramConfig:
    token: str = ""
    chat_id: str = ""
    enabled: bool = False
    send_reports: bool = False
    min_alert_severity: str = "critical"


@dataclass
class WebConfig:
    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = 8787


@dataclass
class HistoryConfig:
    enabled: bool = False
    path: str = "history.sqlite"
    retention_hours: int = 48
    report_log_window_before_seconds: int = 600
    report_log_window_after_seconds: int = 300


@dataclass
class ServiceConfig:
    mode: str = "files"
    node_log_path: Optional[str] = None
    signer_log_path: Optional[str] = None
    node_journal_unit: str = "stacks-node"
    signer_journal_unit: str = "stacks-signer"
    from_beginning: bool = False
    run_once: bool = False
    poll_interval_seconds: float = 0.25
    report_output_path: Optional[str] = None
    signer_names_path: Optional[str] = None
    detector: DetectorConfig = field(default_factory=DetectorConfig)
    telegram: TelegramConfig = field(default_factory=TelegramConfig)
    web: WebConfig = field(default_factory=WebConfig)
    history: HistoryConfig = field(default_factory=HistoryConfig)


def load_json_config(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def build_service_config(raw: Optional[Dict[str, Any]]) -> ServiceConfig:
    payload = raw or {}

    detector_payload = payload.get("detector", {})
    detector = DetectorConfig(
        node_stall_seconds=int(
            detector_payload.get("node_stall_seconds", DetectorConfig.node_stall_seconds)
        ),
        signer_stall_seconds=int(
            detector_payload.get(
                "signer_stall_seconds", DetectorConfig.signer_stall_seconds
            )
        ),
        proposal_timeout_seconds=int(
            detector_payload.get(
                "proposal_timeout_seconds", DetectorConfig.proposal_timeout_seconds
            )
        ),
        stale_chunk_window_seconds=int(
            detector_payload.get(
                "stale_chunk_window_seconds", DetectorConfig.stale_chunk_window_seconds
            )
        ),
        stale_chunk_threshold=int(
            detector_payload.get(
                "stale_chunk_threshold", DetectorConfig.stale_chunk_threshold
            )
        ),
        report_interval_seconds=int(
            detector_payload.get(
                "report_interval_seconds", DetectorConfig.report_interval_seconds
            )
        ),
        alert_cooldown_seconds=int(
            detector_payload.get(
                "alert_cooldown_seconds", DetectorConfig.alert_cooldown_seconds
            )
        ),
        large_signer_min_samples=int(
            detector_payload.get(
                "large_signer_min_samples", DetectorConfig.large_signer_min_samples
            )
        ),
        large_signer_top_n=int(
            detector_payload.get("large_signer_top_n", DetectorConfig.large_signer_top_n)
        ),
        large_signer_window=int(
            detector_payload.get("large_signer_window", DetectorConfig.large_signer_window)
        ),
        large_signer_min_participation=float(
            detector_payload.get(
                "large_signer_min_participation",
                DetectorConfig.large_signer_min_participation,
            )
        ),
        closed_proposal_retention_seconds=int(
            detector_payload.get(
                "closed_proposal_retention_seconds",
                DetectorConfig.closed_proposal_retention_seconds,
            )
        ),
        proposal_history_size=int(
            detector_payload.get(
                "proposal_history_size",
                DetectorConfig.proposal_history_size,
            )
        ),
        burn_block_boundary_window_seconds=int(
            detector_payload.get(
                "burn_block_boundary_window_seconds",
                DetectorConfig.burn_block_boundary_window_seconds,
            )
        ),
    )

    telegram_payload = payload.get("telegram", {})
    telegram = TelegramConfig(
        token=str(telegram_payload.get("token", "")),
        chat_id=str(telegram_payload.get("chat_id", "")),
        enabled=bool(telegram_payload.get("enabled", False)),
        send_reports=bool(telegram_payload.get("send_reports", False)),
        min_alert_severity=str(
            telegram_payload.get("min_alert_severity", "critical")
        ).lower(),
    )

    web_payload = payload.get("web", {})
    web = WebConfig(
        enabled=bool(web_payload.get("enabled", False)),
        host=str(web_payload.get("host", "127.0.0.1")),
        port=int(web_payload.get("port", 8787)),
    )

    history_payload = payload.get("history", {})
    history = HistoryConfig(
        enabled=bool(history_payload.get("enabled", False)),
        path=str(history_payload.get("path", "history.sqlite")),
        retention_hours=int(history_payload.get("retention_hours", 48)),
        report_log_window_before_seconds=int(
            history_payload.get("report_log_window_before_seconds", 600)
        ),
        report_log_window_after_seconds=int(
            history_payload.get("report_log_window_after_seconds", 300)
        ),
    )

    return ServiceConfig(
        mode=str(payload.get("mode", "files")),
        node_log_path=payload.get("node_log_path"),
        signer_log_path=payload.get("signer_log_path"),
        node_journal_unit=str(payload.get("node_journal_unit", "stacks-node")),
        signer_journal_unit=str(payload.get("signer_journal_unit", "stacks-signer")),
        from_beginning=bool(payload.get("from_beginning", False)),
        run_once=bool(payload.get("run_once", False)),
        poll_interval_seconds=float(payload.get("poll_interval_seconds", 0.25)),
        report_output_path=payload.get("report_output_path"),
        signer_names_path=payload.get("signer_names_path"),
        detector=detector,
        telegram=telegram,
        web=web,
        history=history,
    )
