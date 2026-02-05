import argparse
import copy
from typing import Any, Dict

from .config import ServiceConfig, build_service_config, load_json_config
from .service import MonitoringService


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze stacks-node and stacks-signer logs for anomalies."
    )
    parser.add_argument("--config", help="Path to JSON config file.")
    parser.add_argument(
        "--mode",
        choices=["files", "journalctl"],
        help="Log source mode. files reads paths; journalctl tails systemd units.",
    )
    parser.add_argument("--node-log-path", help="Path to node log file.")
    parser.add_argument("--signer-log-path", help="Path to signer log file.")
    parser.add_argument(
        "--node-journal-unit", help="systemd unit for stacks node (journalctl mode)."
    )
    parser.add_argument(
        "--signer-journal-unit",
        help="systemd unit for signer service (journalctl mode).",
    )
    parser.add_argument(
        "--from-beginning",
        action="store_true",
        help="Read file logs from start instead of tailing from end.",
    )
    parser.add_argument(
        "--run-once",
        action="store_true",
        help="Process current file content and exit.",
    )
    parser.add_argument(
        "--report-output-path",
        help="Optional file path to append periodic reports.",
    )
    parser.add_argument(
        "--signer-names-path",
        help="Optional JSON file mapping signer pubkeys to display names.",
    )
    parser.add_argument(
        "--report-interval-seconds",
        type=int,
        help="Seconds between periodic reports.",
    )
    parser.add_argument(
        "--node-stall-seconds", type=int, help="Alert if no node tip for this duration."
    )
    parser.add_argument(
        "--signer-stall-seconds",
        type=int,
        help="Alert if no signer proposal for this duration.",
    )
    parser.add_argument(
        "--proposal-timeout-seconds",
        type=int,
        help="Alert when a proposal has no threshold event for this duration.",
    )
    parser.add_argument(
        "--telegram-token", help="Telegram bot token (enables telegram delivery)."
    )
    parser.add_argument("--telegram-chat-id", help="Telegram chat id.")
    parser.add_argument(
        "--telegram-send-reports",
        action="store_true",
        help="Send periodic reports to Telegram.",
    )
    parser.add_argument(
        "--web-enable",
        action="store_true",
        help="Enable built-in dashboard web server.",
    )
    parser.add_argument(
        "--web-host",
        help="Dashboard bind host (default: 127.0.0.1).",
    )
    parser.add_argument(
        "--web-port",
        type=int,
        help="Dashboard bind port (default: 8787).",
    )
    return parser.parse_args()


def merged_config_from_cli(args: argparse.Namespace) -> ServiceConfig:
    raw: Dict[str, Any] = {}
    if args.config:
        raw = load_json_config(args.config)

    merged = copy.deepcopy(raw)
    merged.setdefault("detector", {})
    merged.setdefault("telegram", {})

    if args.mode:
        merged["mode"] = args.mode
    if args.node_log_path:
        merged["node_log_path"] = args.node_log_path
    if args.signer_log_path:
        merged["signer_log_path"] = args.signer_log_path
    if args.node_journal_unit:
        merged["node_journal_unit"] = args.node_journal_unit
    if args.signer_journal_unit:
        merged["signer_journal_unit"] = args.signer_journal_unit
    if args.from_beginning:
        merged["from_beginning"] = True
    if args.run_once:
        merged["run_once"] = True
    if args.report_output_path:
        merged["report_output_path"] = args.report_output_path
    if args.signer_names_path:
        merged["signer_names_path"] = args.signer_names_path

    if args.report_interval_seconds is not None:
        merged["detector"]["report_interval_seconds"] = args.report_interval_seconds
    if args.node_stall_seconds is not None:
        merged["detector"]["node_stall_seconds"] = args.node_stall_seconds
    if args.signer_stall_seconds is not None:
        merged["detector"]["signer_stall_seconds"] = args.signer_stall_seconds
    if args.proposal_timeout_seconds is not None:
        merged["detector"]["proposal_timeout_seconds"] = args.proposal_timeout_seconds

    if args.telegram_token:
        merged["telegram"]["token"] = args.telegram_token
        merged["telegram"]["enabled"] = True
    if args.telegram_chat_id:
        merged["telegram"]["chat_id"] = args.telegram_chat_id
        merged["telegram"]["enabled"] = True
    if args.telegram_send_reports:
        merged["telegram"]["send_reports"] = True

    if args.web_enable:
        merged["web"] = merged.get("web", {})
        merged["web"]["enabled"] = True
    if args.web_host:
        merged["web"] = merged.get("web", {})
        merged["web"]["host"] = args.web_host
    if args.web_port is not None:
        merged["web"] = merged.get("web", {})
        merged["web"]["port"] = args.web_port

    return build_service_config(merged)


def validate_config(config: ServiceConfig) -> None:
    if config.mode == "files":
        if not config.node_log_path and not config.signer_log_path:
            raise ValueError(
                "files mode requires at least one of --node-log-path or --signer-log-path"
            )
    if config.mode == "journalctl" and config.run_once:
        raise ValueError("--run-once is only supported in files mode")


def main() -> int:
    args = parse_args()
    config = merged_config_from_cli(args)
    validate_config(config)

    service = MonitoringService(config)
    return service.run()


if __name__ == "__main__":
    raise SystemExit(main())
