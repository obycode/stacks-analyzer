import threading
import unittest
from collections import deque
from types import SimpleNamespace

from stacks_analyzer.detector import Alert
from stacks_analyzer.service import MonitoringService


class _DummyNotifier:
    def __init__(self, results=None):
        self.results = list(results or [])
        self.sent = []

    def send(self, text: str, parse_mode=None) -> bool:
        _ = parse_mode
        self.sent.append(text)
        if self.results:
            return bool(self.results.pop(0))
        return True


class TestServiceTelegramResolution(unittest.TestCase):
    def _build_service(self, notifier: _DummyNotifier) -> MonitoringService:
        service = MonitoringService.__new__(MonitoringService)
        service.state_lock = threading.Lock()
        service.recent_alerts = deque(maxlen=200)
        service.recent_reports = deque(maxlen=200)
        service.history_store = None
        service.detector = None
        service.notifier = notifier
        service.suppress_notifications = False
        service.telegram_critical_open_keys = set()
        service.config = SimpleNamespace(
            telegram=SimpleNamespace(min_alert_severity="critical")
        )
        return service

    def test_sends_resolution_message_for_tracked_critical_alert(self) -> None:
        notifier = _DummyNotifier()
        service = self._build_service(notifier)

        service._publish_alert(
            Alert(
                key="node-stall",
                severity="critical",
                message="No new node tip for 120s",
                ts=100.0,
            )
        )
        service._publish_alert(
            Alert(
                key="node-stall-recovered",
                severity="info",
                message="node-stall recovered",
                ts=130.0,
            )
        )

        self.assertEqual(
            notifier.sent,
            [
                "[ALERT][CRITICAL] No new node tip for 120s",
                "[RESOLVED][CRITICAL] node-stall recovered",
            ],
        )
        self.assertNotIn("node-stall", service.telegram_critical_open_keys)

    def test_no_resolution_message_when_critical_send_failed(self) -> None:
        notifier = _DummyNotifier(results=[False, True])
        service = self._build_service(notifier)

        service._publish_alert(
            Alert(
                key="node-stall",
                severity="critical",
                message="No new node tip for 120s",
                ts=100.0,
            )
        )
        service._publish_alert(
            Alert(
                key="node-stall-recovered",
                severity="info",
                message="node-stall recovered",
                ts=130.0,
            )
        )

        # Only the initial alert send is attempted. Recovery should not send because
        # the critical alert was never tracked as successfully delivered.
        self.assertEqual(
            notifier.sent,
            [
                "[ALERT][CRITICAL] No new node tip for 120s",
            ],
        )
        self.assertNotIn("node-stall", service.telegram_critical_open_keys)


if __name__ == "__main__":
    unittest.main()
