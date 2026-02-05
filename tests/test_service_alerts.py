import unittest
from types import SimpleNamespace

from stacks_analyzer.detector import Alert
from stacks_analyzer.service import MonitoringService


class TestServiceAlertRouting(unittest.TestCase):
    def _service_with_min_severity(self, min_severity: str) -> MonitoringService:
        service = MonitoringService.__new__(MonitoringService)
        service.config = SimpleNamespace(
            telegram=SimpleNamespace(min_alert_severity=min_severity)
        )
        return service

    def test_info_not_sent_when_min_is_critical(self) -> None:
        service = self._service_with_min_severity("critical")
        alert = Alert(
            key="signer-reject-aabbcc",
            severity="info",
            message="Signer response rejection for proposal aabbcc: SortitionViewMismatch",
            ts=100.0,
        )
        self.assertFalse(service._should_notify_telegram_for_alert(alert))

    def test_critical_sent_when_min_is_critical(self) -> None:
        service = self._service_with_min_severity("critical")
        alert = Alert(
            key="node-stall",
            severity="critical",
            message="No new node tip for 120s",
            ts=100.0,
        )
        self.assertTrue(service._should_notify_telegram_for_alert(alert))

    def test_warning_sent_when_min_is_warning(self) -> None:
        service = self._service_with_min_severity("warning")
        alert = Alert(
            key="large-signer-participation",
            severity="warning",
            message="Large signer participation dropped",
            ts=100.0,
        )
        self.assertTrue(service._should_notify_telegram_for_alert(alert))


if __name__ == "__main__":
    unittest.main()
