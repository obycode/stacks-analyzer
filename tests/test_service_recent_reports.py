import unittest
from collections import deque

from stacks_analyzer.service import MonitoringService


class _DummyHistoryStore:
    def __init__(self, rows):
        self.rows = rows

    def list_reports(self, limit: int = 100):
        _ = limit
        return list(self.rows)


class TestServiceRecentReportsHydration(unittest.TestCase):
    def test_hydrate_recent_reports_from_history(self) -> None:
        service = MonitoringService.__new__(MonitoringService)
        service.recent_reports = deque(maxlen=10)
        service.history_store = _DummyHistoryStore(
            [
                {
                    "id": 12,
                    "ts": 1200.0,
                    "severity": "critical",
                    "alert_key": "node-stall",
                    "summary": "latest",
                },
                {
                    "id": 11,
                    "ts": 1100.0,
                    "severity": "warning",
                    "alert_key": "proposal-timeout",
                    "summary": "older",
                },
            ]
        )

        service._hydrate_recent_reports()

        reports = list(service.recent_reports)
        self.assertEqual(len(reports), 2)
        self.assertEqual(reports[0]["report_id"], 11)
        self.assertEqual(reports[1]["report_id"], 12)
        self.assertEqual(reports[0]["summary"], "older")
        self.assertEqual(reports[1]["summary"], "latest")


if __name__ == "__main__":
    unittest.main()
