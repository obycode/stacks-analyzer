import unittest
from unittest.mock import patch

from stacks_analyzer.config import ServiceConfig
from stacks_analyzer.service import MonitoringService


class TestServiceClock(unittest.TestCase):
    def test_replay_clock_uses_event_time_baseline(self) -> None:
        service = MonitoringService(
            ServiceConfig(mode="files", from_beginning=True, run_once=False)
        )
        service.replay_event_base_ts = 1000.0
        service.replay_wall_base_ts = 2000.0
        service.latest_event_ts = 1010.0

        with patch("stacks_analyzer.service.time.time", return_value=2010.0):
            self.assertEqual(service._state_now(), 1010.0)

        with patch("stacks_analyzer.service.time.time", return_value=2035.0):
            self.assertEqual(service._state_now(), 1035.0)

    def test_replay_clock_uses_slowest_source_progress(self) -> None:
        service = MonitoringService(
            ServiceConfig(
                mode="files",
                from_beginning=True,
                run_once=False,
                node_log_path="sample_logs/node.log",
                signer_log_path="sample_logs/signer.log",
            )
        )
        service.replay_event_base_ts = 1000.0
        service.replay_wall_base_ts = 2000.0
        service.latest_event_ts = 1300.0
        service.latest_event_ts_by_source["node"] = 1300.0
        service.latest_event_ts_by_source["signer"] = 1100.0

        with patch("stacks_analyzer.service.time.time", return_value=2050.0):
            # replay_now=1050, slowest source=1100 -> choose 1100, not 1300
            self.assertEqual(service._state_now(), 1100.0)


if __name__ == "__main__":
    unittest.main()
