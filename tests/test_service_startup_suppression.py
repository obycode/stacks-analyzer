import unittest
from unittest.mock import patch

from stacks_analyzer.config import ServiceConfig
from stacks_analyzer.detector import ProposalState
from stacks_analyzer.service import MonitoringService


class TestServiceStartupSuppression(unittest.TestCase):
    def test_journal_mode_starts_suppressed_and_rebases_on_first_live_line(self) -> None:
        service = MonitoringService(ServiceConfig(mode="journalctl"))
        self.assertTrue(service.suppress_notifications)
        self.assertTrue(service.detector.suppress_alerts)

        service.detector.last_node_tip_ts = 100.0
        service.detector.last_signer_proposal_ts = 120.0
        service.detector.last_mempool_stop_reason = "NoMoreCandidates"
        service.detector.last_mempool_ready_txs = 0
        service.detector.last_mempool_ready_ts = 80.0
        service.detector.proposals["open"] = ProposalState(start_ts=50.0)
        service.detector.proposals["closed"] = ProposalState(
            start_ts=55.0, threshold_ts=56.0
        )
        service.detector.active_stalls.add("node-stall")

        service._process_line("node", "__meta__prefetch_end__")
        self.assertFalse(service.awaiting_first_live_after_prefetch)

        service._process_line("signer", "__meta__prefetch_end__")
        self.assertTrue(service.awaiting_first_live_after_prefetch)
        self.assertTrue(service.suppress_notifications)

        with patch.object(service, "_state_now", return_value=1000.0):
            service._process_line("node", "live log line")

        self.assertFalse(service.awaiting_first_live_after_prefetch)
        self.assertFalse(service.suppress_notifications)
        self.assertFalse(service.detector.suppress_alerts)
        self.assertEqual(service.detector.last_node_tip_ts, 1000.0)
        self.assertEqual(service.detector.last_signer_proposal_ts, 1000.0)
        self.assertEqual(service.detector.last_mempool_ready_ts, 1000.0)
        self.assertEqual(service.detector.proposals["open"].start_ts, 1000.0)
        self.assertEqual(service.detector.proposals["closed"].start_ts, 55.0)
        self.assertEqual(len(service.detector.active_stalls), 0)


if __name__ == "__main__":
    unittest.main()
