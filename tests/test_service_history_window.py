import os
import tempfile
import unittest

from stacks_analyzer.history import HistoryStore
from stacks_analyzer.service import MonitoringService


class TestServiceHistoryWindow(unittest.TestCase):
    def setUp(self) -> None:
        handle = tempfile.NamedTemporaryFile(delete=False)
        handle.close()
        self.db_path = handle.name
        self.store = HistoryStore(path=self.db_path, retention_hours=48)
        self.service = MonitoringService.__new__(MonitoringService)
        self.service.history_store = self.store
        self.service._state_now = lambda: 2000.0

    def tearDown(self) -> None:
        self.store.close()
        try:
            os.unlink(self.db_path)
        except OSError:
            pass

    def test_history_window_groups_anomalous_proposals(self) -> None:
        signature_hash = "a" * 64
        self.store.record_event(
            ts=1000.0,
            source="signer",
            kind="signer_block_proposal",
            data={"signer_signature_hash": signature_hash, "block_height": 123},
            line="proposal",
        )
        self.store.record_event(
            ts=1001.0,
            source="signer",
            kind="signer_block_rejection",
            data={
                "signer_signature_hash": signature_hash,
                "block_height": 123,
                "reject_reason": "NotLatestSortitionWinner",
            },
            line="reject",
        )
        self.store.record_event(
            ts=1002.0,
            source="signer",
            kind="signer_threshold_reached",
            data={"signer_signature_hash": signature_hash, "block_height": 123},
            line="threshold",
        )
        self.store.record_event(
            ts=1003.0,
            source="node",
            kind="node_consensus",
            data={"burn_height": 55, "stacks_block_height": 123, "consensus_hash": "b" * 40},
            line="consensus",
        )
        alert_id = self.store.record_alert(
            ts=1004.0,
            severity="warning",
            key="proposal-timeout",
            message="proposal anomaly",
        )
        report_id = self.store.create_report(
            ts=1004.0,
            severity="warning",
            alert_key="proposal-timeout",
            summary="report",
            data={"ok": True},
        )
        self.store.attach_report(alert_id, report_id)

        payload = self.service._history_window_api({"start": ["999"], "stop": ["1010"]})

        self.assertEqual(payload["summary"]["alerts"], 1)
        self.assertEqual(payload["summary"]["reports"], 1)
        self.assertEqual(payload["summary"]["burn_blocks"], 1)
        self.assertEqual(payload["summary"]["anomalous_proposals"], 1)
        self.assertEqual(payload["anomalous_proposals"][0]["signature_hash"], signature_hash)
        self.assertEqual(payload["anomalous_proposals"][0]["reject_count"], 1)
        self.assertEqual(
            payload["anomalous_proposals"][0]["top_reject_reason"],
            "NotLatestSortitionWinner",
        )

    def test_history_window_defaults_to_last_10_minutes(self) -> None:
        payload = self.service._history_window_api({})
        self.assertEqual(payload["stop_ts"], 2000.0)
        self.assertEqual(payload["start_ts"], 1400.0)
        self.assertEqual(payload["duration_seconds"], 600.0)


if __name__ == "__main__":
    unittest.main()
