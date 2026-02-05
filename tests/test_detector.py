import unittest

from stacks_analyzer.detector import Detector, DetectorConfig
from stacks_analyzer.events import LogParser, ParsedEvent


class TestDetector(unittest.TestCase):
    def test_stall_alerts(self) -> None:
        detector = Detector(
            DetectorConfig(
                node_stall_seconds=10,
                signer_stall_seconds=10,
                alert_cooldown_seconds=0,
                report_interval_seconds=99999,
            )
        )
        detector.last_node_tip_ts = 100.0
        detector.last_signer_proposal_ts = 100.0

        alerts, _ = detector.tick(now=120.0)
        keys = {alert.key for alert in alerts}
        self.assertIn("node-stall", keys)
        self.assertIn("signer-stall", keys)

    def test_sample_logs_build_report(self) -> None:
        parser = LogParser()
        detector = Detector(
            DetectorConfig(
                report_interval_seconds=1,
                alert_cooldown_seconds=0,
                large_signer_min_samples=2,
                large_signer_window=5,
            )
        )

        with open("sample_logs/node.log", "r", encoding="utf-8") as node:
            for line in node:
                detector.process_line("node")
                for event in parser.parse_line("node", line):
                    detector.process_event(event)

        with open("sample_logs/signer.log", "r", encoding="utf-8") as signer:
            for line in signer:
                detector.process_line("signer")
                for event in parser.parse_line("signer", line):
                    detector.process_event(event)

        alerts, report = detector.tick(now=2_000_000_000.0)
        _ = alerts
        self.assertIsNotNone(report)
        self.assertIn("lines(node=", report)
        self.assertGreater(detector.completed_proposals, 0)

    def test_stale_chunks_do_not_alert(self) -> None:
        detector = Detector(
            DetectorConfig(
                stale_chunk_window_seconds=60,
                stale_chunk_threshold=1,
                alert_cooldown_seconds=0,
                report_interval_seconds=99999,
            )
        )
        detector.process_event(
            ParsedEvent(source="node", kind="node_stale_chunk", ts=100.0, fields={})
        )
        alerts, _ = detector.tick(now=101.0)
        keys = {alert.key for alert in alerts}
        self.assertNotIn("node-stale-chunk-rate", keys)

    def test_pushed_without_threshold_does_not_alert(self) -> None:
        detector = Detector(
            DetectorConfig(
                proposal_timeout_seconds=99999,
                alert_cooldown_seconds=0,
                report_interval_seconds=99999,
            )
        )
        signature_hash = "abc123"
        detector.process_event(
            ParsedEvent(
                source="signer",
                kind="signer_block_proposal",
                ts=100.0,
                fields={"signer_signature_hash": signature_hash, "block_height": 1},
            )
        )
        detector.process_event(
            ParsedEvent(
                source="signer",
                kind="signer_block_acceptance",
                ts=101.0,
                fields={
                    "signer_signature_hash": signature_hash,
                    "signer_pubkey": "pub1",
                    "total_weight_approved": 100,
                    "total_weight": 1000,
                    "percent_approved": 10.0,
                },
            )
        )
        alerts = detector.process_event(
            ParsedEvent(
                source="signer",
                kind="signer_block_pushed",
                ts=102.0,
                fields={"signer_signature_hash": signature_hash, "block_height": 1},
            )
        )
        keys = {alert.key for alert in alerts}
        self.assertFalse(
            any(key.startswith("proposal-without-threshold-") for key in keys)
        )
        self.assertEqual(detector.completed_proposals, 1)

    def test_threshold_after_push_does_not_reopen_proposal(self) -> None:
        detector = Detector(
            DetectorConfig(
                proposal_timeout_seconds=10,
                alert_cooldown_seconds=0,
                report_interval_seconds=99999,
            )
        )
        signature_hash = "abc999"
        detector.process_event(
            ParsedEvent(
                source="signer",
                kind="signer_block_proposal",
                ts=100.0,
                fields={"signer_signature_hash": signature_hash, "block_height": 7},
            )
        )
        detector.process_event(
            ParsedEvent(
                source="signer",
                kind="signer_block_pushed",
                ts=101.0,
                fields={"signer_signature_hash": signature_hash, "block_height": 7},
            )
        )
        detector.process_event(
            ParsedEvent(
                source="signer",
                kind="signer_threshold_reached",
                ts=102.0,
                fields={
                    "signer_signature_hash": signature_hash,
                    "block_height": 7,
                    "percent_approved": 75.0,
                },
            )
        )
        self.assertNotIn(signature_hash, detector.proposals)
        alerts, _ = detector.tick(now=120.0)
        keys = {alert.key for alert in alerts}
        self.assertNotIn("proposal-timeout-%s" % signature_hash, keys)

    def test_new_block_event_closes_proposal_and_updates_heights(self) -> None:
        detector = Detector(
            DetectorConfig(
                proposal_timeout_seconds=10,
                alert_cooldown_seconds=0,
                report_interval_seconds=99999,
            )
        )
        signature_hash = "feedbeef"
        detector.process_event(
            ParsedEvent(
                source="signer",
                kind="signer_block_proposal",
                ts=100.0,
                fields={
                    "signer_signature_hash": signature_hash,
                    "block_height": 6319925,
                    "burn_height": 875000,
                },
            )
        )
        detector.process_event(
            ParsedEvent(
                source="signer",
                kind="signer_threshold_reached",
                ts=101.0,
                fields={
                    "signer_signature_hash": signature_hash,
                    "block_height": 6319925,
                    "percent_approved": 71.0,
                },
            )
        )
        detector.process_event(
            ParsedEvent(
                source="signer",
                kind="signer_new_block_event",
                ts=102.0,
                fields={
                    "signer_signature_hash": signature_hash,
                    "block_height": 6319925,
                    "block_id": "abcd",
                },
            )
        )

        self.assertNotIn(signature_hash, detector.proposals)
        self.assertEqual(detector.completed_proposals, 1)
        self.assertEqual(detector.completed_with_threshold, 1)

        snapshot = detector.snapshot(now=102.0)
        self.assertEqual(snapshot["current_stacks_block_height"], 6319925)
        self.assertEqual(snapshot["current_bitcoin_block_height"], 875000)

        alerts, _ = detector.tick(now=120.0)
        keys = {alert.key for alert in alerts}
        self.assertNotIn("proposal-timeout-%s" % signature_hash, keys)

    def test_signer_names_appear_in_alerts_and_snapshot(self) -> None:
        pubkey = "02abc"
        detector = Detector(
            DetectorConfig(
                large_signer_window=3,
                large_signer_min_participation=0.8,
                large_signer_min_samples=1,
                alert_cooldown_seconds=0,
                report_interval_seconds=99999,
            ),
            signer_names={pubkey: "Friendly Signer"},
        )
        detector.seen_signers.add(pubkey)
        detector.signer_weight_samples[pubkey].append(100)
        detector.total_weight_samples.append(1000)
        detector.signer_participation[pubkey].append(False)
        detector.signer_participation[pubkey].append(False)
        detector.signer_participation[pubkey].append(False)

        alerts, _ = detector.tick(now=200.0)
        self.assertTrue(any("Friendly Signer" in alert.message for alert in alerts))

        snapshot = detector.snapshot(now=200.0)
        signer_row = next(row for row in snapshot["signers"] if row["pubkey"] == pubkey)
        self.assertEqual(signer_row["name"], "Friendly Signer")
        self.assertAlmostEqual(signer_row["weight_percent_of_total"], 10.0)


if __name__ == "__main__":
    unittest.main()
