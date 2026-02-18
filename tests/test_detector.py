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

    def test_mempool_empty_alert_after_90s(self) -> None:
        detector = Detector(
            DetectorConfig(
                alert_cooldown_seconds=0,
                report_interval_seconds=99999,
            )
        )
        detector.last_mempool_stop_reason = "NoMoreCandidates"
        detector.last_mempool_ready_txs = 0
        detector.last_mempool_ready_ts = 100.0

        alerts, _ = detector.tick(now=190.0)
        self.assertFalse(any(alert.key == "mempool-empty" for alert in alerts))

        alerts, _ = detector.tick(now=191.0)
        self.assertTrue(any(alert.key == "mempool-empty" for alert in alerts))

    def test_avg_block_interval_from_node_tips(self) -> None:
        detector = Detector(
            DetectorConfig(
                alert_cooldown_seconds=0,
                report_interval_seconds=99999,
            )
        )
        detector.process_event(
            ParsedEvent(source="node", kind="node_tip_advanced", ts=100.0, fields={})
        )
        detector.process_event(
            ParsedEvent(source="node", kind="node_tip_advanced", ts=110.0, fields={})
        )
        detector.process_event(
            ParsedEvent(source="node", kind="node_tip_advanced", ts=125.0, fields={})
        )

        snapshot = detector.snapshot(now=126.0)
        self.assertAlmostEqual(snapshot["avg_block_interval_seconds"], 12.5)
        self.assertEqual(snapshot["avg_block_interval_samples"], 2)
        self.assertAlmostEqual(snapshot["last_block_interval_seconds"], 15.0)

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

    def test_weight_sample_requires_signature_weight(self) -> None:
        detector = Detector(
            DetectorConfig(
                alert_cooldown_seconds=0,
                report_interval_seconds=99999,
            )
        )
        detector.process_event(
            ParsedEvent(
                source="signer",
                kind="signer_block_acceptance",
                ts=100.0,
                fields={
                    "signer_signature_hash": "weightjump",
                    "signer_pubkey": "pub1",
                    "total_weight_approved": 600,
                    "total_weight": 1000,
                    "percent_approved": 60.0,
                },
            )
        )
        self.assertEqual(len(detector.signer_weight_samples.get("pub1", [])), 0)

    def test_signature_weight_used_for_samples(self) -> None:
        detector = Detector(
            DetectorConfig(
                alert_cooldown_seconds=0,
                report_interval_seconds=99999,
            )
        )
        detector.process_event(
            ParsedEvent(
                source="signer",
                kind="signer_block_acceptance",
                ts=100.0,
                fields={
                    "signer_signature_hash": "sig1",
                    "signer_pubkey": "pub1",
                    "signature_weight": 42,
                    "total_weight_approved": 200,
                    "total_weight": 1000,
                },
            )
        )

    def test_snapshot_includes_latest_execution_cost_percentages(self) -> None:
        detector = Detector(
            DetectorConfig(
                alert_cooldown_seconds=0,
                report_interval_seconds=99999,
            )
        )
        detector.process_event(
            ParsedEvent(
                source="node",
                kind="node_mined_nakamoto_block",
                ts=99.0,
                fields={
                    "block_height": 6398579,
                    "tx_count": 9,
                    "percent_full": 99,
                    "consensus_hash": "ignored",
                    "runtime": 999999,
                    "write_len": 999,
                    "write_cnt": 999,
                    "read_len": 999999,
                    "read_cnt": 999,
                },
            )
        )
        self.assertIsNone(detector.snapshot(now=99.5)["latest_execution_costs"])

        detector.process_event(
            ParsedEvent(
                source="node",
                kind="node_block_proposal",
                ts=100.0,
                fields={
                    "block_header_hash": "abc123",
                    "block_height": 6398580,
                    "tx_count": 4,
                    "runtime": 312966534,
                    "write_len": 309422,
                    "write_cnt": 2876,
                    "read_len": 83413180,
                    "read_cnt": 219,
                },
            )
        )
        self.assertIsNone(detector.snapshot(now=100.5)["latest_execution_costs"])
        detector.process_event(
            ParsedEvent(
                source="node",
                kind="node_tip_advanced",
                ts=101.0,
                fields={
                    "block_header_hash": "abc123",
                    "consensus_hash": "6cd01af5",
                },
            )
        )

        snapshot = detector.snapshot(now=110.0)
        self.assertEqual(snapshot["latest_execution_cost_block_height"], 6398580)
        self.assertEqual(snapshot["latest_execution_cost_tx_count"], 4)
        self.assertIsNone(snapshot["latest_execution_cost_percent_full"])
        self.assertAlmostEqual(
            snapshot["latest_execution_costs_percent"]["runtime"], 6.25933068, places=4
        )
        self.assertAlmostEqual(
            snapshot["latest_execution_costs_percent"]["read_len"], 83.41318, places=4
        )
        self.assertAlmostEqual(snapshot["latest_execution_cost_age_seconds"], 9.0)
        self.assertEqual(
            snapshot["recent_execution_costs"][0]["consensus_hash"], "6cd01af5"
        )

    def test_boundary_timeout_emits_warning(self) -> None:
        detector = Detector(
            DetectorConfig(
                proposal_timeout_seconds=5,
                burn_block_boundary_window_seconds=15,
                alert_cooldown_seconds=0,
                report_interval_seconds=99999,
            )
        )
        signature_hash = "boundary123"
        detector.process_event(
            ParsedEvent(
                source="node",
                kind="node_consensus",
                ts=100.0,
                fields={"burn_height": 935301, "consensus_hash": "abc123"},
            )
        )
        detector.process_event(
            ParsedEvent(
                source="signer",
                kind="signer_block_proposal",
                ts=105.0,
                fields={
                    "signer_signature_hash": signature_hash,
                    "block_height": 6376073,
                    "burn_height": 935301,
                },
            )
        )
        detector.process_event(
            ParsedEvent(
                source="signer",
                kind="signer_block_rejection",
                ts=106.0,
                fields={
                    "signer_signature_hash": signature_hash,
                    "signer_pubkey": "pub1",
                    "percent_rejected": 29.0,
                    "reject_reason": "SortitionViewMismatch",
                },
            )
        )
        alerts, _ = detector.tick(now=112.0)
        keys = {alert.key for alert in alerts}
        self.assertIn("proposal-timeout-boundary-%s" % signature_hash, keys)
        self.assertNotIn("proposal-timeout-%s" % signature_hash, keys)

    def test_accept_then_reject_emits_warning(self) -> None:
        detector = Detector(
            DetectorConfig(
                alert_cooldown_seconds=0,
                report_interval_seconds=99999,
            )
        )
        signature_hash = "flip123"
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
                    "signature_weight": 10,
                },
            )
        )
        alerts = detector.process_event(
            ParsedEvent(
                source="signer",
                kind="signer_block_rejection",
                ts=102.0,
                fields={
                    "signer_signature_hash": signature_hash,
                    "signer_pubkey": "pub1",
                    "percent_rejected": 1.0,
                    "reject_reason": "SortitionViewMismatch",
                },
            )
        )
        keys = {alert.key for alert in alerts}
        self.assertIn(
            "signer-accept-then-reject-%s-%s" % (signature_hash, "pub1"[:10]),
            keys,
        )
        self.assertEqual(detector.signer_weight_samples["pub1"][-1], 10)

        detector.process_event(
            ParsedEvent(
                source="signer",
                kind="signer_block_rejection",
                ts=101.0,
                fields={
                    "signer_signature_hash": "sig2",
                    "signer_pubkey": "pub2",
                    "signature_weight": 55,
                    "total_weight": 1000,
                    "percent_rejected": 5.0,
                },
            )
        )
        self.assertEqual(detector.signer_weight_samples["pub2"][-1], 55)

    def test_sortition_parent_burn_mismatch_warns(self) -> None:
        detector = Detector(
            DetectorConfig(
                alert_cooldown_seconds=0,
                report_interval_seconds=99999,
            )
        )
        signature_hash = "abcd1234"
        detector.process_event(
            ParsedEvent(
                source="signer",
                kind="signer_block_proposal",
                ts=100.0,
                fields={
                    "signer_signature_hash": signature_hash,
                    "burn_height": 100,
                },
            )
        )
        detector.process_event(
            ParsedEvent(
                source="signer",
                kind="signer_block_pushed",
                ts=101.0,
                fields={
                    "signer_signature_hash": signature_hash,
                    "block_height": 1,
                },
            )
        )

        detector.process_event(
            ParsedEvent(
                source="node",
                kind="node_leader_block_commit",
                ts=110.0,
                fields={
                    "burn_height": 105,
                    "commit_txid": "tx1",
                    "apparent_sender": "bc1qqq",
                    "stacks_block_hash": "abcd",
                    "parent_burn_block": 99,
                },
            )
        )

        alerts = detector.process_event(
            ParsedEvent(
                source="node",
                kind="node_sortition_winner_selected",
                ts=111.0,
                fields={
                    "burn_height": 105,
                    "winner_txid": "tx1",
                    "winning_stacks_block_hash": "abcd",
                },
            )
        )
        keys = {alert.key for alert in alerts}
        self.assertIn("sortition-parent-burn-mismatch-105", keys)

    def test_burnchain_reorg_emits_warning_alert(self) -> None:
        detector = Detector(
            DetectorConfig(
                alert_cooldown_seconds=0,
                report_interval_seconds=99999,
            )
        )
        alerts = detector.process_event(
            ParsedEvent(
                source="node",
                kind="node_burnchain_reorg",
                ts=100.0,
                fields={"common_ancestor_height": 935496},
            )
        )
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].key, "burnchain-reorg-935496")
        self.assertEqual(alerts[0].severity, "warning")
        self.assertIn("highest common ancestor at height 935496", alerts[0].message)

    def test_sortition_winner_rejected_emits_info_alert(self) -> None:
        detector = Detector(
            DetectorConfig(
                alert_cooldown_seconds=0,
                report_interval_seconds=99999,
            )
        )
        alerts = detector.process_event(
            ParsedEvent(
                source="node",
                kind="node_sortition_winner_rejected",
                ts=100.0,
                fields={
                    "burn_height": 935500,
                    "rejection_reason": "Miner did not mine often enough to win",
                    "rejected_txid": "abc123",
                },
            )
        )
        keys = {alert.key for alert in alerts}
        self.assertIn("sortition-winner-rejected-935500", keys)
        message = next(
            alert.message for alert in alerts if alert.key == "sortition-winner-rejected-935500"
        )
        self.assertIn("Miner did not mine often enough to win", message)

    def test_node_block_proposal_rejected_emits_warning_alert(self) -> None:
        detector = Detector(
            DetectorConfig(
                alert_cooldown_seconds=0,
                report_interval_seconds=99999,
            )
        )
        alerts = detector.process_event(
            ParsedEvent(
                source="node",
                kind="node_block_proposal_rejected",
                ts=100.0,
                fields={
                    "reason": "InvalidParentBlock",
                    "signer_signature_hash": "f98fab91d65e",
                    "block_height": 6365169,
                    "burn_height": 935297,
                },
            )
        )
        self.assertEqual(len(alerts), 1)
        self.assertTrue(alerts[0].key.startswith("node-block-proposal-rejected-"))
        self.assertEqual(alerts[0].severity, "warning")
        self.assertIn("InvalidParentBlock", alerts[0].message)

    def test_node_signers_rejected_emits_warning_alert(self) -> None:
        detector = Detector(
            DetectorConfig(
                alert_cooldown_seconds=0,
                report_interval_seconds=99999,
            )
        )
        alerts = detector.process_event(
            ParsedEvent(
                source="node",
                kind="node_signers_rejected",
                ts=100.0,
                fields={
                    "pause_ms": 500,
                    "signer_signature_hash": "f98fab91d65e",
                    "block_height": 6365169,
                    "consensus_hash": "abcde",
                },
            )
        )
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].key, "miner-signers-rejected-f98fab91d65e")
        self.assertEqual(alerts[0].severity, "warning")
        self.assertIn("retry_pause_ms=500", alerts[0].message)

    def test_signer_validation_slow_emits_warning_alert(self) -> None:
        detector = Detector(
            DetectorConfig(
                alert_cooldown_seconds=0,
                report_interval_seconds=99999,
            )
        )
        alerts = detector.process_event(
            ParsedEvent(
                source="signer",
                kind="signer_block_validate_ok",
                ts=100.0,
                fields={
                    "signer_signature_hash": "f98fab91d65e",
                    "validation_time_ms": 5400,
                },
            )
        )
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].key, "signer-validation-slow-f98fab91d65e")
        self.assertEqual(alerts[0].severity, "warning")
        self.assertIn("5400ms", alerts[0].message)

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

    def test_confirmed_block_history_uses_node_tip_and_dedupes_signer_push(self) -> None:
        detector = Detector(
            DetectorConfig(
                alert_cooldown_seconds=0,
                report_interval_seconds=99999,
            )
        )
        detector.process_event(
            ParsedEvent(
                source="node",
                kind="node_tip_advanced",
                ts=100.0,
                fields={
                    "consensus_hash": "aa11",
                    "block_header_hash": "bb22",
                },
            )
        )
        detector.process_event(
            ParsedEvent(
                source="signer",
                kind="signer_new_block_event",
                ts=101.0,
                fields={
                    "block_id": "cc33",
                    "block_height": 6319926,
                    "consensus_hash": "aa11",
                    "signer_signature_hash": "sig1",
                },
            )
        )
        detector.process_event(
            ParsedEvent(
                source="signer",
                kind="signer_block_pushed",
                ts=102.0,
                fields={
                    "block_id": "cc33",
                    "block_height": 6319926,
                    "signer_signature_hash": "sig1",
                },
            )
        )

        snapshot = detector.snapshot(now=103.0)
        recent_confirmed = snapshot["recent_confirmed_blocks"]
        self.assertEqual(len(recent_confirmed), 2)
        self.assertEqual(recent_confirmed[0]["source"], "node_tip_advanced")
        self.assertEqual(recent_confirmed[0]["consensus_hash"], "aa11")
        self.assertEqual(recent_confirmed[1]["source"], "signer_new_block_event")
        self.assertEqual(recent_confirmed[1]["block_id"], "cc33")
        self.assertEqual(
            snapshot["recent_confirmed_blocks_capacity"], detector.confirmed_block_history.maxlen
        )

    def test_signer_block_events_fallback_to_current_consensus_for_history(self) -> None:
        detector = Detector(
            DetectorConfig(
                alert_cooldown_seconds=0,
                report_interval_seconds=99999,
            )
        )
        detector.process_event(
            ParsedEvent(
                source="node",
                kind="node_tip_advanced",
                ts=100.0,
                fields={
                    "consensus_hash": "aa11",
                    "block_header_hash": "bb22",
                },
            )
        )
        detector.process_event(
            ParsedEvent(
                source="signer",
                kind="signer_new_block_event",
                ts=101.0,
                fields={
                    "block_id": "cc33",
                    "block_height": 6319926,
                    "signer_signature_hash": "sig1",
                },
            )
        )

        snapshot = detector.snapshot(now=102.0)
        recent_confirmed = snapshot["recent_confirmed_blocks"]
        self.assertEqual(len(recent_confirmed), 2)
        self.assertEqual(recent_confirmed[1]["source"], "signer_new_block_event")
        self.assertEqual(recent_confirmed[1]["consensus_hash"], "aa11")

    def test_node_nakamoto_block_records_confirmed_history(self) -> None:
        detector = Detector(
            DetectorConfig(
                alert_cooldown_seconds=0,
                report_interval_seconds=99999,
            )
        )
        detector.process_event(
            ParsedEvent(
                source="node",
                kind="node_nakamoto_block",
                ts=100.0,
                fields={
                    "consensus_hash": "aa11",
                    "block_header_hash": "bb22",
                    "block_id": "cc33",
                },
            )
        )
        snapshot = detector.snapshot(now=101.0)
        recent_confirmed = snapshot["recent_confirmed_blocks"]
        self.assertEqual(len(recent_confirmed), 1)
        self.assertEqual(recent_confirmed[0]["source"], "node_nakamoto_block")
        self.assertEqual(recent_confirmed[0]["consensus_hash"], "aa11")
        self.assertEqual(recent_confirmed[0]["block_header_hash"], "bb22")

    def test_confirmed_block_fallback_key_uses_line_hash_when_ids_missing(self) -> None:
        detector = Detector(
            DetectorConfig(
                alert_cooldown_seconds=0,
                report_interval_seconds=99999,
            )
        )
        detector.process_event(
            ParsedEvent(
                source="node",
                kind="node_tip_advanced",
                ts=100.0,
                fields={},
                line="Advanced to new tip aaa/bbb",
            )
        )
        detector.process_event(
            ParsedEvent(
                source="node",
                kind="node_tip_advanced",
                ts=100.0,
                fields={},
                line="Advanced to new tip ccc/ddd",
            )
        )

        snapshot = detector.snapshot(now=101.0)
        recent_confirmed = snapshot["recent_confirmed_blocks"]
        self.assertEqual(len(recent_confirmed), 2)

    def test_tenure_block_counts_increment_on_node_tips(self) -> None:
        detector = Detector(
            DetectorConfig(
                alert_cooldown_seconds=0,
                report_interval_seconds=99999,
            )
        )
        detector.process_event(
            ParsedEvent(
                source="node",
                kind="node_tip_advanced",
                ts=100.0,
                fields={"consensus_hash": "aa11"},
            )
        )
        detector.process_event(
            ParsedEvent(
                source="node",
                kind="node_tip_advanced",
                ts=101.0,
                fields={"consensus_hash": "aa11"},
            )
        )
        detector.process_event(
            ParsedEvent(
                source="node",
                kind="node_tip_advanced",
                ts=102.0,
                fields={"consensus_hash": "bb22"},
            )
        )

        snapshot = detector.snapshot(now=103.0)
        counts = snapshot["recent_tenure_block_counts"]
        self.assertEqual(len(counts), 2)
        self.assertEqual(counts[0]["consensus_hash"], "aa11")
        self.assertEqual(counts[0]["block_count"], 2)
        self.assertEqual(counts[1]["consensus_hash"], "bb22")
        self.assertEqual(counts[1]["block_count"], 1)

    def test_tenure_block_counts_accumulate_confirmed_txs_fees_and_types(self) -> None:
        detector = Detector(
            DetectorConfig(
                alert_cooldown_seconds=0,
                report_interval_seconds=99999,
            )
        )
        block_header_hash = "aa" * 32
        detector.process_event(
            ParsedEvent(
                source="node",
                kind="node_block_proposal",
                ts=100.0,
                fields={
                    "is_validation_request": True,
                    "block_header_hash": block_header_hash,
                    "tx_count": 2,
                },
            )
        )
        detector.process_event(
            ParsedEvent(
                source="node",
                kind="node_include_tx",
                ts=100.1,
                fields={
                    "txid": "tx1",
                    "payload": "TokenTransfer",
                    "from_block_proposal_thread": True,
                },
            )
        )
        detector.process_event(
            ParsedEvent(
                source="node",
                kind="node_include_tx",
                ts=100.2,
                fields={
                    "txid": "tx2",
                    "payload": "ContractCall",
                    "from_block_proposal_thread": True,
                },
            )
        )
        detector.process_event(
            ParsedEvent(
                source="node",
                kind="node_block_proposal",
                ts=100.3,
                fields={
                    "is_validated": True,
                    "block_header_hash": block_header_hash,
                    "tx_count": 2,
                    "tx_fees_microstacks": 6580,
                    "runtime": 100,
                    "write_len": 100,
                    "write_cnt": 1,
                    "read_len": 100,
                    "read_cnt": 1,
                },
            )
        )
        detector.process_event(
            ParsedEvent(
                source="node",
                kind="node_tip_advanced",
                ts=101.0,
                fields={
                    "consensus_hash": "cc11",
                    "block_header_hash": block_header_hash,
                },
            )
        )

        snapshot = detector.snapshot(now=102.0)
        counts = snapshot["recent_tenure_block_counts"]
        self.assertEqual(len(counts), 1)
        self.assertEqual(counts[0]["block_count"], 1)
        self.assertEqual(counts[0]["tx_count_total"], 2)
        self.assertEqual(counts[0]["fee_microstx_total"], 6580)
        type_counts = counts[0]["tx_type_counts"]
        self.assertEqual(type_counts["transfer"], 1)
        self.assertEqual(type_counts["contract_call"], 1)
        self.assertEqual(type_counts["contract_deploy"], 0)

    def test_tenure_block_counts_backfill_metrics_when_validation_arrives_after_tip(self) -> None:
        detector = Detector(
            DetectorConfig(
                alert_cooldown_seconds=0,
                report_interval_seconds=99999,
            )
        )
        block_header_hash = "bb" * 32
        detector.process_event(
            ParsedEvent(
                source="node",
                kind="node_tip_advanced",
                ts=101.0,
                fields={
                    "consensus_hash": "late11",
                    "block_header_hash": block_header_hash,
                },
            )
        )
        detector.process_event(
            ParsedEvent(
                source="node",
                kind="node_block_proposal",
                ts=102.0,
                fields={
                    "is_validated": True,
                    "block_header_hash": block_header_hash,
                    "tx_count": 3,
                    "tx_fees_microstacks": 7777,
                    "runtime": 100,
                    "write_len": 100,
                    "write_cnt": 1,
                    "read_len": 100,
                    "read_cnt": 1,
                    "tx_type_counts": {
                        "transfer": 2,
                        "contract_call": 1,
                    },
                },
            )
        )

        snapshot = detector.snapshot(now=103.0)
        counts = snapshot["recent_tenure_block_counts"]
        self.assertEqual(len(counts), 1)
        self.assertEqual(counts[0]["consensus_hash"], "late11")
        self.assertEqual(counts[0]["block_count"], 1)
        self.assertEqual(counts[0]["tx_count_total"], 3)
        self.assertEqual(counts[0]["fee_microstx_total"], 7777)
        self.assertEqual(snapshot["latest_execution_cost_block_height"], None)
        self.assertEqual(snapshot["latest_execution_cost_tx_count"], 3)
        self.assertEqual(snapshot["recent_execution_costs"][0]["consensus_hash"], "late11")

    def test_tenure_block_counts_keeps_last_eight(self) -> None:
        detector = Detector(
            DetectorConfig(
                alert_cooldown_seconds=0,
                report_interval_seconds=99999,
            )
        )
        for idx in range(10):
            detector.process_event(
                ParsedEvent(
                    source="node",
                    kind="node_tip_advanced",
                    ts=100.0 + idx,
                    fields={"consensus_hash": "hash%02d" % idx},
                )
            )

        snapshot = detector.snapshot(now=200.0)
        counts = snapshot["recent_tenure_block_counts"]
        self.assertEqual(len(counts), 8)
        self.assertEqual(counts[0]["consensus_hash"], "hash02")
        self.assertEqual(counts[-1]["consensus_hash"], "hash09")

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

    def test_snapshot_tracks_miner_consensus_and_tenure_extend(self) -> None:
        detector = Detector(
            DetectorConfig(
                alert_cooldown_seconds=0,
                report_interval_seconds=99999,
            )
        )
        detector.process_event(
            ParsedEvent(
                source="node",
                kind="node_winning_block_commit",
                ts=100.0,
                fields={
                    "burn_height": 934988,
                    "apparent_sender": "bc1qmineraddress",
                    "miner_pubkey": "0277minerpubkey",
                    "winning_stacks_block_hash": "aa" * 32,
                },
            )
        )
        detector.process_event(
            ParsedEvent(
                source="node",
                kind="node_tenure_notify",
                ts=101.0,
                fields={
                    "consensus_hash": "bb" * 20,
                    "burn_height": 934988,
                    "winning_stacks_block_hash": "aa" * 32,
                },
            )
        )
        detector.process_event(
            ParsedEvent(
                source="node",
                kind="node_tenure_change",
                ts=102.0,
                fields={
                    "tenure_change_kind": "ExtendAll",
                    "txid": "cc" * 32,
                    "origin": "SPVYF6M3FD0738FWDGDMJ84EFMGM38JS0N7DE42K",
                },
            )
        )

        snapshot = detector.snapshot(now=110.0)
        self.assertEqual(snapshot["current_bitcoin_block_height"], 934988)
        self.assertEqual(snapshot["current_consensus_hash"], "bb" * 20)
        self.assertEqual(snapshot["current_consensus_burn_height"], 934988)
        self.assertEqual(snapshot["current_miner_apparent_sender"], "bc1qmineraddress")
        self.assertEqual(snapshot["current_miner_pubkey"], "0277minerpubkey")
        self.assertEqual(snapshot["last_tenure_extend_kind"], "ExtendAll")
        self.assertEqual(snapshot["last_tenure_extend_txid"], "cc" * 32)
        self.assertEqual(
            snapshot["last_tenure_extend_origin"],
            "SPVYF6M3FD0738FWDGDMJ84EFMGM38JS0N7DE42K",
        )
        self.assertEqual(snapshot["last_tenure_extend_age_seconds"], 8.0)

        detector.process_event(
            ParsedEvent(
                source="node",
                kind="node_tenure_notify",
                ts=111.0,
                fields={
                    "consensus_hash": "dd" * 20,
                    "burn_height": 934989,
                    "winning_stacks_block_hash": "0" * 64,
                },
            )
        )
        snapshot = detector.snapshot(now=112.0)
        self.assertEqual(snapshot["current_miner_winning_stacks_block_hash"], "0" * 64)
        self.assertEqual(snapshot["current_consensus_burn_height"], 934989)
        self.assertEqual(snapshot["current_miner_apparent_sender"], "bc1qmineraddress")
        self.assertEqual(snapshot["current_miner_pubkey"], "0277minerpubkey")

    def test_tenure_change_history_includes_non_extend_changes(self) -> None:
        detector = Detector(
            DetectorConfig(
                alert_cooldown_seconds=0,
                report_interval_seconds=99999,
            )
        )
        detector.process_event(
            ParsedEvent(
                source="node",
                kind="node_tenure_change",
                ts=100.0,
                fields={
                    "tenure_change_kind": "BlockFound",
                    "txid": "aa" * 32,
                    "block_height": 123,
                    "burn_height": 456,
                },
            )
        )
        snapshot = detector.snapshot(now=101.0)
        self.assertEqual(len(snapshot["tenure_change_history"]), 1)
        self.assertEqual(snapshot["tenure_change_history"][0]["kind"], "BlockFound")
        self.assertEqual(len(snapshot["recent_tenure_extends"]), 0)

    def test_sortition_rounds_and_active_miner_snapshot(self) -> None:
        detector = Detector(
            DetectorConfig(
                alert_cooldown_seconds=0,
                report_interval_seconds=99999,
            )
        )
        detector.process_event(
            ParsedEvent(
                source="node",
                kind="node_sortition_winner_selected",
                ts=100.0,
                fields={
                    "burn_height": 934988,
                    "winner_txid": "aa" * 32,
                    "winning_stacks_block_hash": "bb" * 32,
                },
            )
        )
        detector.process_event(
            ParsedEvent(
                source="node",
                kind="node_leader_block_commit",
                ts=101.0,
                fields={
                    "burn_height": 934988,
                    "commit_txid": "11" * 32,
                    "sortition_position": 100,
                    "apparent_sender": "bc1qminer1",
                    "stacks_block_hash": "bb" * 32,
                    "parent_burn_block": 934987,
                    "burn_fee": 80_000,
                },
            )
        )
        detector.process_event(
            ParsedEvent(
                source="node",
                kind="node_leader_block_commit",
                ts=101.1,
                fields={
                    "burn_height": 934988,
                    "commit_txid": "aa" * 32,
                    "sortition_position": 200,
                    "apparent_sender": "bc1qwinner",
                    "stacks_block_hash": "bb" * 32,
                    "parent_burn_block": 934987,
                    "burn_fee": 90_000,
                },
            )
        )
        detector.process_event(
            ParsedEvent(
                source="signer",
                kind="signer_state_machine_update",
                ts=102.0,
                fields={
                    "burn_block": "cc" * 20,
                    "burn_height": 934988,
                    "current_miner_pkh": "pkh123",
                    "tenure_id": "cc" * 20,
                    "parent_tenure_id": "dd" * 20,
                    "parent_tenure_last_block": "ee" * 32,
                    "parent_tenure_last_block_height": 6319944,
                },
            )
        )

        snapshot = detector.snapshot(now=110.0)
        self.assertEqual(snapshot["current_miner_apparent_sender"], "bc1qwinner")
        self.assertEqual(
            snapshot["last_successful_sortition"]["winner_apparent_sender"],
            "bc1qwinner",
        )
        self.assertEqual(
            snapshot["last_successful_sortition"]["winner_stacks_block_height"], None
        )
        self.assertEqual(len(snapshot["last_successful_sortition_commits"]), 2)
        self.assertEqual(len(snapshot["miners_since_last_successful_sortition"]), 0)
        self.assertEqual(len(snapshot["recent_sortition_details"]), 1)
        self.assertEqual(snapshot["recent_sortition_details"][0]["burn_height"], 934988)
        self.assertEqual(len(snapshot["recent_sortition_details"][0]["commits"]), 2)
        self.assertEqual(snapshot["recent_sortition_details"][0]["total_burn_fee"], 170000)
        self.assertEqual(
            snapshot["recent_sortition_details"][0]["commits"][0]["burn_fee"], 80000
        )
        self.assertEqual(
            snapshot["recent_sortition_details"][0]["commits"][1]["burn_fee"], 90000
        )
        self.assertEqual(snapshot["active_miner"]["current_miner_pkh"], "pkh123")
        self.assertEqual(snapshot["current_consensus_burn_height"], 934988)
        self.assertEqual(
            snapshot["active_miner"]["parent_tenure_last_block_height"], 6319944
        )

    def test_null_miner_round_keeps_last_successful_winner(self) -> None:
        detector = Detector(
            DetectorConfig(
                alert_cooldown_seconds=0,
                report_interval_seconds=99999,
            )
        )
        detector.process_event(
            ParsedEvent(
                source="node",
                kind="node_sortition_winner_selected",
                ts=100.0,
                fields={
                    "burn_height": 934982,
                    "winner_txid": "aa" * 32,
                    "winning_stacks_block_hash": "bb" * 32,
                },
            )
        )
        detector.process_event(
            ParsedEvent(
                source="node",
                kind="node_leader_block_commit",
                ts=101.0,
                fields={
                    "burn_height": 934982,
                    "commit_txid": "aa" * 32,
                    "sortition_position": 10,
                    "apparent_sender": "bc1qpreviouswinner",
                    "stacks_block_hash": "bb" * 32,
                    "parent_burn_block": 934981,
                },
            )
        )
        detector.process_event(
            ParsedEvent(
                source="node",
                kind="node_sortition_winner_rejected",
                ts=102.0,
                fields={
                    "burn_height": 934983,
                    "rejected_txid": "cc" * 32,
                    "rejected_stacks_block_hash": "dd" * 32,
                    "rejection_reason": (
                        "Null miner defeats block winner due to insufficient commit carryover"
                    ),
                },
            )
        )
        detector.process_event(
            ParsedEvent(
                source="node",
                kind="node_tenure_notify",
                ts=103.0,
                fields={
                    "consensus_hash": "ee" * 20,
                    "burn_height": 934983,
                    "winning_stacks_block_hash": "0" * 64,
                },
            )
        )

        snapshot = detector.snapshot(now=110.0)
        self.assertEqual(snapshot["current_miner_apparent_sender"], "bc1qpreviouswinner")
        self.assertEqual(snapshot["last_successful_sortition"]["burn_height"], 934982)
        self.assertEqual(snapshot["latest_sortition"]["burn_height"], 934983)
        self.assertTrue(snapshot["latest_sortition"]["null_miner_won"])
        self.assertIn(
            "Null miner",
            str(snapshot["latest_sortition"]["null_miner_reason"]),
        )

    def test_recent_tenure_extends_tracks_last_five(self) -> None:
        detector = Detector(
            DetectorConfig(
                alert_cooldown_seconds=0,
                report_interval_seconds=99999,
            )
        )
        for index in range(6):
            detector.process_event(
                ParsedEvent(
                    source="node",
                    kind="node_tenure_change",
                    ts=100.0 + index,
                    fields={
                        "tenure_change_kind": "ExtendAll",
                        "txid": f"tx{index}",
                        "origin": "SPTEST",
                        "block_height": 6319900 + index,
                        "burn_height": 934980 + index,
                    },
                )
            )

        snapshot = detector.snapshot(now=200.0)
        recent = snapshot["recent_tenure_extends"]
        self.assertEqual(len(recent), 5)
        self.assertEqual(recent[0]["txid"], "tx5")
        self.assertEqual(recent[-1]["txid"], "tx1")
        self.assertEqual(recent[0]["block_height"], 6319905)
        self.assertEqual(recent[0]["burn_height"], 934985)

    def test_recent_proposals_include_open_and_closed(self) -> None:
        detector = Detector(
            DetectorConfig(
                proposal_timeout_seconds=99999,
                alert_cooldown_seconds=0,
                report_interval_seconds=99999,
            )
        )
        closed_hash = "closed123"
        open_hash = "open456"

        detector.process_event(
            ParsedEvent(
                source="signer",
                kind="signer_block_proposal",
                ts=100.0,
                fields={"signer_signature_hash": closed_hash, "block_height": 10},
            )
        )
        detector.process_event(
            ParsedEvent(
                source="signer",
                kind="signer_threshold_reached",
                ts=101.0,
                fields={
                    "signer_signature_hash": closed_hash,
                    "block_height": 10,
                    "percent_approved": 72.0,
                },
            )
        )
        detector.process_event(
            ParsedEvent(
                source="signer",
                kind="signer_block_pushed",
                ts=102.0,
                fields={"signer_signature_hash": closed_hash, "block_height": 10},
            )
        )
        detector.process_event(
            ParsedEvent(
                source="signer",
                kind="signer_block_proposal",
                ts=103.0,
                fields={"signer_signature_hash": open_hash, "block_height": 11},
            )
        )

        snapshot = detector.snapshot(now=110.0)
        recent = snapshot["recent_proposals"]
        self.assertGreaterEqual(len(recent), 2)
        self.assertEqual(recent[0]["signature_hash"], open_hash)
        self.assertEqual(recent[1]["signature_hash"], closed_hash)
        self.assertTrue(recent[0]["is_open"])
        self.assertFalse(recent[1]["is_open"])
        self.assertEqual(recent[0]["status"], "in_progress")
        self.assertEqual(recent[1]["status"], "approved")
        self.assertTrue(recent[1]["threshold_seen"])

    def test_recent_proposal_status_rejected(self) -> None:
        detector = Detector(
            DetectorConfig(
                proposal_timeout_seconds=99999,
                alert_cooldown_seconds=0,
                report_interval_seconds=99999,
            )
        )
        rejected_hash = "deadbeef01"
        detector.process_event(
            ParsedEvent(
                source="signer",
                kind="signer_block_proposal",
                ts=100.0,
                fields={"signer_signature_hash": rejected_hash, "block_height": 12},
            )
        )
        detector.process_event(
            ParsedEvent(
                source="signer",
                kind="signer_block_response",
                ts=101.0,
                fields={
                    "signer_signature_hash": rejected_hash,
                    "reject_reason": "SortitionViewMismatch",
                },
            )
        )

        snapshot = detector.snapshot(now=110.0)
        recent = snapshot["recent_proposals"]
        rejected_row = next(row for row in recent if row["signature_hash"] == rejected_hash)
        self.assertEqual(rejected_row["status"], "rejected")
        self.assertFalse(rejected_row["is_open"])
        self.assertEqual(snapshot["open_proposals_count"], 0)

    def test_rejection_threshold_finalizes_proposal(self) -> None:
        detector = Detector(
            DetectorConfig(
                alert_cooldown_seconds=0,
                report_interval_seconds=99999,
            )
        )
        signature_hash = "reject30"
        detector.process_event(
            ParsedEvent(
                source="signer",
                kind="signer_block_proposal",
                ts=100.0,
                fields={
                    "signer_signature_hash": signature_hash,
                    "block_height": 10,
                    "burn_height": 100,
                    "consensus_hash": "aa",
                },
            )
        )
        alerts = detector.process_event(
            ParsedEvent(
                source="signer",
                kind="signer_block_rejection",
                ts=101.0,
                fields={
                    "signer_signature_hash": signature_hash,
                    "signer_pubkey": "pub1",
                    "reject_reason": "NotLatestSortitionWinner",
                    "percent_rejected": 30.1,
                    "total_weight_rejected": 301,
                    "total_weight": 1000,
                },
            )
        )
        keys = {alert.key for alert in alerts}
        self.assertIn("proposal-reject-threshold-%s" % signature_hash, keys)
        self.assertNotIn(signature_hash, detector.proposals)
        self.assertEqual(detector.completed_proposals, 1)
        self.assertEqual(
            detector.proposal_reject_reasons.get(signature_hash),
            "NotLatestSortitionWinner",
        )

    def test_burn_boundary_rejection_alert(self) -> None:
        detector = Detector(
            DetectorConfig(
                alert_cooldown_seconds=0,
                report_interval_seconds=99999,
                burn_block_boundary_window_seconds=10,
            )
        )
        signature_hash = "boundary01"
        detector.process_event(
            ParsedEvent(
                source="signer",
                kind="signer_block_proposal",
                ts=100.0,
                fields={
                    "signer_signature_hash": signature_hash,
                    "block_height": 10,
                    "burn_height": 100,
                    "consensus_hash": "aa",
                },
            )
        )
        alerts = detector.process_event(
            ParsedEvent(
                source="signer",
                kind="signer_rejection_threshold_reached",
                ts=101.0,
                fields={
                    "signer_signature_hash": signature_hash,
                    "signer_pubkey": "pub1",
                    "reject_reason": "NotLatestSortitionWinner",
                    "percent_rejected": 35.0,
                    "total_weight_rejected": 350,
                    "total_weight": 1000,
                },
            )
        )
        alerts2 = detector.process_event(
            ParsedEvent(
                source="node",
                kind="node_consensus",
                ts=105.0,
                fields={
                    "burn_height": 101,
                    "consensus_hash": "bb",
                },
            )
        )
        keys = {alert.key for alert in alerts} | {alert.key for alert in alerts2}
        self.assertIn("proposal-reject-boundary-%s" % signature_hash, keys)

    def test_signer_block_response_rejection_is_info(self) -> None:
        detector = Detector(
            DetectorConfig(
                alert_cooldown_seconds=0,
                report_interval_seconds=99999,
            )
        )
        alerts = detector.process_event(
            ParsedEvent(
                source="signer",
                kind="signer_block_response",
                ts=100.0,
                fields={
                    "signer_signature_hash": "aa11bb22cc33",
                    "reject_reason": "SortitionViewMismatch",
                },
            )
        )
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, "info")
        self.assertEqual(alerts[0].key, "signer-reject-aa11bb22cc33")

    def test_info_alerts_for_new_burn_block_and_tenure_extend(self) -> None:
        detector = Detector(
            DetectorConfig(
                alert_cooldown_seconds=0,
                report_interval_seconds=99999,
            )
        )
        burn_alerts = detector.process_event(
            ParsedEvent(
                source="node",
                kind="node_tenure_notify",
                ts=100.0,
                fields={
                    "burn_height": 934988,
                    "consensus_hash": "aa" * 20,
                },
            )
        )
        burn_alerts.extend(
            detector.process_event(
                ParsedEvent(
                    source="node",
                    kind="node_consensus",
                    ts=100.1,
                    fields={
                        "burn_height": 934988,
                        "consensus_hash": "aa" * 20,
                    },
                )
            )
        )
        burn_keys = {alert.key for alert in burn_alerts}
        self.assertIn("burn-block-934988", burn_keys)
        self.assertTrue(all(alert.severity == "info" for alert in burn_alerts))
        burn_message = next(
            alert.message for alert in burn_alerts if alert.key == "burn-block-934988"
        )
        self.assertIn("sortition=not_observed", burn_message)

        extend_alerts = detector.process_event(
            ParsedEvent(
                source="node",
                kind="node_tenure_change",
                ts=101.0,
                fields={
                    "tenure_change_kind": "ExtendAll",
                    "txid": "tx-extend-1",
                    "origin": "SPTEST",
                    "block_height": 6319944,
                    "burn_height": 934988,
                },
            )
        )
        extend_keys = {alert.key for alert in extend_alerts}
        self.assertIn("tenure-extend-tx-extend-1", extend_keys)

    def test_burn_block_alert_includes_sortition_and_new_miner(self) -> None:
        detector = Detector(
            DetectorConfig(
                alert_cooldown_seconds=0,
                report_interval_seconds=99999,
            )
        )
        detector.current_bitcoin_block_height = 934987
        detector.process_event(
            ParsedEvent(
                source="node",
                kind="node_sortition_winner_selected",
                ts=100.0,
                fields={
                    "burn_height": 934988,
                    "winner_txid": "aa11bb22cc33dd44",
                    "winning_stacks_block_hash": "bb" * 32,
                },
            )
        )
        alerts = detector.process_event(
            ParsedEvent(
                source="node",
                kind="node_consensus",
                ts=100.1,
                fields={
                    "burn_height": 934988,
                    "consensus_hash": "cc" * 20,
                },
            )
        )
        burn_alert = next(
            alert for alert in alerts if alert.key == "burn-block-934988"
        )
        self.assertEqual(burn_alert.severity, "info")
        self.assertIn("sortition=winner_selected", burn_alert.message)
        self.assertIn("new_miner=txid:aa11bb22cc33", burn_alert.message)


if __name__ == "__main__":
    unittest.main()
