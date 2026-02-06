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
        self.assertEqual(detector.signer_weight_samples["pub1"][-1], 42)

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
                source="signer",
                kind="signer_state_machine_update",
                ts=105.0,
                fields={
                    "burn_height": 101,
                    "burn_block": "bb",
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
        alerts = detector.process_event(
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
        burn_alert = next(
            alert for alert in alerts if alert.key == "burn-block-934988"
        )
        self.assertEqual(burn_alert.severity, "info")
        self.assertIn("sortition=winner_selected", burn_alert.message)
        self.assertIn("new_miner=txid:aa11bb22cc33", burn_alert.message)


if __name__ == "__main__":
    unittest.main()
