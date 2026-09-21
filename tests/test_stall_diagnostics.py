import json
import threading
import unittest
from collections import deque

from stacks_analyzer.detector import Alert, Detector, DetectorConfig
from stacks_analyzer.events import ParsedEvent
from stacks_analyzer.service import MonitoringService


def _config(**overrides) -> DetectorConfig:
    base = dict(
        node_stall_seconds=90,
        signer_stall_seconds=120,
        alert_cooldown_seconds=0,
        report_interval_seconds=99999,
        flash_block_seconds=60,
    )
    base.update(overrides)
    return DetectorConfig(**base)


def _tip(detector: Detector, ts: float, height: int, consensus: str, header: str, burn: int):
    detector.process_event(
        ParsedEvent(
            source="node",
            kind="node_block_proposal",
            ts=ts - 0.5,
            fields={
                "block_header_hash": header,
                "block_height": height,
                "burn_height": burn,
                "consensus_hash": consensus,
                "is_validated": True,
            },
        )
    )
    return detector.process_event(
        ParsedEvent(
            source="node",
            kind="node_tip_advanced",
            ts=ts,
            fields={"consensus_hash": consensus, "block_header_hash": header},
        )
    )


def _burn_block(detector: Detector, ts: float, burn: int, consensus: str):
    return detector.process_event(
        ParsedEvent(
            source="node",
            kind="node_consensus",
            ts=ts,
            fields={"consensus_hash": consensus, "burn_height": burn},
        )
    )


def _sortition_winner(detector: Detector, ts: float, burn: int, sender: str, txid: str):
    detector.process_event(
        ParsedEvent(
            source="node",
            kind="node_leader_block_commit",
            ts=ts - 1.0,
            fields={
                "burn_height": burn,
                "commit_txid": txid,
                "apparent_sender": sender,
                "stacks_block_hash": "ab" * 16,
                "sortition_position": 0,
                "parent_burn_block": burn - 1,
                "burn_fee": 50_000,
            },
        )
    )
    return detector.process_event(
        ParsedEvent(
            source="node",
            kind="node_sortition_winner_selected",
            ts=ts,
            fields={
                "burn_height": burn,
                "winner_txid": txid,
                "winning_stacks_block_hash": "ab" * 16,
            },
        )
    )


class TestStallDiagnostics(unittest.TestCase):
    def test_tenure_start_stall_names_new_miner_and_prior_heights(self) -> None:
        detector = Detector(_config())
        _burn_block(detector, ts=50.0, burn=1000, consensus="c1" * 20)
        _tip(detector, ts=100.0, height=500, consensus="c1" * 20, header="h500", burn=1000)
        _burn_block(detector, ts=130.0, burn=1001, consensus="c2" * 20)
        _sortition_winner(detector, ts=131.0, burn=1001, sender="bc1qnewminer", txid="f1" * 32)
        detector.process_event(
            ParsedEvent(
                source="node",
                kind="node_mempool_iteration",
                ts=140.0,
                fields={"considered_txs": 7, "stop_reason": "NoMoreCandidates", "elapsed_ms": 12},
            )
        )

        alerts, _ = detector.tick(now=200.0)
        stall_alerts = [alert for alert in alerts if alert.key == "node-stall"]
        self.assertEqual(len(stall_alerts), 1)
        message = stall_alerts[0].message
        self.assertIn("shape=tenure_start_no_block", message)
        self.assertIn("tenure=tenure_start", message)
        self.assertIn("miner=bc1qnewminer (burn 1001)", message)
        self.assertIn("last_block=500", message)
        self.assertIn("btc=1001", message)
        self.assertIn("mempool_ready=7", message)

        snapshot = detector.snapshot(now=200.0)
        active = snapshot["stall_diagnostics"]["active"]
        self.assertEqual(len(active), 1)
        diag = active[0]
        self.assertTrue(diag["active"])
        self.assertEqual(diag["kind"], "node")
        self.assertEqual(diag["shape"], "tenure_start_no_block")
        self.assertEqual(diag["tenure"]["position"], "tenure_start")
        self.assertEqual(diag["tenure"]["blocks_in_tenure"], 0)
        self.assertEqual(diag["miner"]["expected_apparent_sender"], "bc1qnewminer")
        self.assertEqual(diag["miner"]["expected_burn_height"], 1001)
        self.assertEqual(diag["stacks"]["last_confirmed_height"], 500)
        self.assertAlmostEqual(diag["stacks"]["last_confirmed_age_seconds"], 100.0)
        self.assertEqual(diag["bitcoin"]["height"], 1001)
        self.assertEqual(diag["bitcoin"]["last_burn_block_height"], 1001)
        self.assertIsNone(diag["bitcoin"]["reorg"])
        self.assertFalse(diag["bitcoin"]["flash_block"]["seen"])
        self.assertEqual(diag["mempool"]["ready_txs"], 7)
        self.assertTrue(diag["mempool"]["had_ready_txs"])
        since = diag["bitcoin"]["burn_blocks_since_last_stacks_block"]
        self.assertEqual([row["burn_height"] for row in since], [1001])
        self.assertEqual(since[0]["outcome"], "winner")
        self.assertTrue(any("bc1qnewminer" in factor for factor in diag["factors"]))
        # The snapshot must be JSON serializable for /api/state and the reports table.
        json.dumps(snapshot)

    def test_mid_tenure_stall_flags_reorg_flash_block_and_stuck_proposal(self) -> None:
        detector = Detector(_config())
        _burn_block(detector, ts=-600.0, burn=2000, consensus="d1" * 20)
        _sortition_winner(detector, ts=-599.0, burn=2000, sender="bc1qincumbent", txid="a1" * 32)
        _tip(detector, ts=20.0, height=700, consensus="d1" * 20, header="h700", burn=2000)
        _tip(detector, ts=40.0, height=701, consensus="d1" * 20, header="h701", burn=2000)
        # Two burn blocks 20s apart after the last Stacks block, neither with a winner.
        _burn_block(detector, ts=60.0, burn=2001, consensus="d2" * 20)
        _burn_block(detector, ts=80.0, burn=2002, consensus="d3" * 20)
        detector.process_event(
            ParsedEvent(
                source="node",
                kind="node_burnchain_reorg",
                ts=85.0,
                fields={"common_ancestor_height": 2001},
            )
        )
        detector.process_event(
            ParsedEvent(
                source="signer",
                kind="signer_block_proposal",
                ts=90.0,
                fields={
                    "signer_signature_hash": "ee" * 32,
                    "block_height": 702,
                    "burn_height": 2002,
                },
            )
        )
        detector.process_event(
            ParsedEvent(
                source="node",
                kind="node_error_or_warn",
                ts=95.0,
                fields={},
                line="Feb 04 08:01:05 host stacks-node[1]: WARN [95.0] [relay.rs:1] [p2p:x] noisy",
            )
        )
        detector.process_event(
            ParsedEvent(
                source="signer",
                kind="signer_error_or_warn",
                ts=96.0,
                fields={},
                line="Feb 04 08:01:06 host stacks-signer[1]: WARN [96.0] [signer.rs:1] Something odd",
            )
        )

        alerts, _ = detector.tick(now=140.0)
        keys = {alert.key for alert in alerts}
        self.assertIn("node-stall", keys)
        self.assertNotIn("signer-stall", keys)

        diag = detector.active_stall_diagnostics["node-stall"]
        self.assertEqual(diag["tenure"]["position"], "mid_tenure")
        self.assertEqual(diag["tenure"]["blocks_in_tenure"], 2)
        self.assertEqual(diag["shape"], "proposal_stuck")
        self.assertEqual(diag["miner"]["expected_apparent_sender"], "bc1qincumbent")
        self.assertEqual(diag["miner"]["latest_sortition_burn_height"], 2002)
        reorg = diag["bitcoin"]["reorg"]
        self.assertEqual(reorg["common_ancestor_height"], 2001)
        self.assertAlmostEqual(reorg["age_seconds"], 55.0)
        flash = diag["bitcoin"]["flash_block"]
        self.assertTrue(flash["seen"])
        self.assertEqual(
            [(pair["from_height"], pair["to_height"]) for pair in flash["pairs"]],
            [(2001, 2002)],
        )
        since = diag["bitcoin"]["burn_blocks_since_last_stacks_block"]
        self.assertEqual([row["burn_height"] for row in since], [2001, 2002])
        self.assertEqual(diag["proposals"]["open_count"], 1)
        self.assertEqual(diag["proposals"]["open"][0]["block_height"], 702)
        self.assertEqual(diag["stacks"]["last_proposal_height"], 702)
        # p2p chatter is dropped; the signer warning is kept, prefix stripped.
        self.assertEqual(len(diag["log_warnings"]), 1)
        self.assertEqual(diag["log_warnings"][0]["source"], "signer")
        self.assertTrue(diag["log_warnings"][0]["line"].startswith("WARN "))
        factors = " | ".join(diag["factors"])
        self.assertIn("Bitcoin reorg", factors)
        self.assertIn("Flash block: Bitcoin 2001 -> 2002", factors)
        self.assertIn("should have extended its tenure", factors)
        self.assertIn("Open proposal at height 702", factors)
        message = next(alert.message for alert in alerts if alert.key == "node-stall")
        self.assertIn("reorg=yes", message)
        self.assertIn("flash_block=yes", message)

    def test_recovery_finalizes_entry_and_enriches_recovered_alert(self) -> None:
        detector = Detector(_config())
        _tip(detector, ts=100.0, height=900, consensus="a1" * 20, header="h900", burn=3000)
        detector.tick(now=200.0)
        self.assertIn("node-stall", detector.active_stall_diagnostics)

        alerts = _tip(detector, ts=260.0, height=901, consensus="a1" * 20, header="h901", burn=3000)
        recovered = [alert for alert in alerts if alert.key == "node-stall-recovered"]
        self.assertEqual(len(recovered), 1)
        self.assertIn("recovered after 160s", recovered[0].message)
        self.assertIn("height=901", recovered[0].message)

        self.assertEqual(detector.active_stall_diagnostics, {})
        snapshot = detector.snapshot(now=261.0)
        self.assertEqual(snapshot["stall_diagnostics"]["active"], [])
        recent = snapshot["stall_diagnostics"]["recent"]
        self.assertEqual(len(recent), 1)
        self.assertFalse(recent[0]["active"])
        self.assertAlmostEqual(recent[0]["duration_seconds"], 160.0)
        self.assertAlmostEqual(recent[0]["recovered_ts"], 260.0)
        self.assertEqual(recent[0]["recovered_height"], 901)
        self.assertEqual(recent[0]["stacks"]["last_confirmed_height"], 900)

    def test_refresh_keeps_detection_facts_and_notes_miner_change(self) -> None:
        detector = Detector(_config())
        _burn_block(detector, ts=10.0, burn=4000, consensus="b1" * 20)
        _sortition_winner(detector, ts=11.0, burn=4000, sender="bc1qfirst", txid="c1" * 32)
        _tip(detector, ts=20.0, height=100, consensus="b1" * 20, header="h100", burn=4000)
        detector.tick(now=120.0)
        first = detector.active_stall_diagnostics["node-stall"]
        self.assertEqual(first["shape"], "mid_tenure_silent")

        _burn_block(detector, ts=150.0, burn=4001, consensus="b2" * 20)
        _sortition_winner(detector, ts=151.0, burn=4001, sender="bc1qsecond", txid="c2" * 32)
        detector.tick(now=200.0)
        refreshed = detector.active_stall_diagnostics["node-stall"]
        self.assertIs(refreshed, first)
        self.assertAlmostEqual(refreshed["detected_ts"], 120.0)
        self.assertAlmostEqual(refreshed["gap_seconds"], 180.0)
        self.assertEqual(refreshed["shape_at_detection"], "mid_tenure_silent")
        self.assertEqual(refreshed["shape"], "tenure_start_no_block")
        self.assertEqual(refreshed["miner_at_detection"]["expected_apparent_sender"], "bc1qfirst")
        self.assertEqual(refreshed["miner"]["expected_apparent_sender"], "bc1qsecond")
        self.assertTrue(
            any("bc1qfirst -> bc1qsecond" in factor for factor in refreshed["factors"])
        )
        # One history entry, not one per tick.
        self.assertEqual(len(detector.stall_history), 1)

    def test_idle_mempool_stall_is_named_as_such(self) -> None:
        detector = Detector(_config())
        _tip(detector, ts=100.0, height=10, consensus="e1" * 20, header="h10", burn=5000)
        detector.process_event(
            ParsedEvent(
                source="node",
                kind="node_mempool_iteration",
                ts=170.0,
                fields={"considered_txs": 0, "stop_reason": "NoMoreCandidates"},
            )
        )
        alerts, _ = detector.tick(now=200.0)
        stall = next(alert for alert in alerts if alert.key == "node-stall")
        self.assertEqual(stall.severity, "info")
        self.assertIn("shape=idle_mempool", stall.message)
        diag = detector.active_stall_diagnostics["node-stall"]
        self.assertTrue(diag["mempool"]["empty_recent"])

    def test_signer_stall_has_its_own_entry(self) -> None:
        detector = Detector(_config())
        detector.process_event(
            ParsedEvent(
                source="signer",
                kind="signer_block_proposal",
                ts=100.0,
                fields={"signer_signature_hash": "aa" * 32, "block_height": 55, "burn_height": 7},
            )
        )
        alerts, _ = detector.tick(now=300.0)
        self.assertIn("signer-stall", {alert.key for alert in alerts})
        diag = detector.active_stall_diagnostics["signer-stall"]
        self.assertEqual(diag["kind"], "signer")
        self.assertEqual(diag["stacks"]["last_proposal_height"], 55)
        self.assertAlmostEqual(diag["stacks"]["last_proposal_age_seconds"], 200.0)
        self.assertEqual(detector.stall_diagnostics_for_alert("signer-stall"), diag)

    def test_suppressed_and_rebased_stalls_leave_no_diagnostics(self) -> None:
        detector = Detector(_config())
        detector.suppress_alerts = True
        _tip(detector, ts=100.0, height=1, consensus="f1" * 20, header="h1", burn=1)
        detector.tick(now=300.0)
        self.assertIn("node-stall", detector.active_stalls)
        self.assertEqual(detector.active_stall_diagnostics, {})
        self.assertEqual(len(detector.stall_history), 0)

        detector.suppress_alerts = False
        detector.tick(now=301.0)
        self.assertIn("node-stall", detector.active_stall_diagnostics)
        detector.rebase_for_live_start(400.0)
        self.assertEqual(detector.active_stall_diagnostics, {})
        self.assertFalse(detector.stall_history[0]["active"])

    def test_stall_diagnostics_for_recovered_key_finds_finished_stall(self) -> None:
        detector = Detector(_config())
        _tip(detector, ts=100.0, height=1, consensus="f1" * 20, header="h1", burn=1)
        detector.tick(now=300.0)
        _tip(detector, ts=310.0, height=2, consensus="f1" * 20, header="h2", burn=1)
        diag = detector.stall_diagnostics_for_alert("node-stall-recovered")
        self.assertIsNotNone(diag)
        self.assertFalse(diag["active"])
        self.assertIsNone(detector.stall_diagnostics_for_alert("proposal-timeout-x"))


class _RecordingHistoryStore:
    def __init__(self) -> None:
        self.reports = []

    def record_alert(self, ts, severity, key, message):
        return 1

    def report_context_events(self, ts):
        return []

    def create_report(self, ts, severity, alert_key, summary, data):
        self.reports.append(json.loads(json.dumps(data)))
        return len(self.reports)

    def attach_report(self, alert_id, report_id):
        pass


class TestServiceStallReports(unittest.TestCase):
    def _service(self, detector: Detector) -> MonitoringService:
        service = MonitoringService.__new__(MonitoringService)
        service.state_lock = threading.Lock()
        service.recent_alerts = deque(maxlen=200)
        service.recent_reports = deque(maxlen=200)
        service.history_store = _RecordingHistoryStore()
        service.detector = detector
        service.notifier = None
        service.suppress_notifications = False
        service.telegram_critical_open_keys = set()
        return service

    def test_stall_report_carries_a_detached_copy_of_the_diagnostics(self) -> None:
        detector = Detector(_config())
        _tip(detector, ts=100.0, height=42, consensus="a9" * 20, header="h42", burn=8000)
        alerts, _ = detector.tick(now=200.0)
        stall = next(alert for alert in alerts if alert.key == "node-stall")
        service = self._service(detector)

        service._publish_alert(stall)

        report = service.history_store.reports[0]
        diag = report["stall_diagnostics"]
        self.assertEqual(diag["key"], "node-stall")
        self.assertEqual(diag["stacks"]["last_confirmed_height"], 42)
        self.assertTrue(diag["active"])
        # Later ticks refresh the live entry but must not rewrite the stored report.
        detector.tick(now=500.0)
        self.assertAlmostEqual(detector.active_stall_diagnostics["node-stall"]["gap_seconds"], 400.0)
        self.assertAlmostEqual(report["stall_diagnostics"]["gap_seconds"], 100.0)
        self.assertIn("stall_diagnostics", report["snapshot"])

    def test_non_stall_report_has_no_diagnostics(self) -> None:
        detector = Detector(_config())
        service = self._service(detector)
        service._publish_alert(
            Alert(key="proposal-timeout-" + "ab" * 32, severity="critical", message="x", ts=5.0)
        )
        self.assertIsNone(service.history_store.reports[0]["stall_diagnostics"])


if __name__ == "__main__":
    unittest.main()
