"""Stall shapes that come from the history of the proposal that held the chain.

Modeled on mainnet stalls seen on 4.0.3: a minority of signer weight rejects a
premature tenure extend and the miner sits out its rejection timer; a new tenure's
first block is rejected because signers have not agreed on the new burn block yet;
a high-weight signer goes silent and pre-commits sit just under the threshold.
"""

import unittest

from stacks_analyzer.detector import Detector, DetectorConfig
from stacks_analyzer.events import LogParser, ParsedEvent

SIG = "5a" * 32
FAST = "023d6e4adbd5e7bedd5a1e1b85940e1e8c6c34924fd0d584e5e15d84c8572083d9"
FAST_ADDRESS = "SP0D0P5KKX29BD0JZXZAV9V3XAK3GVNS189NAA3M"


def _config(**overrides) -> DetectorConfig:
    base = dict(
        node_stall_seconds=90,
        signer_stall_seconds=120,
        alert_cooldown_seconds=0,
        report_interval_seconds=99999,
        proposal_timeout_seconds=99999,
    )
    base.update(overrides)
    return DetectorConfig(**base)


def _event(detector: Detector, kind: str, ts: float, source: str = "signer", **fields):
    return detector.process_event(ParsedEvent(source=source, kind=kind, ts=ts, fields=fields))


def _tip(detector: Detector, ts: float, height: int, header: str):
    consensus = "c1" * 20
    _event(
        detector,
        "node_block_proposal",
        ts - 0.5,
        source="node",
        block_header_hash=header,
        block_height=height,
        burn_height=1000,
        consensus_hash=consensus,
        is_validated=True,
    )
    return _event(
        detector,
        "node_tip_advanced",
        ts,
        source="node",
        consensus_hash=consensus,
        block_header_hash=header,
    )


def _pre_commit(detector: Detector, ts: float, address: str, weight: int, running: int):
    _event(
        detector,
        "signer_block_pre_commit",
        ts,
        signer_signature_hash=SIG,
        block_height=101,
        signer_address=address,
        signer_weight=weight,
        pre_commit_weight=running,
        pre_commit_weight_required=2800,
        total_weight=4000,
        pre_commit_threshold_reached=running >= 2800,
    )


def _proposal(detector: Detector, ts: float):
    _event(detector, "signer_block_proposal", ts, signer_signature_hash=SIG, block_height=101, burn_height=1000)


def _stalled_below_threshold(detector: Detector) -> None:
    """Tip at 100; proposal at 105 pre-committed to 2573/2800 by 110, then nothing."""
    _tip(detector, ts=100.0, height=100, header="h100")
    _proposal(detector, 105.0)
    _event(detector, "signer_block_pre_commit_sent", 106.0, signer_signature_hash=SIG)
    _pre_commit(detector, 107.0, "SPBIG1", 1500, 1500)
    _pre_commit(detector, 110.0, "SPBIG2", 1073, 2573)


def _recover(detector: Detector, ts: float, running_before: int = 2573):
    _pre_commit(detector, ts, FAST_ADDRESS, 636, running_before + 636)
    _event(detector, "signer_threshold_reached", ts + 1.0, signer_signature_hash=SIG, percent_approved=72.0)
    _event(detector, "signer_block_pushed", ts + 2.0, signer_signature_hash=SIG, block_height=101)
    return _tip(detector, ts=ts + 3.0, height=101, header="h101")


class TestStallProposalShapes(unittest.TestCase):
    def test_minority_rejection_names_the_signer_and_the_miner_retry_timer(self) -> None:
        detector = Detector(_config(), signer_names={FAST: "Fast Pool 2"})
        _stalled_below_threshold(detector)
        _event(
            detector,
            "signer_block_rejection",
            113.0,
            signer_signature_hash=SIG,
            signer_pubkey=FAST,
            reject_reason="InvalidTenureExtend",
            signature_weight=636,
            total_weight=4000,
            block_height=101,
        )

        alerts, _ = detector.tick(now=192.0)
        stall = next(alert for alert in alerts if alert.key == "node-stall")
        self.assertIn("shape=minority_rejection_wait", stall.message)
        self.assertIn("precommits=2573/2800 flat=82s", stall.message)
        self.assertIn("early_reject=15.9%(InvalidTenureExtend)", stall.message)
        self.assertIn("miner_retry~90s", stall.message)

        diag = detector.active_stall_diagnostics["node-stall"]
        stuck = diag["stuck_proposal"]
        self.assertEqual(stuck["block_height"], 101)
        self.assertAlmostEqual(stuck["early_reject_percent"], 15.9)
        self.assertEqual(stuck["miner_retry"]["timeout_seconds"], 90)
        self.assertAlmostEqual(stuck["miner_retry"]["expected_ts"], 195.0)
        self.assertTrue(stuck["pre_commit_plateau"]["ongoing"])
        factors = " | ".join(diag["factors"])
        self.assertIn("Rejected within 30s by Fast Pool 2", factors)

        # The miner re-proposes when its timer runs out; the rejecting signer's own
        # timer has passed by then, so it pre-commits and the tally crosses.
        _event(detector, "signer_block_reproposal", 195.0, signer_signature_hash=SIG, block_height=101)
        alerts = _recover(detector, 196.0)
        recovered = next(alert for alert in alerts if alert.key == "node-stall-recovered")
        # The proposal closed before the tip advanced; the diagnosis must not
        # collapse to "miner went quiet".
        self.assertIn("shape=minority_rejection_wait", recovered.message)
        self.assertIn("reproposed=1", recovered.message)

        final = detector.stall_history[-1]
        self.assertEqual(final["shape"], "minority_rejection_wait")
        stuck = final["stuck_proposal"]
        plateau = stuck["pre_commit_plateau"]
        self.assertFalse(plateau["ongoing"])
        self.assertAlmostEqual(plateau["seconds"], 86.0)
        self.assertEqual(plateau["weight"], 2573)
        self.assertEqual([row["address"] for row in plateau["ended_by"]], [FAST_ADDRESS])
        self.assertEqual([row["address"] for row in stuck["threshold_crossed_by"]], [FAST_ADDRESS])
        self.assertEqual(stuck["reproposals"], 1)
        self.assertAlmostEqual(stuck["first_reproposal_after_seconds"], 90.0)
        self.assertEqual(stuck["dominant_phase"], "pre_commit_wait")

    def test_silent_signer_is_a_pre_commit_plateau_on_the_full_timer(self) -> None:
        detector = Detector(_config())
        _stalled_below_threshold(detector)
        # Fast Pool 2 is a known signer (it pre-committed to an earlier block).
        detector.signer_weight_by_address[FAST_ADDRESS] = 636

        alerts, _ = detector.tick(now=192.0)
        stall = next(alert for alert in alerts if alert.key == "node-stall")
        self.assertIn("shape=pre_commit_plateau", stall.message)
        self.assertIn("miner_retry~180s", stall.message)
        diag = detector.active_stall_diagnostics["node-stall"]
        missing = diag["stuck_proposal"]["missing_pre_commit_signers"]
        self.assertEqual([row["address"] for row in missing], [FAST_ADDRESS])
        factors = " | ".join(diag["factors"])
        self.assertIn("Pre-commits flat at 2573/2800", factors)
        self.assertIn("Not pre-committed yet: ", factors)
        self.assertIn("No early rejections: the miner waits ~3m 00s", factors)

        _recover(detector, 280.0)
        final = detector.stall_history[-1]
        self.assertEqual(final["shape"], "pre_commit_plateau")
        self.assertEqual(final["shape_at_detection"], "pre_commit_plateau")

    def test_tenure_start_block_rejected_without_signer_consensus(self) -> None:
        detector = Detector(_config())
        _tip(detector, ts=100.0, height=100, header="h100")
        _event(detector, "node_consensus", 104.0, source="node", consensus_hash="c2" * 20, burn_height=1001)
        _proposal(detector, 107.0)
        _event(detector, "signer_no_global_state", 107.1, signer_signature_hash=SIG)
        _event(
            detector,
            "signer_block_response",
            107.2,
            signer_signature_hash=SIG,
            reject_reason="NoSignerConsensus",
            accepted=False,
        )
        # Our signer turned the block down without storing it, so peers'
        # pre-commits for it are logged as being for an unknown block.
        _event(
            detector,
            "signer_block_pre_commit_unknown",
            108.0,
            signer_signature_hash=SIG,
            signer_address="SPBIG1",
            signer_weight=1500,
        )
        self.assertIn(SIG, detector.proposals)
        self.assertEqual(len(detector.pre_commits_before_proposal), 0)

        detector.tick(now=192.0)
        diag = detector.active_stall_diagnostics["node-stall"]
        self.assertEqual(diag["shape"], "no_signer_consensus")
        stuck = diag["stuck_proposal"]
        self.assertTrue(stuck["no_global_state"])
        self.assertEqual(stuck["pre_commit_weight"], 1500)
        self.assertEqual(stuck["rejecting_signers"][0]["label"], "this signer")
        factors = " | ".join(diag["factors"])
        self.assertIn("no agreed signer state when it arrived, 3s after burn block 1001", factors)

        # Re-proposed after the miner's timer; this time it is signed.
        _proposal(detector, 197.0)
        _pre_commit(detector, 198.0, "SPBIG2", 1300, 2800)
        _event(detector, "signer_threshold_reached", 199.0, signer_signature_hash=SIG, percent_approved=72.0)
        alerts = _tip(detector, ts=201.0, height=101, header="h101")
        recovered = next(alert for alert in alerts if alert.key == "node-stall-recovered")
        self.assertIn("shape=no_signer_consensus", recovered.message)
        self.assertEqual(detector.stall_history[-1]["stuck_proposal"]["reproposals"], 1)

    def test_stuck_proposal_is_the_one_that_cost_the_most_time(self) -> None:
        rows = [
            {"signature_hash": "old", "block_height": 101, "start_ts": 105.0},
            {"signature_hash": "new", "block_height": 101, "start_ts": 150.0, "signed_ts": 260.0},
            {"signature_hash": "retry", "block_height": 101, "start_ts": 255.0, "signed_ts": 258.0},
        ]
        picked = Detector._pick_stuck_proposal(rows, stalled_since=100.0, now=270.0)
        self.assertEqual(picked["signature_hash"], "new")
        self.assertAlmostEqual(picked["stuck_seconds"], 105.0)

    def test_miner_retry_steps_follow_the_rejected_weight(self) -> None:
        detector = Detector(_config())
        self.assertEqual(detector._miner_retry_timeout(0.0), 180)
        self.assertEqual(detector._miner_retry_timeout(15.9), 90)
        self.assertEqual(detector._miner_retry_timeout(23.0), 45)
        self.assertEqual(detector._miner_retry_timeout(30.0), 0)
        custom = Detector(_config(miner_rejection_timeout_steps=((0.0, 60), (20.0, 10))))
        self.assertEqual(custom._miner_retry_timeout(15.0), 60)


PREFIX = (
    "Sep 27 21:39:48 host stacks-signer[1]: %s [1790559588.330438] "
    "[stacks-signer/src/v0/signer.rs:1512] [signer_runloop:30000] Cycle #144 Signer #3: "
)


class TestStallProposalParsing(unittest.TestCase):
    def test_reproposal_lines_from_both_signer_versions(self) -> None:
        parser = LogParser()
        for text in (
            # 4.0.3
            "received a block proposal for a block we have pre-committed to but not signed. "
            "Re-evaluating the pre-commit.",
            # 4.0.4
            "received a block proposal for a block we validated but have not signed. "
            "Re-evaluating the pre-commit.",
            "received a block proposal for this block before, but our rejection reason "
            "allows us to reconsider",
        ):
            line = (PREFIX % "INFO") + text + (
                ", signer_signature_hash: %s, block_id: aa04, block_height: 9077867, "
                "burn_height: 968914" % SIG
            )
            kinds = {event.kind: event for event in parser.parse_line("signer", line)}
            self.assertIn("signer_block_reproposal", kinds, text)
            self.assertNotIn("signer_block_proposal", kinds)
            self.assertEqual(kinds["signer_block_reproposal"].fields["signer_signature_hash"], SIG)
            self.assertEqual(kinds["signer_block_reproposal"].fields["block_height"], 9077867)

    def test_new_block_and_other_cycle_lines_are_not_reproposals(self) -> None:
        parser = LogParser()
        for text, expected in (
            ("received a block proposal for a new block.", "signer_block_proposal"),
            ("Received a block proposal for a different reward cycle. Ignore it.", None),
        ):
            line = (PREFIX % "INFO") + text + ", signer_signature_hash: %s, block_height: 5" % SIG
            kinds = {event.kind for event in parser.parse_line("signer", line)}
            self.assertNotIn("signer_block_reproposal", kinds)
            if expected:
                self.assertIn(expected, kinds)

    def test_no_global_signer_state_warning(self) -> None:
        line = (PREFIX % "WARN") + (
            "Cannot validate block, no global signer state, signer_signature_hash: %s, "
            "block_id: 1618ac1a, local_signer_state: Initialized(SignerStateMachine { })" % SIG
        )
        events = {event.kind: event for event in LogParser().parse_line("signer", line)}
        self.assertEqual(events["signer_no_global_state"].fields["signer_signature_hash"], SIG)
        self.assertIn("signer_error_or_warn", events)


if __name__ == "__main__":
    unittest.main()
