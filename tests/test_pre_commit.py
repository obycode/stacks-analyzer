import unittest

from stacks_analyzer.detector import Detector, DetectorConfig
from stacks_analyzer.events import LogParser

HASH = "0a231350b7433770c1f13d887aca91b974e219c05e13357af4297f8667ffa455"
PREFIX = (
    "Aug 03 21:55:41 host stacks-signer[123]: INFO [%s] "
    "[stacks-signer/src/v0/signer.rs:1140] [signer_runloop:30000] "
    "Cycle #140 Signer #7: "
)


def pre_commit_line(ts, address, weight, have, need, reached, already_signed=False):
    return (PREFIX % ts) + (
        "Received block pre-commit, signer_address: %s, signer_signature_hash: %s, "
        "consensus_hash: 8b2a669d766fc1edc4818d09b3e38d72f843478c, "
        "block_height: 8698973, signer_weight: %d, pre_commit_weight: %d, "
        "pre_commit_weight_required: %d, total_weight: 3654, "
        "pre_commit_threshold_reached: %s, already_signed: %s"
        % (address, HASH, weight, have, need,
           "true" if reached else "false",
           "true" if already_signed else "false")
    )


def unknown_line(ts, address):
    return (PREFIX % ts) + (
        "Received block pre-commit for an unknown block, storing as pending, "
        "signer_address: %s, signer_signature_hash: %s, signer_weight: 430"
        % (address, HASH)
    )


def sent_line(ts):
    return (PREFIX % ts) + (
        "Broadcasting block pre-commit to stacks node for %s" % HASH
    )


def proposal_line(ts):
    return (PREFIX % ts) + (
        "received a block proposal for a new block., signer_signature_hash: %s, "
        "block_id: ef0f4a17, block_height: 8698973, burn_height: 960948, "
        "consensus_hash: 8b2a669d766fc1edc4818d09b3e38d72f843478c" % HASH
    )


class TestPreCommitParsing(unittest.TestCase):
    def test_parses_inbound_pre_commit_with_running_tally(self) -> None:
        events = LogParser().parse_line(
            "signer", pre_commit_line("1785808541.9", "SP2ABC", 624, 2568, 2558, True)
        )
        self.assertEqual(len(events), 1)
        fields = events[0].fields
        self.assertEqual(events[0].kind, "signer_block_pre_commit")
        self.assertEqual(fields["signer_address"], "SP2ABC")
        self.assertEqual(fields["signer_signature_hash"], HASH)
        self.assertEqual(fields["pre_commit_weight"], 2568)
        self.assertEqual(fields["pre_commit_weight_required"], 2558)
        self.assertEqual(fields["total_weight"], 3654)
        self.assertTrue(fields["pre_commit_threshold_reached"])
        self.assertFalse(fields["already_signed"])

    def test_unknown_block_variant_is_not_confused_with_the_normal_one(self) -> None:
        events = LogParser().parse_line("signer", unknown_line("1785808541.9", "SP9LATE"))
        kinds = [event.kind for event in events]
        self.assertEqual(kinds, ["signer_block_pre_commit_unknown"])
        self.assertEqual(events[0].fields["signer_address"], "SP9LATE")

    def test_parses_our_own_outbound_pre_commit(self) -> None:
        events = LogParser().parse_line("signer", sent_line("1785808541.6"))
        self.assertEqual([event.kind for event in events],
                         ["signer_block_pre_commit_sent"])
        self.assertEqual(events[0].fields["signer_signature_hash"], HASH)


class TestPreCommitPhaseAttribution(unittest.TestCase):
    def _detector(self):
        return Detector(DetectorConfig(proposal_timeout_seconds=45))

    def _feed(self, detector, line):
        for event in LogParser().parse_line("signer", line):
            detector.process_event(event)

    def test_precommit_starvation_is_attributed_and_alerted(self) -> None:
        """The 8698973 shape: we validate fast, then wait minutes for 70%."""
        detector = self._detector()
        self._feed(detector, proposal_line("1785808540.838"))
        self._feed(detector, sent_line("1785808541.655"))
        # A minority of weight pre-commits; the threshold is never reached.
        self._feed(
            detector, pre_commit_line("1785808545.0", "SP2SMALL", 4, 1200, 2558, False)
        )

        state = detector.proposals[HASH]
        self.assertIsNotNone(state.own_pre_commit_ts)
        self.assertIsNone(state.pre_commit_threshold_ts)

        phase = detector._proposal_phase(state, 1785808739.5)
        self.assertIn("precommit-starvation", phase)
        self.assertIn("have=1200/2558", phase)
        # Validation was sub-second; the wait was ~198s.
        self.assertIn("validated_in=0.8s", phase)
        self.assertIn("waited=198s", phase)

        # The phase must reach the operator, not just live on the state object.
        alerts = []
        detector._detect_proposal_timeouts(1785808739.5, alerts)
        self.assertEqual(len(alerts), 1)
        self.assertIn("no threshold confirmation", alerts[0].message)
        self.assertIn("phase=precommit-starvation", alerts[0].message)

    def test_threshold_crossing_switches_phase_to_signature_gathering(self) -> None:
        detector = self._detector()
        self._feed(detector, proposal_line("1785808540.838"))
        self._feed(detector, sent_line("1785808541.655"))
        self._feed(
            detector, pre_commit_line("1785808739.5", "SP2BIG", 624, 2568, 2558, True)
        )

        state = detector.proposals[HASH]
        self.assertIsNotNone(state.pre_commit_threshold_ts)
        phase = detector._proposal_phase(state, 1785808745.5)
        self.assertIn("signature-gathering", phase)

    def test_phase_is_none_without_the_pre_commit_log(self) -> None:
        """Older signer builds emit no pre-commit receipts; degrade quietly."""
        detector = self._detector()
        self._feed(detector, proposal_line("1785808540.838"))
        self._feed(detector, sent_line("1785808541.655"))
        state = detector.proposals[HASH]
        self.assertIsNone(detector._proposal_phase(state, 1785808739.5))

    def test_awaiting_local_validation_before_we_pre_commit(self) -> None:
        detector = self._detector()
        self._feed(detector, proposal_line("1785808540.838"))
        state = detector.proposals[HASH]
        phase = detector._proposal_phase(state, 1785808560.0)
        self.assertIn("awaiting-local-validation", phase)


class TestProposalDeliveryLag(unittest.TestCase):
    def test_burst_of_unknown_pre_commits_raises_delivery_lag(self) -> None:
        detector = Detector(
            DetectorConfig(
                pre_commit_before_proposal_threshold=3,
                pre_commit_before_proposal_window_seconds=120,
            )
        )
        parser = LogParser()
        for i in range(3):
            for event in parser.parse_line(
                "signer", unknown_line("178580854%d.0" % i, "SP%d" % i)
            ):
                detector.process_event(event)

        alerts = []
        detector._detect_proposal_delivery_lag(1785808545.0, alerts)
        self.assertEqual(len(alerts), 1)
        self.assertIn("Proposal delivery lagging", alerts[0].message)
        self.assertIn("before this node", alerts[0].message)

    def test_stale_unknown_pre_commits_fall_out_of_the_window(self) -> None:
        detector = Detector(
            DetectorConfig(
                pre_commit_before_proposal_threshold=3,
                pre_commit_before_proposal_window_seconds=60,
            )
        )
        parser = LogParser()
        for i in range(3):
            for event in parser.parse_line(
                "signer", unknown_line("178580854%d.0" % i, "SP%d" % i)
            ):
                detector.process_event(event)

        alerts = []
        # Well past the window: the burst should have aged out.
        detector._detect_proposal_delivery_lag(1785809000.0, alerts)
        self.assertEqual(alerts, [])
        self.assertEqual(len(detector.pre_commits_before_proposal), 0)


class TestPreCommitLaggards(unittest.TestCase):
    def test_median_lateness_ranks_slowest_signers_first(self) -> None:
        detector = Detector(DetectorConfig(large_signer_min_samples=2))
        parser = LogParser()
        # Two blocks; SP_SLOW is consistently ~50s behind, SP_FAST ~1s.
        for block_ts, base in ((1785808540.0, 1785808540.0), (1785808600.0, 1785808600.0)):
            line = proposal_line("%.3f" % block_ts).replace(HASH, HASH)
            for event in parser.parse_line("signer", line):
                detector.process_event(event)
            for address, offset in (("SP_FAST", 1.0), ("SP_SLOW", 50.0)):
                for event in parser.parse_line(
                    "signer",
                    pre_commit_line("%.3f" % (base + offset), address, 10, 100, 2558, False),
                ):
                    detector.process_event(event)
            detector.proposals.pop(HASH, None)

        rows = detector._pre_commit_laggards()
        self.assertEqual(rows[0][0], "SP_SLOW")
        self.assertGreater(rows[0][1], rows[1][1])
        self.assertEqual(rows[0][2], 2)


if __name__ == "__main__":
    unittest.main()


class TestSignerIdentifierJoin(unittest.TestCase):
    """Pre-commits are keyed by address, acceptances by pubkey; they must merge."""

    PUBKEY = "0302328212d5e430a8a880f8e2365a8f976ee50490ff030c106866c0b789eae91a"

    def _driver(self, logged_address=None):
        from stacks_analyzer.c32 import pubkey_to_address

        detector = Detector(DetectorConfig(large_signer_min_samples=1))
        parser = LogParser()
        address = pubkey_to_address(self.PUBKEY)

        def feed(line):
            for event in parser.parse_line("signer", line):
                detector.process_event(event)

        feed(proposal_line("1785808540.000"))
        feed(sent_line("1785808540.500"))
        # Their pre-commit is 2s behind our proposal receipt, and crosses 70%.
        feed(pre_commit_line("1785808542.000", address, 624, 2600, 2558, True))
        # Their acceptance lands 0.4s after the crossing.
        addr_field = (
            ", signer_address: %s" % logged_address if logged_address else ""
        )
        feed(
            (PREFIX % "1785808542.400")
            + ("Received block acceptance, signer_pubkey: %s%s, "
               "signer_signature_hash: %s, block_height: 8698973, signer_weight: 624, "
               "total_weight: 3654" % (self.PUBKEY, addr_field, HASH))
        )
        return detector, address

    def test_derived_address_merges_both_phases_onto_one_row(self) -> None:
        detector, address = self._driver()
        rows = detector._signer_phase_rows()
        self.assertEqual(len(rows), 1, rows)
        row = rows[0]
        self.assertEqual(row["pubkey"], self.PUBKEY)
        self.assertEqual(row["signer_address"], address)
        self.assertAlmostEqual(float(row["pre_commit_median_seconds"]), 2.0, places=2)
        self.assertAlmostEqual(float(row["acceptance_median_seconds"]), 0.4, places=2)
        self.assertEqual(detector.address_derivation_mismatches, 0)

    def test_logged_address_is_preferred_and_agrees_with_derivation(self) -> None:
        from stacks_analyzer.c32 import pubkey_to_address

        detector, address = self._driver(logged_address=pubkey_to_address(self.PUBKEY))
        rows = detector._signer_phase_rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(detector.address_derivation_mismatches, 0)

    def test_disagreeing_logged_address_is_counted_not_silently_joined(self) -> None:
        detector, _ = self._driver(logged_address="SP000000000000000000002Q6VF78")
        self.assertEqual(detector.address_derivation_mismatches, 1)
