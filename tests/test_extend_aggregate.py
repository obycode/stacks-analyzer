import unittest

from stacks_analyzer.detector import Detector, DetectorConfig
from stacks_analyzer.events import LogParser

# Real cycle-140 mainnet signers: (pubkey, weight, tenure_idle_timeout in use).
# Xverse (433/430/424) and the smaller operators were still on 120s while
# L2-Labs (624/498/428) and Fast Pool (387) had moved to 30s.
SIGNERS = [
    ("02844807121921880119fe05ae47fccb4945a4bb2f840fe7de66e6f32640bc8169", 624, 30),
    ("0268e6f499fca2912488e89fc8b6734cafbe24a4ecbcd3312e4eb27ed8e5cfb4f3", 498, 30),
    ("038cb1e945144ca7669b0f33656b8379bcb3c17795b4d8665e42dea76eb3f86d2f", 428, 30),
    ("023d6ecdc36fa1e1c6a9f116c7f13ae843001ed9d617f66f6c68cabf751bf82555", 387, 30),
    ("02c770af1c0316b42d50bb2f7720f473a7393a53878a212f1f573b23b8fecc1b35", 75, 30),
    ("023d6e4adbd5e7bedd5a1e1b85940e1e8c6c34924fd0d584e5e15d84c8572083d9", 67, 30),
    ("0228a566db9a7b3212d612aa06e34fa981351a4372737849bfcaa1a28e8a044e5d", 17, 30),
    ("03a541c1ec2cfb32da48cfadf439c9b2f27d166bbffa18a178c7a6a0d54cfa7813", 3, 30),
    ("0284df4505c6318a0017a7848aa0a95bf8cd3db697a89d2ec1978a027bece770ef", 2, 30),
    ("02877ce29ba35458b827a6ea18510b9058ae4c30e2c33d288f2982c13497caec6e", 433, 120),
    ("0302328212d5e430a8a880f8e2365a8f976ee50490ff030c106866c0b789eae91a", 430, 120),
    ("03b3b78738abbdc573cdcefd8200b1bca999e2f2fd8ecdf70c64ced1e4105437b7", 424, 120),
    ("02a89cb3164d3dabcb5cf8796bfc28b91fade8c71a64b5a76d94e79cd27cfa8895", 83, 120),
    ("03bbbe587de8a76343bb9cd4233b3b60962a2ff54677dc564a704c8578a67aa582", 66, 120),
    ("039262e5a8badd8e49eaa1808a675ad005f7b324bd677576fa670e43e73b166844", 58, 120),
    ("0321129d7a3e14cce66abef68b9a3d31d998f14e9a18b09d66aa1110fc604a3b1f", 33, 120),
    ("038b9ddb9808631dd75ccb0b6715b36bb1e391d85d40f1a031e98a332890bed2ea", 8, 120),
    ("03e0df37e83e43847625a0320456cb9758050a61ce76c2c130bf50242f27ba6d54", 6, 120),
    ("022150d4ea6dc60e75e162455553a92adea0a0f3000c192cc55d0bffed22c0a8e0", 4, 120),
    ("024f164c6e73df283d34d7d9cc86553a82dce76045ba7dfbf4de0004f89eabb8e0", 3, 120),
]

TOTAL_WEIGHT = 3712  # includes 63 weight of offline signers that never respond
SIGHASH = "4c" * 32
REF = 1785349506  # proposed_time of the tenure's last full extend
SUM_VAL = 2  # seconds of accumulated validation time


def acceptance_line(pubkey, weight, timeout, *, with_new_fields=True):
    """A 'Received block acceptance' line as emitted by signer.rs."""
    base = (
        "2026-07-29T12:09:26-04:00 obynuc stacks-signer[898823]: INFO "
        "[1785349520.362834] [stacks-signer/src/v0/signer.rs:2060] "
        "[signer_runloop:30000] Cycle #140 Dry-Run signer: Received block acceptance, "
        "signer_pubkey: %s, signer_signature_hash: %s, "
        "consensus_hash: %s, block_height: 8659818" % (pubkey, SIGHASH, "ea" * 20)
    )
    if not with_new_fields:
        return base
    return base + (
        ", signer_weight: %d, tenure_extend_timestamp: %d, "
        "tenure_extend_read_count_timestamp: %d"
        % (weight, REF + timeout + SUM_VAL, REF + 15 + SUM_VAL)
    )


def threshold_line(weight, approved):
    """The companion line that carries signature_weight but no pubkey."""
    return (
        "2026-07-29T12:09:26-04:00 obynuc stacks-signer[898823]: INFO "
        "[1785349520.362834] [stacks-signer/src/v0/signer.rs:2135] "
        "[signer_runloop:30000] Cycle #140 Dry-Run signer: Received block acceptance, "
        "but have not yet reached the acceptance threshold., signer_signature_hash: %s, "
        "signature_weight: %d, consensus_hash: %s, block_height: 8659818, "
        "total_weight_approved: %d, total_weight: %d, percent_approved: %f"
        % (SIGHASH, weight, "ea" * 20, approved, TOTAL_WEIGHT,
           approved / TOTAL_WEIGHT * 100.0)
    )


class TestExtendAggregate(unittest.TestCase):
    def _drive(self, *, with_new_fields=True):
        detector = Detector(DetectorConfig())
        parser = LogParser()
        approved = 0
        for pubkey, weight, timeout in SIGNERS:
            approved += weight
            for line in (
                acceptance_line(pubkey, weight, timeout,
                                with_new_fields=with_new_fields),
                threshold_line(weight, approved),
            ):
                for event in parser.parse_line("signer", line):
                    detector.process_event(event)
        return detector

    def test_signer_weights_are_attributed(self):
        """Regression: weight and pubkey must be joined from the same line."""
        detector = self._drive()
        snapshot = detector.snapshot(now=1785349520.0)
        by_key = {row["pubkey"]: row for row in snapshot["signers"]}
        for pubkey, weight, _ in SIGNERS:
            self.assertEqual(by_key[pubkey]["estimated_weight"], float(weight), pubkey)
            self.assertAlmostEqual(
                by_key[pubkey]["weight_percent_of_total"],
                weight / TOTAL_WEIGHT * 100.0,
                places=6,
            )
        self.assertEqual(snapshot["total_weight_estimate"], float(TOTAL_WEIGHT))

    def test_aggregate_follows_the_weighted_majority_not_the_local_signer(self):
        detector = self._drive()
        snapshot = detector.snapshot(now=1785349520.0)
        agg = snapshot["extend_aggregate"]

        # 70% of 3712, rounded up.
        self.assertEqual(agg["threshold_weight"], 2599)
        # The 30s cohort holds 2101 -- a majority, but short of the threshold, so
        # the aggregate must land in the 120s cohort.
        self.assertEqual(agg["short_weight"], 2101)
        self.assertEqual(agg["long_weight"], 1548)
        self.assertEqual(
            snapshot["tenure_extend_agg_eligible_ts"], REF + 120 + SUM_VAL
        )
        self.assertEqual(agg["shortfall_weight"], 2599 - 2101)
        self.assertAlmostEqual(agg["short_percent"], 2101 / TOTAL_WEIGHT * 100.0)

    def test_config_split_detects_the_two_cohorts(self):
        detector = self._drive()
        agg = detector.snapshot(now=1785349520.0)["extend_aggregate"]
        self.assertEqual(agg["gap_seconds"], 90)
        groups = {}
        for report in agg["reports"]:
            groups.setdefault(report["config_group"], set()).add(report["pubkey"])
        expected_short = {k for k, _, t in SIGNERS if t == 30}
        expected_long = {k for k, _, t in SIGNERS if t == 120}
        self.assertEqual(groups["short"], expected_short)
        self.assertEqual(groups["long"], expected_long)

    def test_converting_two_xverse_signers_crosses_the_threshold(self):
        """The actionable claim: no single conversion suffices, two do."""
        moved = {
            "02877ce29ba35458b827a6ea18510b9058ae4c30e2c33d288f2982c13497caec6e",
            "0302328212d5e430a8a880f8e2365a8f976ee50490ff030c106866c0b789eae91a",
        }
        detector = Detector(DetectorConfig())
        parser = LogParser()
        approved = 0
        for pubkey, weight, timeout in SIGNERS:
            approved += weight
            effective = 30 if pubkey in moved else timeout
            for line in (
                acceptance_line(pubkey, weight, effective),
                threshold_line(weight, approved),
            ):
                for event in parser.parse_line("signer", line):
                    detector.process_event(event)
        snapshot = detector.snapshot(now=1785349520.0)
        agg = snapshot["extend_aggregate"]
        self.assertEqual(agg["short_weight"], 2101 + 433 + 430)
        self.assertEqual(agg["shortfall_weight"], 0)
        # Aggregate now collapses to the short cohort's timestamp.
        self.assertEqual(
            snapshot["tenure_extend_agg_eligible_ts"], REF + 30 + SUM_VAL
        )

    def test_unpatched_signer_degrades_without_bogus_values(self):
        """Pre-patch signers emit no weight or timestamps; report nothing rather
        than inventing an aggregate."""
        detector = self._drive(with_new_fields=False)
        snapshot = detector.snapshot(now=1785349520.0)
        agg = snapshot["extend_aggregate"]
        self.assertIsNone(snapshot["tenure_extend_agg_eligible_ts"])
        self.assertEqual(agg["reports"], [])
        self.assertEqual(agg["short_weight"], 0)
        self.assertEqual(agg["long_weight"], 0)
        # total_weight still resolves from the threshold lines
        self.assertEqual(snapshot["total_weight_estimate"], float(TOTAL_WEIGHT))
        # and the signers are still listed, but weight reads as unknown (None)
        # rather than a misleading 0.0
        self.assertEqual(len(snapshot["signers"]), len(SIGNERS))
        for row in snapshot["signers"]:
            self.assertIsNone(row["estimated_weight"], row["pubkey"])
            self.assertIsNone(row["weight_percent_of_total"], row["pubkey"])

    def test_sentinel_timestamps_are_ignored(self):
        detector = Detector(DetectorConfig())
        parser = LogParser()
        pubkey, weight, _ = SIGNERS[0]
        line = acceptance_line(pubkey, weight, 30).replace(
            "tenure_extend_timestamp: %d" % (REF + 30 + SUM_VAL),
            "tenure_extend_timestamp: 18446744073709551615",
        )
        for event in parser.parse_line("signer", line):
            detector.process_event(event)
        snapshot = detector.snapshot(now=1785349520.0)
        self.assertIsNone(snapshot["tenure_extend_agg_eligible_ts"])
        self.assertEqual(snapshot["extend_aggregate"]["reports"], [])
        # the weight is still attributed even though the timestamp was a sentinel
        by_key = {row["pubkey"]: row for row in snapshot["signers"]}
        self.assertEqual(by_key[pubkey]["estimated_weight"], float(weight))


if __name__ == "__main__":
    unittest.main()
