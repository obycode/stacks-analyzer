import unittest

from stacks_analyzer.detector import Detector, DetectorConfig
from stacks_analyzer.events import LogParser

# Real mainnet burn heights: 935298-935301 ran as winner, winner, no commits at
# all, winner (see sample_logs/proposal-timeout-boundary.log), and 934983 is the
# null-miner win from sample_logs/null-miner.node.log.
BURN_HASH = "00000000000000000000d27894a9ffaf0be83201efbfce14ef2f00738ea7557a"
NULL_REASON = "Null miner defeats block winner due to insufficient commit carryover"


def node_line(epoch, module, message):
    return (
        "2026-02-06T15:01:47-05:00 obynuc stacks-node[11924]: INFO "
        "[%.6f] [%s] [chains-coordinator:20443] %s" % (epoch, module, message)
    )


def commit_line(epoch, burn_height, txid, sender, position, burn_fee=None):
    """An 'ACCEPTED(height) leader block commit' line from sortdb.rs.

    burn_fee is only present on node builds that log it; the field is optional
    here for the same reason it is optional in the parser.
    """
    message = (
        "ACCEPTED(%d) leader block commit %s at %d,%d, apparent_sender: %s, "
        "stacks_block_hash: %s, parent_burn_block: %d"
        % (burn_height, txid, burn_height, position, sender, "bb" * 32, burn_height - 1)
    )
    if burn_fee is not None:
        message += ", burn_fee: %d" % burn_fee
    return node_line(epoch, "stackslib/src/chainstate/burn/db/sortdb.rs:5500", message)


def winner_line(epoch, burn_height, txid):
    return node_line(
        epoch,
        "stackslib/src/chainstate/burn/sortition.rs:727",
        "SORTITION(%d): WINNER SELECTED, txid: %s, stacks_block_hash: %s, "
        "burn_block_hash: %s" % (burn_height, txid, "bb" * 32, BURN_HASH),
    )


def rejected_line(epoch, burn_height, txid):
    return node_line(
        epoch,
        "stackslib/src/chainstate/burn/sortition.rs:692",
        'SORTITION(%d): WINNER REJECTED: "%s", txid: %s, stacks_block_hash: %s, '
        "burn_block_hash: %s" % (burn_height, NULL_REASON, txid, "bb" * 32, BURN_HASH),
    )


def consensus_line(epoch, burn_height):
    return node_line(
        epoch,
        "stackslib/src/chainstate/burn/db/processing.rs:218",
        "CONSENSUS(%d): %s" % (burn_height, "df504e7da2b716f2da7303ee3749ceab958e2f4f"),
    )


class TestBurnBlockStats(unittest.TestCase):
    def _run(self, lines):
        parser = LogParser()
        detector = Detector(
            DetectorConfig(alert_cooldown_seconds=0, report_interval_seconds=99999)
        )
        for line in lines:
            detector.process_line("node")
            for event in parser.parse_line("node", line):
                detector.process_event(event)
        return detector

    def _mixed_run(self):
        base = 1770408000.0
        lines = [
            # 935297: the first burn block we see. Its commits may predate our
            # log window, so it is deliberately left out of the stats.
            consensus_line(base, 935297),
            # 935298: three commits, real winner.
            winner_line(base + 10, 935298, "aa" * 32),
            commit_line(base + 11, 935298, "aa" * 32, "bc1qwinner", 1203, burn_fee=20000),
            commit_line(base + 12, 935298, "cc" * 32, "bc1qloser", 1245, burn_fee=21000),
            commit_line(base + 13, 935298, "dd" * 32, "12H9Dtpm", 1250, burn_fee=19000),
            consensus_line(base + 14, 935298),
            # 935299: two commits, null miner wins anyway.
            rejected_line(base + 20, 935299, "ee" * 32),
            commit_line(base + 21, 935299, "ee" * 32, "bc1qwinner", 1203, burn_fee=15000),
            commit_line(base + 22, 935299, "ff" * 32, "bc1qloser", 1245, burn_fee=17000),
            consensus_line(base + 23, 935299),
            # 935300: nobody spent any BTC, so the node logs no sortition at all.
            consensus_line(base + 30, 935300),
            # 935301: single commit, real winner.
            winner_line(base + 40, 935301, "ab" * 32),
            commit_line(base + 41, 935301, "ab" * 32, "bc1qwinner", 1203, burn_fee=22000),
            consensus_line(base + 42, 935301),
        ]
        return self._run(lines)

    def test_outcomes_split_the_two_no_coinbase_causes(self) -> None:
        stats = self._mixed_run().snapshot(now=1770408100.0)["burn_block_stats"]

        self.assertEqual(stats["rounds_rated"], 4)
        self.assertEqual(stats["with_coinbase"], 2)
        self.assertEqual(stats["no_coinbase"], 2)
        self.assertEqual(stats["null_with_commits"], 1)
        self.assertEqual(stats["null_no_commits"], 1)
        self.assertEqual(stats["rounds_unresolved"], 0)
        self.assertAlmostEqual(stats["no_coinbase_percent"], 50.0)
        # Contested rounds are the three with commits; the null miner took one.
        self.assertAlmostEqual(stats["null_win_percent_of_contested"], 100.0 / 3.0)
        # Only the real null-miner win contributes a reason; the no-commits
        # burn block gets boilerplate from the node and is left out.
        self.assertEqual(stats["null_reason_counts"], {NULL_REASON: 1})

    def test_sats_and_commits_wasted_per_null_win(self) -> None:
        stats = self._mixed_run().snapshot(now=1770408100.0)["burn_block_stats"]

        self.assertEqual(stats["sats_total"], 20000 + 21000 + 19000 + 15000 + 17000 + 22000)
        self.assertEqual(stats["sats_wasted"], 15000 + 17000)
        self.assertAlmostEqual(stats["sats_per_null_win"], 32000.0)
        self.assertAlmostEqual(stats["sats_per_coinbase"], (20000 + 21000 + 19000 + 22000) / 2.0)
        self.assertEqual(stats["commits_wasted"], 2)
        self.assertAlmostEqual(stats["commits_per_null_win"], 2.0)

    def test_commit_totals_survive_commits_logged_after_the_sortition(self) -> None:
        """The node logs SORTITION before the ACCEPTED commit lines, so a null
        round is first seen with zero commits and must be re-tallied when they
        arrive - otherwise it lands in the no-commits bucket forever."""
        detector = self._mixed_run()

        # One amendment per commit line, and no double counting.
        self.assertEqual(detector.burn_outcome_counts["null_no_commits"], 1)
        self.assertEqual(detector.burn_outcome_counts["null_with_commits"], 1)
        self.assertEqual(detector.burn_outcome_commit_counts["winner"], 4)

    def test_ledger_marks_each_burn_block_for_the_strip(self) -> None:
        ledger = self._mixed_run().snapshot(now=1770408100.0)["burn_block_ledger"]
        by_height = {row["burn_height"]: row for row in ledger}

        self.assertEqual([row["burn_height"] for row in ledger], sorted(by_height))
        self.assertTrue(by_height[935297]["partial_window"])
        self.assertEqual(by_height[935298]["outcome"], "winner")
        self.assertEqual(by_height[935298]["winner_apparent_sender"], "bc1qwinner")
        self.assertEqual(by_height[935299]["outcome"], "null_with_commits")
        self.assertEqual(by_height[935299]["commit_count"], 2)
        self.assertEqual(by_height[935299]["burn_fee_sats"], 32000)
        self.assertEqual(by_height[935299]["null_reason"], NULL_REASON)
        self.assertEqual(by_height[935300]["outcome"], "null_no_commits")
        self.assertEqual(by_height[935300]["commit_count"], 0)

    def test_burn_blocks_since_coinbase_counts_the_dry_spell(self) -> None:
        base = 1770408000.0
        detector = self._run(
            [
                consensus_line(base, 935297),
                winner_line(base + 10, 935298, "aa" * 32),
                commit_line(base + 11, 935298, "aa" * 32, "bc1qwinner", 1203),
                consensus_line(base + 12, 935298),
                consensus_line(base + 20, 935299),
                consensus_line(base + 30, 935300),
            ]
        )
        stats = detector.snapshot(now=1770408100.0)["burn_block_stats"]

        self.assertEqual(stats["burn_blocks_since_coinbase"], 2)
        # No burn_fee on these commits, so the sats metrics stay absent rather
        # than reporting a misleading zero.
        self.assertIsNone(stats["sats_per_coinbase"])
        self.assertIsNone(stats["sats_per_null_win"])

    def test_first_burn_block_counts_when_its_outcome_was_logged(self) -> None:
        """Excluding the first burn block only guards against commits that
        predate the log window; a sortition winner for it is proof the window
        covered it, so it must still count."""
        base = 1770408000.0
        detector = self._run(
            [
                winner_line(base, 935298, "aa" * 32),
                commit_line(base + 1, 935298, "aa" * 32, "bc1qwinner", 1203),
                consensus_line(base + 2, 935298),
                consensus_line(base + 10, 935299),
            ]
        )
        stats = detector.snapshot(now=1770408100.0)["burn_block_stats"]
        ledger = {
            row["burn_height"]: row
            for row in detector.snapshot(now=1770408100.0)["burn_block_ledger"]
        }

        self.assertEqual(stats["with_coinbase"], 1)
        self.assertEqual(stats["null_no_commits"], 1)
        self.assertEqual(stats["rounds_rated"], 2)
        self.assertFalse(ledger[935298]["partial_window"])

    def test_commits_without_a_sortition_line_are_not_null_wins(self) -> None:
        """A log window that shows commits but no outcome is a gap in what we
        saw, not a null-miner win, so it stays out of the rates."""
        base = 1770408000.0
        detector = self._run(
            [
                consensus_line(base, 935297),
                commit_line(base + 10, 935298, "aa" * 32, "bc1qwinner", 1203),
                consensus_line(base + 11, 935298),
            ]
        )
        stats = detector.snapshot(now=1770408100.0)["burn_block_stats"]

        self.assertEqual(stats["rounds_unresolved"], 1)
        self.assertEqual(stats["rounds_rated"], 0)
        self.assertEqual(stats["no_coinbase"], 0)
        self.assertIsNone(stats["no_coinbase_percent"])

    def test_null_miner_sample_log_is_counted_as_a_null_win(self) -> None:
        parser = LogParser()
        detector = Detector(
            DetectorConfig(alert_cooldown_seconds=0, report_interval_seconds=99999)
        )
        with open("sample_logs/null-miner.node.log", "r", encoding="utf-8") as handle:
            for line in handle:
                detector.process_line("node")
                for event in parser.parse_line("node", line):
                    detector.process_event(event)
        stats = detector.snapshot()["burn_block_stats"]

        self.assertGreaterEqual(stats["null_with_commits"], 1)
        self.assertIn(NULL_REASON, stats["null_reason_counts"])


if __name__ == "__main__":
    unittest.main()
