import unittest

from stacks_analyzer.events import LogParser


class TestLogParser(unittest.TestCase):
    def test_sample_logs_produce_expected_events(self) -> None:
        parser = LogParser()
        counts = {}

        with open("sample_logs/node.log", "r", encoding="utf-8") as handle:
            for line in handle:
                for event in parser.parse_line("node", line):
                    counts[event.kind] = counts.get(event.kind, 0) + 1

        with open("sample_logs/signer.log", "r", encoding="utf-8") as handle:
            for line in handle:
                for event in parser.parse_line("signer", line):
                    counts[event.kind] = counts.get(event.kind, 0) + 1

        self.assertGreater(counts.get("node_tip_advanced", 0), 0)
        self.assertGreater(counts.get("node_stale_chunk", 0), 0)
        self.assertGreater(counts.get("signer_block_proposal", 0), 0)
        self.assertGreater(counts.get("signer_block_acceptance", 0), 0)
        self.assertGreater(counts.get("signer_threshold_reached", 0), 0)
        self.assertGreater(counts.get("signer_block_pushed", 0), 0)

    def test_parse_signer_new_block_event(self) -> None:
        parser = LogParser()
        line = (
            "Feb 04 08:01:00 host stacks-signer[123]: INFO [1770210060.111] "
            "[stacks-signer/src/v0/signer.rs:571] "
            "Received a new block event. "
            "block_id: 1111222233334444, block_height: 6319925, "
            "signer_signature_hash: aabbccddeeff00112233"
        )

        events = parser.parse_line("signer", line)
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.kind, "signer_new_block_event")
        self.assertEqual(event.fields["block_id"], "1111222233334444")
        self.assertEqual(event.fields["block_height"], 6319925)
        self.assertEqual(
            event.fields["signer_signature_hash"], "aabbccddeeff00112233"
        )


if __name__ == "__main__":
    unittest.main()
