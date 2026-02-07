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

    def test_parse_signer_block_rejection(self) -> None:
        parser = LogParser()
        line = (
            "Feb 06 04:37:44 host stacks-signer[1]: INFO [1770370664.324761] "
            "[stacks-signer/src/v0/signer.rs:1743] "
            "Received block rejection, signer_pubkey: 03abc, "
            "signer_signature_hash: f98fab, consensus_hash: da98, "
            "block_height: 6365169, reject_reason: NotLatestSortitionWinner, "
            "total_weight_rejected: 1273, total_weight: 3912, percent_rejected: 32.5"
        )

        events = parser.parse_line("signer", line)
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.kind, "signer_block_rejection")
        self.assertEqual(event.fields["signer_pubkey"], "03abc")
        self.assertEqual(event.fields["signer_signature_hash"], "f98fab")
        self.assertEqual(event.fields["block_height"], 6365169)
        self.assertEqual(event.fields["reject_reason"], "NotLatestSortitionWinner")
        self.assertEqual(event.fields["total_weight_rejected"], 1273)
        self.assertEqual(event.fields["total_weight"], 3912)
        self.assertAlmostEqual(event.fields["percent_rejected"], 32.5)

    def test_parse_signer_burn_block_event(self) -> None:
        parser = LogParser()
        line = (
            "Feb 06 04:37:47 host stacks-signer[1]: INFO [1770370667.167988] "
            "[stacks-signer/src/v0/signer.rs:616] "
            "Received a new burn block event for block height 935235"
        )

        events = parser.parse_line("signer", line)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].kind, "signer_burn_block_event")
        self.assertEqual(events[0].fields["burn_height"], 935235)

    def test_parse_signer_rejection_threshold_reached(self) -> None:
        parser = LogParser()
        line = (
            "Feb 06 04:37:44 host stacks-signer[1]: INFO [1770370664.324761] "
            "[stacks-signer/src/v0/signer.rs:1755] "
            "Received block rejection and have reached the rejection threshold, "
            "signer_pubkey: 03def, signer_signature_hash: f98fab, "
            "consensus_hash: da98, block_height: 6365169, "
            "reject_reason: NotLatestSortitionWinner, "
            "total_weight_rejected: 1273, total_weight: 3912, percent_rejected: 32.5"
        )

        events = parser.parse_line("signer", line)
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.kind, "signer_rejection_threshold_reached")
        self.assertEqual(event.fields["signer_pubkey"], "03def")
        self.assertEqual(event.fields["signer_signature_hash"], "f98fab")
        self.assertEqual(event.fields["block_height"], 6365169)
        self.assertEqual(event.fields["reject_reason"], "NotLatestSortitionWinner")
        self.assertEqual(event.fields["total_weight_rejected"], 1273)
        self.assertEqual(event.fields["total_weight"], 3912)
        self.assertAlmostEqual(event.fields["percent_rejected"], 32.5)

    def test_parse_node_winning_commit_and_tenure_events(self) -> None:
        parser = LogParser()
        winning_line = (
            "Feb 04 08:01:14 host stacks-node[1]: INFO [1770210074.818374] "
            "[stacks-node/src/nakamoto_node.rs:345] [main] "
            "Received burnchain block #934988 including block_commit_op (winning) - "
            "bc1qxlne4qmmgpc6rlrvrdyjprnay9q6ykg98gz2j3 "
            "(de3b7737fae28c2ca5375aea614a129a5e3d03c058c3ab0a8264b8bd7fc04418)"
        )
        tenure_notify_line = (
            "Feb 04 08:01:14 host stacks-node[1]: INFO [1770210074.818404] "
            "Tenure: Notify burn block!, "
            "consensus_hash: 700bcef8d93d6b0265ce558114613d85e60bb9da, "
            "burn_block_hash: 00000000000000000000d27894a9ffaf0be83201efbfce14ef2f00738ea7557a, "
            "winning_stacks_block_hash: de3b7737fae28c2ca5375aea614a129a5e3d03c058c3ab0a8264b8bd7fc04418, "
            "burn_block_height: 934988, sortition_id: abcdef"
        )
        tenure_change_line = (
            "Feb 04 08:01:38 host stacks-node[1]: INFO [1770210098.664609] "
            "[block-proposal] Include tx, tx: de87361bbfb8358f2401f96f6c52da86748854334c708e2c8696a19a1d2df269, "
            "payload: TenureChange(ExtendAll), origin: SPVYF6M3FD0738FWDGDMJ84EFMGM38JS0N7DE42K"
        )
        tenure_change_with_height_line = (
            "Feb 04 08:01:38 host stacks-node[1]: INFO [1770210098.664609] "
            "[block-proposal] Include tx, tx: de87361bbfb8358f2401f96f6c52da86748854334c708e2c8696a19a1d2df269, "
            "payload: TenureChange(ExtendAll), origin: SPVYF6M3FD0738FWDGDMJ84EFMGM38JS0N7DE42K, "
            "height: 6319949, burn_block_height: 934990"
        )
        consensus_line = (
            "Feb 04 08:01:05 host stacks-node[1]: INFO [1770210065.769302] "
            "CONSENSUS(934988): 700bcef8d93d6b0265ce558114613d85e60bb9da"
        )

        winning_events = parser.parse_line("node", winning_line)
        self.assertEqual(len(winning_events), 1)
        self.assertEqual(winning_events[0].kind, "node_winning_block_commit")
        self.assertEqual(winning_events[0].fields["burn_height"], 934988)
        self.assertEqual(
            winning_events[0].fields["apparent_sender"],
            "bc1qxlne4qmmgpc6rlrvrdyjprnay9q6ykg98gz2j3",
        )

        tenure_notify_events = parser.parse_line("node", tenure_notify_line)
        self.assertEqual(len(tenure_notify_events), 1)
        self.assertEqual(tenure_notify_events[0].kind, "node_tenure_notify")
        self.assertEqual(
            tenure_notify_events[0].fields["consensus_hash"],
            "700bcef8d93d6b0265ce558114613d85e60bb9da",
        )
        self.assertEqual(tenure_notify_events[0].fields["burn_height"], 934988)

        tenure_change_events = parser.parse_line("node", tenure_change_line)
        self.assertEqual(len(tenure_change_events), 1)
        self.assertEqual(tenure_change_events[0].kind, "node_tenure_change")
        self.assertEqual(
            tenure_change_events[0].fields["tenure_change_kind"], "ExtendAll"
        )
        self.assertEqual(
            tenure_change_events[0].fields["txid"],
            "de87361bbfb8358f2401f96f6c52da86748854334c708e2c8696a19a1d2df269",
        )
        self.assertIsNone(tenure_change_events[0].fields["block_height"])

        tenure_change_with_height_events = parser.parse_line(
            "node", tenure_change_with_height_line
        )
        self.assertEqual(len(tenure_change_with_height_events), 1)
        self.assertEqual(
            tenure_change_with_height_events[0].fields["block_height"], 6319949
        )
        self.assertEqual(
            tenure_change_with_height_events[0].fields["burn_height"], 934990
        )

        consensus_events = parser.parse_line("node", consensus_line)
        self.assertEqual(len(consensus_events), 1)
        self.assertEqual(consensus_events[0].kind, "node_consensus")
        self.assertEqual(
            consensus_events[0].fields["consensus_hash"],
            "700bcef8d93d6b0265ce558114613d85e60bb9da",
        )
        self.assertEqual(consensus_events[0].fields["burn_height"], 934988)

    def test_parse_sortition_commits_and_active_miner_update(self) -> None:
        parser = LogParser()
        commit_line = (
            "Feb 04 08:01:05 host stacks-node[1]: INFO [1770210065.757652] "
            "ACCEPTED(934988) leader block commit "
            "e0e8e9eb9315bbd3710887cc907059e10a9e7f000918465f65070d9756f99757 "
            "at 934988,710, apparent_sender: bc1qxlne4qmmgpc6rlrvrdyjprnay9q6ykg98gz2j3, "
            "stacks_block_hash: de3b7737fae28c2ca5375aea614a129a5e3d03c058c3ab0a8264b8bd7fc04418, "
            "parent_burn_block: 934987"
        )
        winner_line = (
            "Feb 04 08:01:05 host stacks-node[1]: INFO [1770210065.697281] "
            "SORTITION(934988): WINNER SELECTED, "
            "txid: e0e8e9eb9315bbd3710887cc907059e10a9e7f000918465f65070d9756f99757, "
            "stacks_block_hash: de3b7737fae28c2ca5375aea614a129a5e3d03c058c3ab0a8264b8bd7fc04418, "
            "burn_block_hash: 00000000000000000000d27894a9ffaf0be83201efbfce14ef2f00738ea7557a"
        )
        active_line = (
            "Feb 04 08:01:04 host stacks-signer[1]: INFO [1770210064.146379] "
            "Received state machine update from signer ... "
            "content: V1 { burn_block: 700bcef8d93d6b0265ce558114613d85e60bb9da, "
            "burn_block_height: 934988, current_miner: ActiveMiner { "
            "current_miner_pkh: 37e79a837b4071a1fc6c1b49208e7d2141a25905, "
            "tenure_id: 700bcef8d93d6b0265ce558114613d85e60bb9da, "
            "parent_tenure_id: 0e95ff3f705c6061c82ace32890ee88c39fa4f69, "
            "parent_tenure_last_block: 1a9bcc747b54bf37c7a911e87887b827ff7574b96b6e1ddae1d9ef6e5ec5e939, "
            "parent_tenure_last_block_height: 6319944 } }"
        )

        commit_events = parser.parse_line("node", commit_line)
        self.assertEqual(len(commit_events), 1)
        self.assertEqual(commit_events[0].kind, "node_leader_block_commit")
        self.assertEqual(commit_events[0].fields["burn_height"], 934988)
        self.assertEqual(commit_events[0].fields["sortition_position"], 710)
        self.assertEqual(
            commit_events[0].fields["commit_txid"],
            "e0e8e9eb9315bbd3710887cc907059e10a9e7f000918465f65070d9756f99757",
        )

        winner_events = parser.parse_line("node", winner_line)
        self.assertEqual(len(winner_events), 1)
        self.assertEqual(winner_events[0].kind, "node_sortition_winner_selected")
        self.assertEqual(winner_events[0].fields["burn_height"], 934988)

        active_events = parser.parse_line("signer", active_line)
        self.assertEqual(len(active_events), 1)
        self.assertEqual(active_events[0].kind, "signer_state_machine_update")
        self.assertEqual(active_events[0].fields["burn_height"], 934988)
        self.assertEqual(
            active_events[0].fields["current_miner_pkh"],
            "37e79a837b4071a1fc6c1b49208e7d2141a25905",
        )
        self.assertEqual(
            active_events[0].fields["parent_tenure_last_block_height"], 6319944
        )

    def test_parse_sortition_winner_rejected(self) -> None:
        parser = LogParser()
        line = (
            "Feb 04 07:38:15 host stacks-node[1]: INFO [1770208695.571152] "
            "SORTITION(934983): WINNER REJECTED: "
            "\"Null miner defeats block winner due to insufficient commit carryover\", "
            "txid: 35c140e1dc254ab7e761a1951093b369e34d279c52c9493b81584fb688a7d3e8, "
            "stacks_block_hash: 7ae1f7fdffa89eea936f7bb9982abdd5a63dd7dd4f5ff50e8b0076d3a50edf34, "
            "burn_block_hash: 00000000000000000001bbfb10185b1894cd597b14450b197e2bb04b48c22eee"
        )

        events = parser.parse_line("node", line)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].kind, "node_sortition_winner_rejected")
        self.assertEqual(events[0].fields["burn_height"], 934983)
        self.assertEqual(
            events[0].fields["rejection_reason"],
            "Null miner defeats block winner due to insufficient commit carryover",
        )
        self.assertEqual(
            events[0].fields["rejected_txid"],
            "35c140e1dc254ab7e761a1951093b369e34d279c52c9493b81584fb688a7d3e8",
        )

    def test_parse_node_mined_nakamoto_block_execution_costs(self) -> None:
        parser = LogParser()
        line = (
            "Feb 07 13:20:25 obynuc stacks-node[224726]: INFO [1770488425.029337] "
            "[stackslib/src/chainstate/nakamoto/miner.rs:772] "
            "Miner: mined Nakamoto block, stacks_block_hash: 608678ea, "
            "stacks_block_id: 1b49e4a0, height: 6398580, tx_count: 4, "
            "parent_block_id: 57a70a04, block_size: 897, "
            'execution_consumed: {"runtime": 312966534, "write_len": 309422, '
            '"write_cnt": 2876, "read_len": 83413180, "read_cnt": 219}, '
            "percent_full: 83, assembly_time_ms: 475, consensus_hash: 6cd01af5"
        )

        events = parser.parse_line("node", line)
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.kind, "node_mined_nakamoto_block")
        self.assertEqual(event.fields["block_height"], 6398580)
        self.assertEqual(event.fields["tx_count"], 4)
        self.assertEqual(event.fields["percent_full"], 83)
        self.assertEqual(event.fields["runtime"], 312966534)
        self.assertEqual(event.fields["write_len"], 309422)
        self.assertEqual(event.fields["write_cnt"], 2876)
        self.assertEqual(event.fields["read_len"], 83413180)
        self.assertEqual(event.fields["read_cnt"], 219)


if __name__ == "__main__":
    unittest.main()
