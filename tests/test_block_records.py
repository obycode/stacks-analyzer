import os
import tempfile
import unittest

from stacks_analyzer.detector import EXECUTION_COST_LIMITS, Detector, DetectorConfig
from stacks_analyzer.events import LogParser, ParsedEvent
from stacks_analyzer.history import HistoryStore
from stacks_analyzer.service import MonitoringService

CONSENSUS_A = "aa" * 20
CONSENSUS_B = "bb" * 20


def validated(ts, block_hash, height, costs, tx_count=2, fees=1000, size=500, validation_ms=40):
    fields = {
        "block_header_hash": block_hash,
        "block_height": height,
        "tx_count": tx_count,
        "tx_fees_microstacks": fees,
        "block_size": size,
        "validation_time_ms": validation_ms,
        "is_validation_request": False,
        "is_validated": True,
    }
    fields.update(costs)
    return ParsedEvent(source="node", kind="node_block_proposal", ts=ts, fields=fields)


def tip(ts, block_hash, consensus_hash):
    return ParsedEvent(
        source="node",
        kind="node_tip_advanced",
        ts=ts,
        fields={"block_header_hash": block_hash, "consensus_hash": consensus_hash},
    )


def consensus(ts, burn_height, consensus_hash):
    return ParsedEvent(
        source="node",
        kind="node_consensus",
        ts=ts,
        fields={"burn_height": burn_height, "consensus_hash": consensus_hash},
    )


def costs(runtime, write_len=100, write_cnt=10, read_len=1000, read_cnt=10):
    return {
        "runtime": runtime,
        "write_len": write_len,
        "write_cnt": write_cnt,
        "read_len": read_len,
        "read_cnt": read_cnt,
    }


def record(detector, ts, block_hash, height, cost, consensus_hash, **kwargs):
    detector.process_event(validated(ts, block_hash, height, cost, **kwargs))
    detector.process_event(tip(ts + 0.5, block_hash, consensus_hash))


class TestDetectorBlockRecords(unittest.TestCase):
    def test_confirmed_block_record_has_usage_and_increment(self) -> None:
        detector = Detector(DetectorConfig())
        detector.process_event(consensus(1.0, 900, CONSENSUS_A))
        record(detector, 10.0, "h1", 100, costs(1_000_000_000, read_len=50_000_000), CONSENSUS_A)
        record(detector, 20.0, "h2", 101, costs(1_500_000_000, read_len=80_000_000), CONSENSUS_A, size=800)

        records = detector.drain_block_records()
        self.assertEqual([r["block_height"] for r in records], [100, 101])
        self.assertEqual(detector.drain_block_records(), [])

        first, second = records
        self.assertEqual(first["burn_height"], 900)
        self.assertEqual(first["tip_burn_height"], 900)
        self.assertEqual(first["block_header_hash"], "h1")
        self.assertEqual(first["consensus_hash"], CONSENSUS_A)
        self.assertEqual(first["block_size"], 500)
        self.assertEqual(first["validation_time_ms"], 40)
        self.assertEqual(first["tx_fees_microstacks"], 1000)
        # read_len 50M of 100M is the largest dimension
        self.assertAlmostEqual(first["percent_full"], 50.0, places=2)
        # first block ever seen: no previous height to diff against
        self.assertIsNone(first["costs_delta"])
        self.assertIsNone(first["budget_reset"])

        self.assertAlmostEqual(second["percent_full"], 80.0, places=2)
        self.assertEqual(second["block_size"], 800)
        self.assertFalse(second["budget_reset"])
        self.assertEqual(second["costs_delta"]["runtime"], 500_000_000)
        self.assertEqual(second["costs_delta"]["read_len"], 30_000_000)
        self.assertEqual(second["costs_delta"]["write_len"], 0)
        self.assertAlmostEqual(second["costs_delta_percent"]["runtime"], 10.0, places=2)
        self.assertAlmostEqual(second["costs_delta_percent"]["read_len"], 30.0, places=2)

        snapshot = detector.snapshot(now=30.0)
        self.assertEqual(len(snapshot["recent_execution_costs"]), 2)
        self.assertEqual(snapshot["recent_execution_costs"][-1]["burn_height"], 900)
        self.assertAlmostEqual(snapshot["latest_execution_cost_percent_full"], 80.0, places=2)

    def test_budget_reset_when_costs_drop_or_tenure_changes(self) -> None:
        detector = Detector(DetectorConfig())
        detector.process_event(consensus(1.0, 900, CONSENSUS_A))
        record(detector, 10.0, "h1", 100, costs(2_000_000_000), CONSENSUS_A)
        # Tenure extend mid-tenure: same consensus hash, costs fall back.
        record(detector, 20.0, "h2", 101, costs(300_000_000), CONSENSUS_A)
        # New tenure at the next Bitcoin block.
        detector.process_event(consensus(25.0, 901, CONSENSUS_B))
        record(detector, 30.0, "h3", 102, costs(400_000_000), CONSENSUS_B)
        # Gap in observed heights: increment unknown.
        record(detector, 40.0, "h5", 104, costs(600_000_000), CONSENSUS_B)

        records = {r["block_height"]: r for r in detector.drain_block_records()}
        extend = records[101]
        self.assertTrue(extend["budget_reset"])
        self.assertEqual(extend["costs_delta"], extend["costs"])
        self.assertEqual(extend["costs_delta"]["runtime"], 300_000_000)

        new_tenure = records[102]
        self.assertTrue(new_tenure["budget_reset"])
        self.assertEqual(new_tenure["burn_height"], 901)
        self.assertEqual(new_tenure["costs_delta"]["runtime"], 400_000_000)

        gap = records[104]
        self.assertIsNone(gap["costs_delta"])
        self.assertIsNone(gap["budget_reset"])
        self.assertEqual(gap["burn_height"], 901)

    def test_tip_burn_height_kept_when_tenure_unmapped(self) -> None:
        detector = Detector(DetectorConfig())
        detector.process_event(
            ParsedEvent(
                source="signer",
                kind="signer_burn_block_event",
                ts=1.0,
                fields={"burn_height": 950},
            )
        )
        record(detector, 10.0, "h1", 100, costs(1_000), "cc" * 20)
        (only,) = detector.drain_block_records()
        self.assertIsNone(only["burn_height"])
        self.assertEqual(only["tip_burn_height"], 950)

    def test_real_log_lines_produce_record(self) -> None:
        parser = LogParser()
        detector = Detector(DetectorConfig())
        lines = [
            "Feb 07 13:20:20 obynuc stacks-node[224726]: INFO [1770488420.000000] "
            "[stackslib/src/chainstate/burn/db/processing.rs:218] [chains-coordinator:20443] "
            "CONSENSUS(935000): 6cd01af58983661e71c4e6671ff2f2c3982cb24b",
            "Feb 07 13:20:25 obynuc stacks-node[224726]: INFO [1770488425.556168] "
            "[stackslib/src/net/api/postblock_proposal.rs:692] [block-proposal] Participant: validated anchored block, "
            "block_header_hash: 59313766771f5415b98944dcbebbd70d4f544c4c15b57873001f7022802fe824, height: 6398581, "
            "tx_count: 2, parent_stacks_block_id: fe72b407730dfe87b5af1e439fb1ccb2feee0458ae8f9c2e48c724b7f7686a80, "
            'block_size: 419, execution_cost: {"runtime": 312966534, "write_len": 309422, "write_cnt": 2876, '
            '"read_len": 83413180, "read_cnt": 219}, validation_time_ms: 55, tx_fees_microstacks: 6580',
            "Feb 07 13:20:27 obynuc stacks-node[224726]: INFO [1770488427.193742] "
            "[stackslib/src/chainstate/nakamoto/mod.rs:2160] [chains-coordinator:20443] Advanced to new tip! "
            "6cd01af58983661e71c4e6671ff2f2c3982cb24b/59313766771f5415b98944dcbebbd70d4f544c4c15b57873001f7022802fe824",
        ]
        for line in lines:
            for event in parser.parse_line("node", line):
                detector.process_event(event)
        (rec,) = detector.drain_block_records()
        self.assertEqual(rec["block_height"], 6398581)
        self.assertEqual(rec["burn_height"], 935000)
        self.assertEqual(rec["block_size"], 419)
        self.assertEqual(rec["validation_time_ms"], 55)
        self.assertEqual(rec["tx_fees_microstacks"], 6580)
        self.assertEqual(rec["costs"]["read_len"], 83413180)
        self.assertAlmostEqual(rec["percent_full"], 83.41, places=2)


class TestHistoryStoreBlocks(unittest.TestCase):
    def setUp(self) -> None:
        handle = tempfile.NamedTemporaryFile(delete=False)
        handle.close()
        self.db_path = handle.name
        self.store = HistoryStore(path=self.db_path, retention_hours=48, block_retention_days=30)

    def tearDown(self) -> None:
        self.store.close()
        try:
            os.unlink(self.db_path)
        except OSError:
            pass

    def _record(self, height, burn, ts, runtime=1_000_000, tip_burn=None, delta=None, reset=None, hash_=None):
        self.store.record_block(
            {
                "ts": ts,
                "block_height": height,
                "burn_height": burn,
                "tip_burn_height": tip_burn if tip_burn is not None else burn,
                "consensus_hash": "cc" * 20,
                "block_header_hash": hash_ or ("h%d" % height),
                "tx_count": 3,
                "tx_fees_microstacks": 1500,
                "block_size": 640,
                "validation_time_ms": 12,
                "percent_full": 12.5,
                "budget_reset": reset,
                "costs": {"runtime": runtime, "write_len": 10, "write_cnt": 1, "read_len": 100, "read_cnt": 1},
                "costs_percent": {},
                "costs_delta": delta,
                "costs_delta_percent": None,
            }
        )

    def test_record_and_lookup_by_height_and_burn(self) -> None:
        self._record(100, 900, 1000.0)
        self._record(101, 900, 1010.0, delta={"runtime": 5, "write_len": 0, "write_cnt": 0, "read_len": 0, "read_cnt": 0}, reset=False)
        self._record(102, 901, 1020.0, reset=True)
        self._record(103, 901, 1030.0, tip_burn=902)

        by_height = self.store.query_blocks(height=101)
        self.assertEqual(len(by_height), 1)
        row = by_height[0]
        self.assertEqual(row["block_header_hash"], "h101")
        self.assertEqual(row["burn_height"], 900)
        self.assertEqual(row["tip_burn_height"], 900)
        self.assertEqual(row["tx_count"], 3)
        self.assertEqual(row["block_size"], 640)
        self.assertEqual(row["validation_time_ms"], 12)
        self.assertEqual(row["costs"]["runtime"], 1_000_000)
        self.assertAlmostEqual(
            row["costs_percent"]["runtime"],
            1_000_000 / EXECUTION_COST_LIMITS["runtime"] * 100.0,
        )
        self.assertEqual(row["costs_delta"]["runtime"], 5)
        self.assertAlmostEqual(row["costs_delta_percent"]["runtime"], 5 / EXECUTION_COST_LIMITS["runtime"] * 100.0)
        self.assertFalse(row["budget_reset"])
        self.assertEqual(row["percent_full"], 12.5)

        self.assertIsNone(self.store.query_blocks(height=100)[0]["costs_delta"])
        self.assertIsNone(self.store.query_blocks(height=100)[0]["budget_reset"])
        self.assertTrue(self.store.query_blocks(height=102)[0]["budget_reset"])

        self.assertEqual([r["block_height"] for r in self.store.query_blocks(burn_height=900)], [101, 100])
        # 903 was the Bitcoin tip when block 103 was confirmed, so it is found there too
        self.assertEqual([r["block_height"] for r in self.store.query_blocks(burn_height=902)], [103])
        self.assertEqual([r["block_height"] for r in self.store.query_blocks(burn_height=901)], [103, 102])
        self.assertEqual(self.store.query_blocks(height=999), [])

    def test_paging_and_bounds(self) -> None:
        for height in range(100, 110):
            self._record(height, 900 + (height - 100) // 5, 1000.0 + height)
        latest = self.store.query_blocks(limit=3)
        self.assertEqual([r["block_height"] for r in latest], [109, 108, 107])
        older = self.store.query_blocks(before_height=107, limit=3)
        self.assertEqual([r["block_height"] for r in older], [106, 105, 104])
        newer = self.store.query_blocks(after_height=104, limit=3)
        self.assertEqual([r["block_height"] for r in newer], [107, 106, 105])
        bounds = self.store.block_bounds()
        self.assertEqual(bounds["count"], 10)
        self.assertEqual(bounds["min_height"], 100)
        self.assertEqual(bounds["max_height"], 109)
        self.assertEqual(bounds["min_burn_height"], 900)
        self.assertEqual(bounds["max_burn_height"], 901)

    def test_reobserved_block_updates_in_place(self) -> None:
        self._record(100, None, 1000.0, runtime=5)
        self._record(100, 900, 1001.0, runtime=7)
        rows = self.store.query_blocks(height=100)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["costs"]["runtime"], 7)
        self.assertEqual(rows[0]["burn_height"], 900)
        # a sibling at the same height keeps its own row
        self._record(100, 900, 1002.0, hash_="fork")
        self.assertEqual(len(self.store.query_blocks(height=100)), 2)

    def test_block_retention_is_separate_from_event_retention(self) -> None:
        old_ts = 1_000_000.0
        self._record(100, 900, old_ts)
        self.store.record_event(ts=old_ts, source="node", kind="node_consensus", data={}, line="x")
        # events prune at 48h, blocks at 30 days
        now = old_ts + 3 * 86400
        self.store._last_prune_ts = 0.0
        self.store.record_event(ts=now, source="node", kind="node_consensus", data={}, line="y")
        self.assertEqual(len(self.store.query_events(limit=10)), 1)
        self.assertEqual(self.store.block_bounds()["count"], 1)
        now = old_ts + 31 * 86400
        self.store._last_prune_ts = 0.0
        self.store.record_event(ts=now, source="node", kind="node_consensus", data={}, line="z")
        self.assertEqual(self.store.block_bounds()["count"], 0)

    def test_schema_lists_blocks_table(self) -> None:
        schema = self.store.schema()
        self.assertIn("blocks", schema)
        self.assertIn("tip_burn_height", schema["blocks"])


class TestServiceBlocksApi(unittest.TestCase):
    def setUp(self) -> None:
        handle = tempfile.NamedTemporaryFile(delete=False)
        handle.close()
        self.db_path = handle.name
        self.store = HistoryStore(path=self.db_path, retention_hours=48)
        self.service = MonitoringService.__new__(MonitoringService)
        self.service.history_store = self.store
        self.service._state_now = lambda: 2000.0

    def tearDown(self) -> None:
        self.store.close()
        try:
            os.unlink(self.db_path)
        except OSError:
            pass

    def _seed(self) -> None:
        for height in range(100, 105):
            self.store.record_block(
                {
                    "ts": 1000.0 + height,
                    "block_height": height,
                    "burn_height": 900 if height < 103 else 901,
                    "tip_burn_height": 900 if height < 103 else 901,
                    "block_header_hash": "h%d" % height,
                    "costs": {"runtime": 10 * height},
                }
            )

    def test_blocks_api_reads_history(self) -> None:
        self._seed()
        payload = self.service._blocks_api({"limit": ["2"]})
        self.assertEqual(payload["source"], "history")
        self.assertEqual([b["block_height"] for b in payload["blocks"]], [104, 103])
        self.assertEqual(payload["bounds"]["count"], 5)
        self.assertEqual(payload["query"]["limit"], 2)
        self.assertEqual(payload["execution_cost_limits"], EXECUTION_COST_LIMITS)

        by_burn = self.service._blocks_api({"burn_height": ["901"]})
        self.assertEqual([b["block_height"] for b in by_burn["blocks"]], [104, 103])
        by_height = self.service._blocks_api({"height": ["101"]})
        self.assertEqual([b["block_height"] for b in by_height["blocks"]], [101])
        older = self.service._blocks_api({"before": ["102"], "limit": ["1"]})
        self.assertEqual([b["block_height"] for b in older["blocks"]], [101])
        bad = self.service._blocks_api({"height": ["nope"], "limit": ["99999"]})
        self.assertEqual(bad["query"]["height"], None)
        self.assertEqual(bad["query"]["limit"], 500)

    def test_blocks_api_falls_back_to_memory_without_history(self) -> None:
        import threading

        service = MonitoringService.__new__(MonitoringService)
        service.history_store = None
        service.state_lock = threading.Lock()
        service.detector = Detector(DetectorConfig())
        service.detector.process_event(consensus(1.0, 900, CONSENSUS_A))
        record(service.detector, 10.0, "h1", 100, costs(1_000), CONSENSUS_A)
        record(service.detector, 20.0, "h2", 101, costs(2_000), CONSENSUS_A)
        service.detector.process_event(consensus(25.0, 901, CONSENSUS_B))
        record(service.detector, 30.0, "h3", 102, costs(3_000), CONSENSUS_B)

        payload = service._blocks_api({})
        self.assertEqual(payload["source"], "memory")
        self.assertEqual([b["block_height"] for b in payload["blocks"]], [102, 101, 100])
        self.assertEqual(payload["bounds"]["count"], 3)
        self.assertEqual(payload["bounds"]["max_burn_height"], 901)
        self.assertEqual(
            [b["block_height"] for b in service._blocks_api({"burn_height": ["900"]})["blocks"]],
            [101, 100],
        )
        self.assertEqual(
            [b["block_height"] for b in service._blocks_api({"height": ["101"]})["blocks"]],
            [101],
        )
        self.assertEqual(
            [b["block_height"] for b in service._blocks_api({"before": ["102"], "limit": ["1"]})["blocks"]],
            [101],
        )
        self.assertEqual(
            [b["block_height"] for b in service._blocks_api({"after": ["100"], "limit": ["1"]})["blocks"]],
            [101],
        )

    def test_persist_block_records_drains_detector(self) -> None:
        import threading

        self.service.state_lock = threading.Lock()
        self.service.detector = Detector(DetectorConfig())
        record(self.service.detector, 10.0, "h1", 100, costs(1_000), CONSENSUS_A)
        self.service._persist_block_records()
        self.assertEqual(self.service.detector.drain_block_records(), [])
        self.assertEqual(self.store.block_bounds()["count"], 1)
        self.assertEqual(self.store.query_blocks(height=100)[0]["block_header_hash"], "h1")


if __name__ == "__main__":
    unittest.main()
