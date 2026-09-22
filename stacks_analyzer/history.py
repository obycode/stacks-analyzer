import json
import sqlite3
import threading
import time
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .detector import EXECUTION_COST_LIMITS

COST_KEYS = ("runtime", "write_len", "write_cnt", "read_len", "read_cnt")


class HistoryStore:
    def __init__(
        self,
        path: str,
        retention_hours: int = 48,
        report_context_seconds: int = 180,
        report_context_limit: int = 200,
        block_retention_days: int = 5,
    ) -> None:
        self.path = path
        self.retention_seconds = int(retention_hours) * 3600
        # Blocks are compact and are what the /blocks page pages through, so
        # they outlive the raw event log; 0 keeps them forever.
        self.block_retention_seconds = max(0, int(block_retention_days)) * 86400
        self.report_context_seconds = report_context_seconds
        self.report_context_limit = report_context_limit
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._init_schema()
        self._last_prune_ts: float = 0.0

    def _init_schema(self) -> None:
        with self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL NOT NULL,
                    source TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    data TEXT,
                    line TEXT
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL NOT NULL,
                    severity TEXT NOT NULL,
                    key TEXT NOT NULL,
                    message TEXT NOT NULL,
                    report_id INTEGER
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL NOT NULL,
                    severity TEXT NOT NULL,
                    alert_key TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    data TEXT
                )
                """
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_kind_ts ON events(kind, ts)"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts)"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_reports_ts ON reports(ts)"
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sortitions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL NOT NULL,
                    burn_height INTEGER,
                    winner_txid TEXT,
                    winning_stacks_block_hash TEXT,
                    null_miner_won INTEGER NOT NULL DEFAULT 0,
                    event_kind TEXT
                )
                """
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_sortitions_ts ON sortitions(ts)"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_sortitions_null ON sortitions(null_miner_won)"
            )
            # One row per confirmed Stacks block: the tenure budget consumed
            # through that block (runtime..read_cnt, as the node logs it) plus
            # the block's own increment (d_*), NULL when the previous height was
            # not observed. block_header_hash is the identity so a re-observed
            # block updates in place and forks at one height keep both rows.
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS blocks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL NOT NULL,
                    block_height INTEGER,
                    burn_height INTEGER,
                    tip_burn_height INTEGER,
                    consensus_hash TEXT,
                    block_header_hash TEXT NOT NULL UNIQUE,
                    tx_count INTEGER,
                    tx_fees_microstacks INTEGER,
                    block_size INTEGER,
                    validation_time_ms INTEGER,
                    percent_full REAL,
                    budget_reset INTEGER,
                    runtime INTEGER,
                    write_len INTEGER,
                    write_cnt INTEGER,
                    read_len INTEGER,
                    read_cnt INTEGER,
                    d_runtime INTEGER,
                    d_write_len INTEGER,
                    d_write_cnt INTEGER,
                    d_read_len INTEGER,
                    d_read_cnt INTEGER
                )
                """
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_blocks_height ON blocks(block_height)"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_blocks_burn ON blocks(burn_height)"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_blocks_tip_burn ON blocks(tip_burn_height)"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_blocks_ts ON blocks(ts)"
            )

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def record_event(
        self,
        ts: float,
        source: str,
        kind: str,
        data: Dict[str, Any],
        line: Optional[str],
    ) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO events (ts, source, kind, data, line) VALUES (?, ?, ?, ?, ?)",
                (
                    float(ts),
                    source,
                    kind,
                    json.dumps(data, sort_keys=True) if data else None,
                    line,
                ),
            )
            self._conn.commit()
        self._maybe_prune(ts)

    def record_alert(
        self,
        ts: float,
        severity: str,
        key: str,
        message: str,
        report_id: Optional[int] = None,
    ) -> int:
        with self._lock:
            cursor = self._conn.execute(
                "INSERT INTO alerts (ts, severity, key, message, report_id) VALUES (?, ?, ?, ?, ?)",
                (float(ts), severity, key, message, report_id),
            )
            self._conn.commit()
            alert_id = int(cursor.lastrowid)
        self._maybe_prune(ts)
        return alert_id

    def attach_report(self, alert_id: int, report_id: int) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE alerts SET report_id = ? WHERE id = ?",
                (report_id, alert_id),
            )
            self._conn.commit()

    def create_report(
        self,
        ts: float,
        severity: str,
        alert_key: str,
        summary: str,
        data: Dict[str, Any],
    ) -> int:
        with self._lock:
            cursor = self._conn.execute(
                "INSERT INTO reports (ts, severity, alert_key, summary, data) VALUES (?, ?, ?, ?, ?)",
                (float(ts), severity, alert_key, summary, json.dumps(data, sort_keys=True)),
            )
            self._conn.commit()
            report_id = int(cursor.lastrowid)
        self._maybe_prune(ts)
        return report_id

    def record_sortition(
        self,
        ts: float,
        burn_height: Optional[int],
        winner_txid: Optional[str],
        winning_stacks_block_hash: Optional[str],
        null_miner_won: bool,
        event_kind: str,
    ) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO sortitions (
                    ts, burn_height, winner_txid, winning_stacks_block_hash, null_miner_won, event_kind
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    float(ts),
                    int(burn_height) if isinstance(burn_height, int) else None,
                    winner_txid,
                    winning_stacks_block_hash,
                    1 if null_miner_won else 0,
                    event_kind,
                ),
            )
            self._conn.commit()
        self._maybe_prune(ts)

    def record_block(self, record: Dict[str, Any]) -> None:
        """Upsert one confirmed block record as built by Detector._build_block_record."""
        block_header_hash = record.get("block_header_hash")
        if not isinstance(block_header_hash, str) or not block_header_hash:
            return
        costs = record.get("costs") if isinstance(record.get("costs"), dict) else {}
        delta = (
            record.get("costs_delta")
            if isinstance(record.get("costs_delta"), dict)
            else {}
        )

        def opt_int(value: Any) -> Optional[int]:
            return int(value) if isinstance(value, int) and not isinstance(value, bool) else None

        budget_reset = record.get("budget_reset")
        ts = record.get("ts")
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO blocks (
                    ts, block_height, burn_height, tip_burn_height, consensus_hash,
                    block_header_hash,
                    tx_count, tx_fees_microstacks, block_size, validation_time_ms,
                    percent_full, budget_reset,
                    runtime, write_len, write_cnt, read_len, read_cnt,
                    d_runtime, d_write_len, d_write_cnt, d_read_len, d_read_cnt
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(block_header_hash) DO UPDATE SET
                    ts = excluded.ts,
                    block_height = excluded.block_height,
                    burn_height = COALESCE(excluded.burn_height, blocks.burn_height),
                    tip_burn_height = COALESCE(excluded.tip_burn_height, blocks.tip_burn_height),
                    consensus_hash = COALESCE(excluded.consensus_hash, blocks.consensus_hash),
                    tx_count = excluded.tx_count,
                    tx_fees_microstacks = excluded.tx_fees_microstacks,
                    block_size = excluded.block_size,
                    validation_time_ms = excluded.validation_time_ms,
                    percent_full = excluded.percent_full,
                    budget_reset = COALESCE(excluded.budget_reset, blocks.budget_reset),
                    runtime = excluded.runtime,
                    write_len = excluded.write_len,
                    write_cnt = excluded.write_cnt,
                    read_len = excluded.read_len,
                    read_cnt = excluded.read_cnt,
                    d_runtime = COALESCE(excluded.d_runtime, blocks.d_runtime),
                    d_write_len = COALESCE(excluded.d_write_len, blocks.d_write_len),
                    d_write_cnt = COALESCE(excluded.d_write_cnt, blocks.d_write_cnt),
                    d_read_len = COALESCE(excluded.d_read_len, blocks.d_read_len),
                    d_read_cnt = COALESCE(excluded.d_read_cnt, blocks.d_read_cnt)
                """,
                (
                    float(ts) if isinstance(ts, (int, float)) else time.time(),
                    opt_int(record.get("block_height")),
                    opt_int(record.get("burn_height")),
                    opt_int(record.get("tip_burn_height")),
                    record.get("consensus_hash")
                    if isinstance(record.get("consensus_hash"), str)
                    else None,
                    block_header_hash,
                    opt_int(record.get("tx_count")),
                    opt_int(record.get("tx_fees_microstacks")),
                    opt_int(record.get("block_size")),
                    opt_int(record.get("validation_time_ms")),
                    float(record["percent_full"])
                    if isinstance(record.get("percent_full"), (int, float))
                    else None,
                    None if budget_reset is None else (1 if budget_reset else 0),
                )
                + tuple(opt_int(costs.get(key)) for key in COST_KEYS)
                + tuple(opt_int(delta.get(key)) for key in COST_KEYS),
            )
            self._conn.commit()
        if isinstance(ts, (int, float)):
            self._maybe_prune(float(ts))

    _BLOCK_COLUMNS = (
        "id, ts, block_height, burn_height, tip_burn_height, consensus_hash, "
        "block_header_hash, "
        "tx_count, tx_fees_microstacks, block_size, validation_time_ms, "
        "percent_full, budget_reset, "
        "runtime, write_len, write_cnt, read_len, read_cnt, "
        "d_runtime, d_write_len, d_write_cnt, d_read_len, d_read_cnt"
    )

    @staticmethod
    def _percent_of_limits(values: Dict[str, int]) -> Dict[str, float]:
        output: Dict[str, float] = {}
        for key, value in values.items():
            limit = EXECUTION_COST_LIMITS.get(key)
            if limit:
                output[key] = max(0.0, min(100.0, (float(value) / float(limit)) * 100.0))
        return output

    @classmethod
    def _row_to_block(cls, row: Sequence[Any]) -> Dict[str, Any]:
        cost_offset = 13
        delta_offset = cost_offset + len(COST_KEYS)
        costs = {
            key: row[cost_offset + index]
            for index, key in enumerate(COST_KEYS)
            if isinstance(row[cost_offset + index], int)
        }
        delta_values = [row[delta_offset + index] for index in range(len(COST_KEYS))]
        delta: Optional[Dict[str, int]] = None
        if any(isinstance(value, int) for value in delta_values):
            delta = {
                key: value
                for key, value in zip(COST_KEYS, delta_values)
                if isinstance(value, int)
            }
        budget_reset = row[12]
        return {
            "id": row[0],
            "ts": row[1],
            "block_height": row[2],
            "burn_height": row[3],
            "tip_burn_height": row[4],
            "consensus_hash": row[5],
            "block_header_hash": row[6],
            "tx_count": row[7],
            "tx_fees_microstacks": row[8],
            "block_size": row[9],
            "validation_time_ms": row[10],
            "percent_full": row[11],
            "budget_reset": None if budget_reset is None else bool(budget_reset),
            "costs": costs,
            "costs_percent": cls._percent_of_limits(costs),
            "costs_delta": delta,
            "costs_delta_percent": cls._percent_of_limits(delta) if delta else None,
        }

    def query_blocks(
        self,
        height: Optional[int] = None,
        burn_height: Optional[int] = None,
        before_height: Optional[int] = None,
        after_height: Optional[int] = None,
        from_ts: Optional[float] = None,
        to_ts: Optional[float] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Confirmed blocks, newest height first.

        `height` is an exact match. `burn_height` matches blocks whose tenure
        was won at that Bitcoin height or that were confirmed while it was the
        Bitcoin tip, so an extended tenure's later blocks are found under the
        Bitcoin block they actually landed in as well. `before_height` pages toward
        older blocks and `after_height` toward newer ones; the result is always
        ordered by descending height.
        """
        clauses: List[str] = []
        params: List[Any] = []
        if height is not None:
            clauses.append("block_height = ?")
            params.append(int(height))
        if burn_height is not None:
            clauses.append("(burn_height = ? OR tip_burn_height = ?)")
            params.extend([int(burn_height), int(burn_height)])
        if before_height is not None:
            clauses.append("block_height < ?")
            params.append(int(before_height))
        if after_height is not None:
            clauses.append("block_height > ?")
            params.append(int(after_height))
        if from_ts is not None:
            clauses.append("ts >= ?")
            params.append(float(from_ts))
        if to_ts is not None:
            clauses.append("ts <= ?")
            params.append(float(to_ts))
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        ascending = after_height is not None and before_height is None
        order = "ASC" if ascending else "DESC"
        sql = (
            "SELECT " + self._BLOCK_COLUMNS + " FROM blocks" + where
            + " ORDER BY block_height %s, ts %s LIMIT ?" % (order, order)
        )
        params.append(max(1, int(limit)))
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        if ascending:
            rows = list(reversed(rows))
        return [self._row_to_block(row) for row in rows]

    def block_bounds(self) -> Dict[str, Any]:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*), MIN(block_height), MAX(block_height), "
                "MIN(COALESCE(burn_height, tip_burn_height)), "
                "MAX(COALESCE(tip_burn_height, burn_height)), MIN(ts), MAX(ts) FROM blocks"
            ).fetchone()
        return {
            "count": int(row[0] or 0),
            "min_height": row[1],
            "max_height": row[2],
            "min_burn_height": row[3],
            "max_burn_height": row[4],
            "min_ts": row[5],
            "max_ts": row[6],
        }

    def query_events(
        self,
        from_ts: Optional[float] = None,
        to_ts: Optional[float] = None,
        kinds: Optional[Sequence[str]] = None,
        limit: int = 200,
    ) -> List[Dict[str, Any]]:
        clauses: List[str] = []
        params: List[Any] = []
        if from_ts is not None:
            clauses.append("ts >= ?")
            params.append(float(from_ts))
        if to_ts is not None:
            clauses.append("ts <= ?")
            params.append(float(to_ts))
        if kinds:
            placeholders = ",".join("?" for _ in kinds)
            clauses.append("kind IN (%s)" % placeholders)
            params.extend(list(kinds))
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        sql = (
            "SELECT id, ts, source, kind, data, line FROM events"
            + where
            + " ORDER BY ts DESC LIMIT ?"
        )
        params.append(int(limit))
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        output: List[Dict[str, Any]] = []
        for row in rows:
            data = row[4]
            output.append(
                {
                    "id": row[0],
                    "ts": row[1],
                    "source": row[2],
                    "kind": row[3],
                    "data": json.loads(data) if data else None,
                    "line": row[5],
                }
            )
        return output

    def query_alerts(
        self,
        from_ts: Optional[float] = None,
        to_ts: Optional[float] = None,
        severities: Optional[Sequence[str]] = None,
        limit: int = 200,
    ) -> List[Dict[str, Any]]:
        clauses: List[str] = []
        params: List[Any] = []
        if from_ts is not None:
            clauses.append("ts >= ?")
            params.append(float(from_ts))
        if to_ts is not None:
            clauses.append("ts <= ?")
            params.append(float(to_ts))
        if severities:
            placeholders = ",".join("?" for _ in severities)
            clauses.append("severity IN (%s)" % placeholders)
            params.extend(list(severities))
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        sql = (
            "SELECT id, ts, severity, key, message, report_id FROM alerts"
            + where
            + " ORDER BY ts DESC LIMIT ?"
        )
        params.append(int(limit))
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [
            {
                "id": row[0],
                "ts": row[1],
                "severity": row[2],
                "key": row[3],
                "message": row[4],
                "report_id": row[5],
            }
            for row in rows
        ]

    def list_reports(
        self,
        from_ts: Optional[float] = None,
        to_ts: Optional[float] = None,
        severities: Optional[Sequence[str]] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        clauses: List[str] = []
        params: List[Any] = []
        if from_ts is not None:
            clauses.append("ts >= ?")
            params.append(float(from_ts))
        if to_ts is not None:
            clauses.append("ts <= ?")
            params.append(float(to_ts))
        if severities:
            placeholders = ",".join("?" for _ in severities)
            clauses.append("severity IN (%s)" % placeholders)
            params.extend(list(severities))
        where = " WHERE " + " AND ".join(clauses) if clauses else ""
        sql = (
            "SELECT id, ts, severity, alert_key, summary FROM reports"
            + where
            + " ORDER BY ts DESC LIMIT ?"
        )
        params.append(int(limit))
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [
            {
                "id": row[0],
                "ts": row[1],
                "severity": row[2],
                "alert_key": row[3],
                "summary": row[4],
            }
            for row in rows
        ]

    def get_report(self, report_id: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT id, ts, severity, alert_key, summary, data FROM reports WHERE id = ?",
                (int(report_id),),
            ).fetchone()
        if row is None:
            return None
        payload = json.loads(row[5]) if row[5] else None
        return {
            "id": row[0],
            "ts": row[1],
            "severity": row[2],
            "alert_key": row[3],
            "summary": row[4],
            "data": payload,
        }

    def report_context_events(self, ts: float) -> List[Dict[str, Any]]:
        start = float(ts) - float(self.report_context_seconds)
        end = float(ts) + 5.0
        return self.query_events(from_ts=start, to_ts=end, limit=self.report_context_limit)

    def schema(self) -> Dict[str, List[str]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            ).fetchall()
            tables = [row[0] for row in rows if isinstance(row[0], str)]
            output: Dict[str, List[str]] = {}
            for table in tables:
                columns = self._conn.execute(
                    "PRAGMA table_info(%s)" % table
                ).fetchall()
                output[table] = [col[1] for col in columns if len(col) > 1]
        return output

    def query_sql(self, sql: str, max_rows: int) -> Tuple[List[str], List[List[Any]]]:
        with self._lock:
            cursor = self._conn.execute(sql)
            columns = [desc[0] for desc in cursor.description or []]
            rows = cursor.fetchmany(max_rows)
        return columns, rows

    def _maybe_prune(self, now_ts: float) -> None:
        if self.retention_seconds <= 0 and self.block_retention_seconds <= 0:
            return
        if now_ts - self._last_prune_ts < 300:
            return
        cutoff = float(now_ts) - float(self.retention_seconds)
        with self._lock:
            if self.retention_seconds > 0:
                self._conn.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
                self._conn.execute("DELETE FROM alerts WHERE ts < ?", (cutoff,))
                self._conn.execute("DELETE FROM reports WHERE ts < ?", (cutoff,))
            if self.block_retention_seconds > 0:
                block_cutoff = float(now_ts) - float(self.block_retention_seconds)
                self._conn.execute("DELETE FROM blocks WHERE ts < ?", (block_cutoff,))
            self._conn.commit()
        self._last_prune_ts = now_ts


def should_store_event(kind: str, fields: Dict[str, Any]) -> bool:
    if kind in {
        "node_mempool_iteration",
        "node_mined_nakamoto_block",
        "node_leader_block_commit",
        "node_sortition_winner_selected",
        "node_sortition_winner_rejected",
        "node_consensus",
        "node_burnchain_reorg",
        "node_winning_block_commit",
        "signer_state_machine_update",
        "signer_block_proposal",
        "signer_block_validation_submitted",
        "signer_pending_block_validation_waiting_parent",
        "signer_pending_block_validation_found",
        "signer_block_acceptance",
        "signer_block_pre_commit",
        "signer_block_pre_commit_unknown",
        "signer_block_pre_commit_sent",
        "signer_block_rejection",
        "signer_rejection_threshold_reached",
        "signer_threshold_reached",
        "signer_block_pushed",
        "signer_new_block_event",
    }:
        return True
    if kind == "node_tenure_change":
        change_kind = fields.get("tenure_change_kind")
        if isinstance(change_kind, str) and "extend" in change_kind.lower():
            return True
        return False
    if kind == "signer_block_response":
        reject_reason = fields.get("reject_reason")
        if isinstance(reject_reason, str) and reject_reason and reject_reason != "NotRejected":
            return True
        return False
    return False
