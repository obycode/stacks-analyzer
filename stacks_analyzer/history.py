import json
import sqlite3
import threading
import time
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


class HistoryStore:
    def __init__(
        self,
        path: str,
        retention_hours: int = 48,
        report_context_seconds: int = 180,
        report_context_limit: int = 200,
    ) -> None:
        self.path = path
        self.retention_seconds = int(retention_hours) * 3600
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
        if self.retention_seconds <= 0:
            return
        if now_ts - self._last_prune_ts < 300:
            return
        cutoff = float(now_ts) - float(self.retention_seconds)
        with self._lock:
            self._conn.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
            self._conn.execute("DELETE FROM alerts WHERE ts < ?", (cutoff,))
            self._conn.execute("DELETE FROM reports WHERE ts < ?", (cutoff,))
            self._conn.commit()
        self._last_prune_ts = now_ts


def should_store_event(kind: str, fields: Dict[str, Any]) -> bool:
    if kind in {
        "node_leader_block_commit",
        "node_sortition_winner_selected",
        "node_sortition_winner_rejected",
        "node_consensus",
        "node_winning_block_commit",
        "signer_state_machine_update",
        "signer_block_proposal",
        "signer_block_acceptance",
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
