# AI Tooling Guide (History API)

This project exposes read‑only APIs and a SQLite history database that are safe to use by external AIs (e.g., GPT‑5.2) for investigations. The recommended integration is:

1) Use the HTTP endpoints as tools.
2) Use the SQL endpoint for advanced aggregations (optional; disabled by default).

## Endpoints

Base URL: `http://<host>:<port>`

### `GET /api/history`
Query stored historical events.

Parameters:
- `from`: epoch seconds (float)
- `to`: epoch seconds (float)
- `kind`: event kind (repeatable)
- `limit`: max rows (default 200)

Response:
```json
{
  "events": [
    { "id": 1, "ts": 1738831120.1, "source": "node", "kind": "node_consensus", "data": {...}, "line": "..." }
  ]
}
```

### `GET /api/alerts`
Query stored alerts.

Parameters:
- `from`, `to` (epoch seconds)
- `severity` (repeatable): `info|warning|critical`
- `limit`

Response:
```json
{
  "alerts": [
    { "id": 12, "ts": 1738831120.1, "severity": "critical", "key": "...", "message": "...", "report_id": 5 }
  ]
}
```

### `GET /api/reports`
List reports.

Parameters:
- `from`, `to`
- `severity`
- `limit`

Response:
```json
{
  "reports": [
    { "id": 5, "ts": 1738831120.1, "severity": "critical", "alert_key": "node-stall", "summary": "..." }
  ]
}
```

### `GET /api/report?id=<id>`
Fetch a report payload (includes snapshot + recent events + recent alerts).

### `GET /api/report-logs?id=<id>`
Download journalctl logs around the report timestamp (journalctl mode only).

Optional overrides:
- `before` seconds (default 600)
- `after` seconds (default 300)

## Optional SQL API (disabled by default)

Enable in config:
```json
"history": {
  "enable_sql_api": true,
  "sql_api_max_rows": 500
}
```

### `POST /api/sql`
Body:
```json
{ "sql": "SELECT ... LIMIT 100" }
```

Rules:
- Only `SELECT` is allowed
- Destructive keywords are blocked
- A `LIMIT` is enforced

Response:
```json
{ "sql": "...", "columns": ["col1","col2"], "rows": [[...],[...]] }
```

## Database Schema (summary)

Primary tables:
- `events(ts, source, kind, data, line)`
- `alerts(ts, severity, key, message, report_id)`
- `reports(ts, severity, alert_key, summary, data)`
- `sortitions(ts, burn_height, winner_txid, winning_stacks_block_hash, null_miner_won, event_kind)`

Notes:
- `data` fields are JSON strings with extra details.
- For null miner frequency, use the `sortitions` table with `null_miner_won=1`.

## Schema Endpoint

### `GET /api/schema`
Returns the current SQLite schema (table -> columns map).

## Example Queries

### Null miner frequency
```sql
SELECT
  SUM(CASE WHEN null_miner_won = 1 THEN 1 ELSE 0 END) AS null_count,
  COUNT(*) AS total_count,
  ROUND(100.0 * SUM(CASE WHEN null_miner_won = 1 THEN 1 ELSE 0 END) / COUNT(*), 2) AS pct,
  MIN(ts) AS start_ts,
  MAX(ts) AS end_ts
FROM sortitions;
```

### Last read‑count extend before a given block height
```sql
SELECT ts, data
FROM events
WHERE kind = 'node_tenure_change'
  AND data LIKE '%extend%'
  AND data LIKE '%read%'
ORDER BY ts DESC
LIMIT 50;
```

## Tool Suggestions for AI

Use these as tools in your AI system:

- `history_query(from, to, kind[], limit)`
- `alerts_query(from, to, severity[], limit)`
- `reports_list(from, to, severity[], limit)`
- `report_get(id)`
- `sql_query(sql)` (optional; only if enabled)

Prefer `sql_query` for aggregations and `history_query` for event lookups.
