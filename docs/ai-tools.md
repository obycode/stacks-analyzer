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

### `GET /api/blocks`
Confirmed Stacks blocks with their execution budget usage, newest first.

Parameters (all optional):
- `height`: exact Stacks block height
- `burn_height`: Bitcoin height; matches blocks whose tenure was won there or
  that were confirmed while it was the Bitcoin tip
- `before` / `after`: Stacks height cursors for paging
- `limit`: max rows (default 50, max 500)

Response:
```json
{
  "blocks": [
    {
      "ts": 1770488427.19, "block_height": 6398581, "burn_height": 935000,
      "tip_burn_height": 935000, "consensus_hash": "...", "block_header_hash": "...",
      "tx_count": 2, "tx_fees_microstacks": 6580, "block_size": 419, "validation_time_ms": 55,
      "percent_full": 83.41, "budget_reset": false,
      "costs": {"runtime": 312966534, "write_len": 309422, "write_cnt": 2876, "read_len": 83413180, "read_cnt": 219},
      "costs_percent": {"runtime": 6.26, "...": 0},
      "costs_delta": {"runtime": 512874, "...": 0},
      "costs_delta_percent": {"runtime": 0.01, "...": 0}
    }
  ],
  "bounds": {"count": 1234, "min_height": 6390000, "max_height": 6398581, "min_burn_height": 934900, "max_burn_height": 935000},
  "query": {"height": null, "burn_height": null, "before": null, "after": null, "limit": 50},
  "source": "history",
  "execution_cost_limits": {"runtime": 5000000000, "write_len": 15000000, "write_cnt": 15000, "read_len": 100000000, "read_cnt": 15000}
}
```

`costs` is the tenure budget consumed through the block (what the node logs),
`costs_delta` is the block's own increment (`null` when the previous height was
not observed), and `budget_reset` marks the first block after a tenure change
or extend. `source` is `memory` when history is disabled.

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
- `blocks(ts, block_height, burn_height, tip_burn_height, consensus_hash, block_header_hash, tx_count, tx_fees_microstacks, block_size, validation_time_ms, percent_full, budget_reset, runtime, write_len, write_cnt, read_len, read_cnt, d_runtime, d_write_len, d_write_cnt, d_read_len, d_read_cnt)`

Notes:
- `data` fields are JSON strings with extra details.
- For null miner frequency, use the `sortitions` table with `null_miner_won=1`.
- `blocks` keeps one row per confirmed block for `history.block_retention_days`
  (default 5) rather than the 48h event retention; `runtime..read_cnt` are the
  tenure budget consumed through the block and `d_*` the block's own increment.

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

### Fullest blocks in the last day
```sql
SELECT block_height, burn_height, tx_count, percent_full, d_runtime, d_read_len
FROM blocks
WHERE ts > strftime('%s', 'now') - 86400
ORDER BY percent_full DESC
LIMIT 20;
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
- `blocks_query(height, burn_height, before, after, limit)`
- `sql_query(sql)` (optional; only if enabled)

Prefer `sql_query` for aggregations and `history_query` for event lookups.
