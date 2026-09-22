# stacks-analyzer

Service for continuous `stacks-node` + signer log analysis with:

- Anomaly detection (node stalls, signer stalls, proposal timeout issues, large signer participation drops).
- Rolling network state reports.
- Telegram alerts (and optional periodic report delivery).
- Built-in web dashboard for live visualization.

## Quick Start

Use the included sample logs:

```bash
python3 -m stacks_analyzer \
  --mode files \
  --node-log-path sample_logs/node.log \
  --signer-log-path sample_logs/signer.log \
  --web-enable \
  --web-port 8787 \
  --from-beginning \
  --report-interval-seconds 30
```

Open `http://127.0.0.1:8787`.

Use a config file:

```bash
cp config.example.json config.json
python3 -m stacks_analyzer --config config.json
```

## Real-Time Monitoring

### Option A: Follow flat files

```bash
python3 -m stacks_analyzer \
  --mode files \
  --node-log-path /var/log/stacks/node.log \
  --signer-log-path /var/log/stacks/signer.log \
  --web-enable
```

### Option B: Follow systemd journals

```bash
python3 -m stacks_analyzer \
  --mode journalctl \
  --node-journal-unit stacks-node \
  --signer-journal-unit stacks-signer \
  --web-enable
```

## Dashboard

When enabled, the dashboard serves:

- `GET /`: interactive UI
- `GET /blocks`: block browser (fullness of recent blocks, lookup by Stacks or
  Bitcoin height)
- `GET /api/state`: raw JSON state
- `GET /api/blocks`: confirmed blocks with budget usage (see Block Fullness)
- `GET /healthz`: health probe
- Recent proposals table (latest 5, with copyable signature hashes and in-progress/approved/rejected status highlighting).
- Recent Blocks strip: each tenure bracket lists every Bitcoin block it covered
  on the left - the one whose sortition it won (⛏) plus each later one that
  produced no coinbase (∅), tagged with the tenure extend that carried the
  tenure through it. Hover a row for the commit count, sats burned, and reason.
- No-coinbase rail beside the strip: share of Bitcoin blocks that produced no
  coinbase, split into null-miner wins and blocks nobody committed to, plus the
  BTC burned per null-miner win (`burn_block_stats` in `/api/state`). Burn
  amounts come from `burn_fee` on accepted block commits, the same source as the
  sortition cards; the rail falls back to commits per null win on node builds
  that omit the field.
- Block Fullness card: the latest 12 confirmed blocks, one row each, with how
  much of the tenure's execution budget had been used through that block (bar,
  largest dimension), what the block itself added, five mini bars for the
  individual dimensions (runtime, write length/count, read length/count), tx
  count, fees, size, and a marker where the budget was reset by a tenure change
  or extend. Hover a row for the full breakdown. See Block Fullness below.
- Visual sortition view for the latest 3 burn heights.
- Each burn-height card shows all captured block commits, the committed stacks block target, and winner highlighting (or null-miner outcome).
- Tenure extends table shows the latest 5 extend events with extend kind, Stacks block height, burn height, and txid.
- Existing operational panels remain: uptime/age metrics, alerts, signer participation, and counters.
- Null-miner sortitions are detected (`WINNER REJECTED` / zero winning hash).

CLI flags:

- `--web-enable`
- `--web-host 127.0.0.1`
- `--web-port 8787`

## Block Fullness

The node logs an execution cost for every block it validates
(`Participant: validated anchored block ... execution_cost: {...}`). In
Nakamoto that figure is the tenure budget consumed so far, this block included:
it climbs across a tenure and drops back to the block's own cost when a tenure
change or a tenure extend resets the budget. The analyzer records that reading
for every block that goes on to advance the tip, together with:

- `percent_full`: the largest dimension's share of the block limit, the same
  figure the miner logs as `percent_full` on mined blocks.
- `costs_delta`: what the block alone added, derived from the previous
  confirmed height when it was observed (`null` otherwise), and `budget_reset`
  when the block started a fresh budget.
- `burn_height`: the Bitcoin block whose sortition started the tenure, and
  `tip_burn_height`: the Bitcoin tip when the block was confirmed. These
  differ once a tenure has been extended across later Bitcoin blocks, and only
  the latter is known for tenures that began before the analyzer started.
- tx count, fees, block size and validation time from the same log line.

With history enabled, every record is stored in the `blocks` table of the
history database and kept for `history.block_retention_days` (default 5,
0 keeps them forever), independent of the 48h event retention. The `/blocks`
page browses them newest first and looks up a single Stacks height or every
block confirmed under a Bitcoin height (matched on either burn height above);
the dashboard's Block Fullness card links each height there. Without history
the page falls back to the in-memory window of the last 720 blocks.

`GET /api/blocks` takes `height`, `burn_height`, `before`, `after` (Stacks
heights) and `limit` (default 50, max 500) and returns
`{"blocks": [...], "bounds": {...}, "query": {...}, "source": "history"|"memory",
"execution_cost_limits": {...}}` with blocks newest first.

## Run As systemd Service

Use `deploy/stacks-analyzer.service.example` as a template:

```bash
sudo cp deploy/stacks-analyzer.service.example /etc/systemd/system/stacks-analyzer.service
sudo systemctl daemon-reload
sudo systemctl enable --now stacks-analyzer
```

## Telegram Alerts

```bash
python3 -m stacks_analyzer \
  --mode files \
  --node-log-path /var/log/stacks/node.log \
  --signer-log-path /var/log/stacks/signer.log \
  --telegram-token "<bot_token>" \
  --telegram-chat-id "<chat_id>"
```

Add `--telegram-send-reports` to send periodic reports to Telegram in addition to alerts.
Telegram alert delivery is severity-based:
- `info`
- `warning`
- `critical`

By default, Telegram receives only `critical` alerts. Configure minimum severity with:
- CLI: `--telegram-min-alert-severity warning`
- Config: `"telegram": { "min_alert_severity": "warning" }`

## Signer Name Mapping

Provide a JSON map of signer pubkey to friendly name:

```bash
python3 -m stacks_analyzer \
  --mode files \
  --node-log-path sample_logs/node.log \
  --signer-log-path sample_logs/signer.log \
  --signer-names-path signer_names.example.json \
  --web-enable
```

You can also set `"signer_names_path"` in `config.json`. Names will appear in:

- Signers table in the dashboard
- Signer-related alerts (for example large signer participation alerts)

## Key Detection Rules

- `node_stall_seconds`: no `Advanced to new tip!` within threshold.
- `signer_stall_seconds`: no signer block proposal within threshold.
- `proposal_timeout_seconds`: proposal has no threshold signal in time.
- large signer participation: for estimated heavy signers, participation drops below configured ratio.

Notes:

- Stale chunk logs are tracked as context in reports/dashboard, but do not trigger anomalies.
- A pushed block observed before local threshold visibility is no longer treated as misbehavior.
- `Received a new block event.` is treated as proposal closure (same closure effect as `Got block pushed message`).
- When replaying historical file logs (`--mode files --from-beginning`), timing checks run on replay time to avoid false timeout alerts from old timestamps.
- Open proposals are now kept closed after a pushed block, even if additional late threshold/acceptance lines arrive for the same signature hash.

## Stall Diagnostics

Every node or signer stall gets a diagnostics entry describing the shape of
the stall, built from what the logs had said up to that moment:

- Where in the tenure it sits: start of a tenure (a new sortition winner has
  produced no block) or mid-tenure (blocks so far, tenure age), plus any burn
  blocks that arrived after the last Stacks block and their outcomes.
- Who should have been mining: the latest sortition winner and the burn height
  it won, alongside the signer's own view of the active miner.
- The last confirmed Stacks block height and the Bitcoin height before the
  stall, with how long before detection each was seen.
- Whether the node logged a Bitcoin reorg, and whether two Bitcoin blocks
  arrived within `flash_block_seconds` (default 60) of each other.
- Whether the mempool had ready transactions at its last sample.
- Open proposals and the pipeline phase each is stuck in, recent rejections,
  pre-commits that arrived before their proposal, the last tenure extend and
  whether the network was already willing to accept one.
- ERROR/WARN lines from either process in the window (p2p chatter dropped).

The entry is refreshed on every tick while the stall lasts and finalized on
recovery with the duration and the height that resumed. It is shown in the
dashboard's Stall Diagnostics card, on the report page for the stall's alert,
in `/api/state` under `stall_diagnostics` (`active` and `recent`), in the AI
package, and summarized in the stall alert text itself
(`shape=... | tenure=... | miner=... | last_block=... | btc=... | mempool_ready=...`).

Detector config: `flash_block_seconds`, `stall_history_size` (default 50),
`stall_lookback_seconds` (default 900, how far back reorgs, flash blocks and
warnings are collected).

## Output

- Alerts are printed as: `[ALERT][SEVERITY] ...`
- Reports are printed as: `[REPORT] ...`
- Optional report file appending via `--report-output-path`.

## Running Tests

```bash
python3 -m unittest discover -s tests -v
```
