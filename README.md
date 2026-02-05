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
- `GET /api/state`: raw JSON state
- `GET /healthz`: health probe
- Recent proposals table (latest 5, with copyable signature hashes and in-progress/approved/rejected status highlighting).
- Visual sortition view for the latest 3 burn heights.
- Each burn-height card shows all captured block commits, the committed stacks block target, and winner highlighting (or null-miner outcome).
- Tenure extends table shows the latest 5 extend events with extend kind, Stacks block height, burn height, and txid.
- Existing operational panels remain: uptime/age metrics, alerts, signer participation, and counters.
- Null-miner sortitions are detected (`WINNER REJECTED` / zero winning hash).

CLI flags:

- `--web-enable`
- `--web-host 127.0.0.1`
- `--web-port 8787`

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

## Output

- Alerts are printed as: `[ALERT][SEVERITY] ...`
- Reports are printed as: `[REPORT] ...`
- Optional report file appending via `--report-output-path`.

## Running Tests

```bash
python3 -m unittest discover -s tests -v
```
