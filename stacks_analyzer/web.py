import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, Optional
from urllib.parse import urlparse


DASHBOARD_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Stacks Analyzer Dashboard</title>
  <style>
    :root {
      --bg-0: #081018;
      --bg-1: #11253d;
      --card: rgba(16, 26, 36, 0.72);
      --line: rgba(148, 163, 184, 0.25);
      --text: #f8fafc;
      --muted: #94a3b8;
      --ok: #22c55e;
      --warn: #f59e0b;
      --critical: #ef4444;
      --info: #38bdf8;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "Avenir Next", "Segoe UI", "Helvetica Neue", sans-serif;
      color: var(--text);
      background:
        radial-gradient(1200px 520px at -10% -20%, #1f4f80 0%, transparent 60%),
        radial-gradient(900px 420px at 115% -20%, #3d1a63 0%, transparent 62%),
        linear-gradient(180deg, var(--bg-1), var(--bg-0));
      min-height: 100vh;
    }
    .wrap {
      max-width: 1200px;
      margin: 0 auto;
      padding: 24px;
    }
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 16px;
      margin-bottom: 18px;
    }
    .header-right {
      display: flex;
      align-items: center;
      gap: 10px;
      flex-wrap: wrap;
      justify-content: flex-end;
    }
    .height-chip {
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 4px 10px;
      font-size: 12px;
      color: #dbeafe;
      background: rgba(15, 23, 42, 0.48);
    }
    h1 { margin: 0; font-size: 28px; letter-spacing: 0.4px; }
    .muted { color: var(--muted); font-size: 13px; }
    .grid {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 12px;
      margin-bottom: 14px;
    }
    .card {
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: 14px;
      backdrop-filter: blur(8px);
      padding: 14px;
    }
    .label {
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.12em;
      color: var(--muted);
      margin-bottom: 6px;
    }
    .value { font-size: 24px; font-weight: 700; line-height: 1.1; }
    .two {
      display: grid;
      grid-template-columns: 1.2fr 1fr;
      gap: 12px;
      margin-bottom: 12px;
    }
    .panel-title {
      margin: 0 0 10px 0;
      font-size: 14px;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }
    th, td {
      text-align: left;
      padding: 8px 6px;
      border-bottom: 1px solid var(--line);
      vertical-align: top;
    }
    th { color: var(--muted); font-weight: 600; }
    .sev {
      display: inline-block;
      min-width: 64px;
      text-transform: uppercase;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.08em;
      padding: 2px 8px;
      border-radius: 999px;
    }
    .sev-critical { background: rgba(239, 68, 68, 0.18); color: #fecaca; }
    .sev-warning { background: rgba(245, 158, 11, 0.18); color: #fde68a; }
    .sev-info { background: rgba(56, 189, 248, 0.18); color: #bae6fd; }
    .sev-ok { background: rgba(34, 197, 94, 0.18); color: #bbf7d0; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
    .hash-btn {
      border: 1px solid var(--line);
      background: rgba(15, 23, 42, 0.55);
      color: #dbeafe;
      border-radius: 8px;
      padding: 2px 8px;
      cursor: pointer;
      font: inherit;
    }
    .hash-btn:hover { border-color: rgba(186, 230, 253, 0.45); }
    @media (max-width: 980px) {
      .grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .two { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="header">
      <h1>Stacks Analyzer</h1>
      <div class="header-right">
        <div class="height-chip" id="btcHeight">BTC: -</div>
        <div class="height-chip" id="stxHeight">STX: -</div>
        <div class="muted" id="updated">Waiting for data...</div>
      </div>
    </div>

    <div class="card" style="margin-bottom: 12px;">
      <div class="panel-title">Open Proposals</div>
      <table>
        <thead>
          <tr><th>Signature Hash</th><th>Block Height</th><th>Age</th><th>Max Seen</th><th>Threshold</th></tr>
        </thead>
        <tbody id="proposalsBody"></tbody>
      </table>
    </div>

    <div class="grid">
      <div class="card"><div class="label">Uptime</div><div class="value" id="uptime">-</div></div>
      <div class="card"><div class="label">Node Tip Age</div><div class="value" id="tipAge">-</div></div>
      <div class="card"><div class="label">Signer Proposal Age</div><div class="value" id="proposalAge">-</div></div>
      <div class="card"><div class="label">Threshold Ratio</div><div class="value" id="thresholdRatio">-</div></div>
    </div>

    <div class="two">
      <div class="card">
        <div class="panel-title">Recent Alerts</div>
        <table>
          <thead>
            <tr><th>Time</th><th>Severity</th><th>Message</th></tr>
          </thead>
          <tbody id="alertsBody"></tbody>
        </table>
      </div>
      <div class="card">
        <div class="panel-title">All Signers</div>
        <table>
          <thead>
            <tr><th>Name</th><th>Signer Key</th><th>Weight</th><th>Weight %</th><th>Participation</th></tr>
          </thead>
          <tbody id="signersBody"></tbody>
        </table>
      </div>
    </div>

    <div class="card">
      <div class="panel-title">Counters</div>
      <table>
        <tbody id="countsBody"></tbody>
      </table>
    </div>
  </div>

  <script>
    function fmtAge(value) {
      if (value === null || value === undefined) return "-";
      if (value < 1) return value.toFixed(2) + "s";
      if (value < 60) return Math.round(value) + "s";
      const m = Math.floor(value / 60);
      const s = Math.round(value % 60);
      return m + "m " + s + "s";
    }

    function escapeHtml(value) {
      return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;");
    }

    function render(data) {
      const now = new Date();
      document.getElementById("updated").textContent = "Updated " + now.toLocaleTimeString();
      document.getElementById("uptime").textContent = fmtAge(data.uptime_seconds);
      document.getElementById("tipAge").textContent = fmtAge(data.node_tip_age_seconds);
      document.getElementById("proposalAge").textContent = fmtAge(data.signer_proposal_age_seconds);
      document.getElementById("thresholdRatio").textContent = (data.threshold_ratio_percent || 0).toFixed(1) + "%";
      const btc = data.current_bitcoin_block_height;
      const stx = data.current_stacks_block_height;
      document.getElementById("btcHeight").textContent = "BTC: " + (btc === null || btc === undefined ? "-" : btc);
      document.getElementById("stxHeight").textContent = "STX: " + (stx === null || stx === undefined ? "-" : stx);

      const alerts = data.recent_alerts || [];
      const alertsBody = document.getElementById("alertsBody");
      alertsBody.innerHTML = alerts.slice().reverse().slice(0, 20).map((item) => {
        const sev = (item.severity || "ok").toLowerCase();
        const sevClass = "sev sev-" + (sev === "warning" ? "warning" : sev === "critical" ? "critical" : sev === "info" ? "info" : "ok");
        return "<tr><td>" + escapeHtml(new Date(item.ts * 1000).toLocaleTimeString()) + "</td><td><span class='" + sevClass + "'>" + escapeHtml(sev) + "</span></td><td>" + escapeHtml(item.message || "") + "</td></tr>";
      }).join("");

      const signers = data.signers || data.large_signers || [];
      document.getElementById("signersBody").innerHTML = signers.map((item) => {
        const name = item.name ? escapeHtml(item.name) : "-";
        return "<tr><td>" + name + "</td><td class='mono'>" + escapeHtml(item.pubkey.slice(0, 18)) + "...</td><td>" + Number(item.estimated_weight || 0).toFixed(1) + "</td><td>" + Number(item.weight_percent_of_total || 0).toFixed(2) + "%</td><td>" + Math.round((item.participation_ratio || 0) * 100) + "% (" + (item.participation_samples || 0) + ")</td></tr>";
      }).join("");

      const proposals = data.open_proposals || [];
      document.getElementById("proposalsBody").innerHTML = proposals.slice(0, 20).map((item) => {
        const label = escapeHtml(item.signature_hash.slice(0, 14)) + "...";
        const blockHeight = item.block_height === null || item.block_height === undefined ? "-" : item.block_height;
        return "<tr><td class='mono'><button class='hash-btn mono' data-copy-hash='" + escapeHtml(item.signature_hash) + "' title='Copy full hash'>" + label + "</button></td><td>" + escapeHtml(blockHeight) + "</td><td>" + fmtAge(item.age_seconds) + "</td><td>" + Number(item.max_percent_observed || 0).toFixed(1) + "%</td><td>" + (item.threshold_seen ? "yes" : "no") + "</td></tr>";
      }).join("");

      const lines = data.lines || {};
      const counts = [
        ["Node lines", lines.node || 0],
        ["Signer lines", lines.signer || 0],
        ["Signer entries", signers.length],
        ["Open proposals", data.open_proposals_count || 0],
        ["Completed proposals", data.completed_proposals || 0],
        ["Completed with threshold", data.completed_with_threshold || 0],
        ["Total weight est.", data.total_weight_estimate ? Number(data.total_weight_estimate).toFixed(1) : "-"],
        ["Stale chunks (window)", data.stale_chunks_window_count || 0],
        ["Active stalls", (data.active_stalls || []).join(", ") || "none"]
      ];
      document.getElementById("countsBody").innerHTML = counts.map((row) => {
        return "<tr><th>" + escapeHtml(row[0]) + "</th><td>" + escapeHtml(row[1]) + "</td></tr>";
      }).join("");
    }

    async function load() {
      try {
        const response = await fetch("/api/state", { cache: "no-store" });
        if (!response.ok) throw new Error("bad status");
        const data = await response.json();
        render(data);
      } catch (err) {
        document.getElementById("updated").textContent = "Dashboard disconnected";
      }
    }

    load();
    setInterval(load, 2000);

    document.addEventListener("click", async (event) => {
      const target = event.target.closest("[data-copy-hash]");
      if (!target) return;
      const value = target.getAttribute("data-copy-hash");
      if (!value) return;
      try {
        await navigator.clipboard.writeText(value);
        const prev = target.textContent;
        target.textContent = "Copied";
        setTimeout(() => { target.textContent = prev; }, 900);
      } catch (_err) {}
    });
  </script>
</body>
</html>
"""


def build_handler(state_provider: Callable[[], Dict[str, Any]]) -> type:
    class DashboardHandler(BaseHTTPRequestHandler):
        def _send_bytes(
            self, payload: bytes, content_type: str, status: int = 200
        ) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path == "/":
                self._send_bytes(DASHBOARD_HTML.encode("utf-8"), "text/html; charset=utf-8")
                return
            if parsed.path == "/api/state":
                payload = json.dumps(state_provider(), sort_keys=True).encode("utf-8")
                self._send_bytes(payload, "application/json; charset=utf-8")
                return
            if parsed.path == "/healthz":
                self._send_bytes(b"ok\n", "text/plain; charset=utf-8")
                return
            self._send_bytes(b"not found\n", "text/plain; charset=utf-8", status=404)

        def log_message(self, format: str, *args: object) -> None:
            _ = (format, args)

    return DashboardHandler


class DashboardServer:
    def __init__(
        self,
        host: str,
        port: int,
        state_provider: Callable[[], Dict[str, Any]],
    ) -> None:
        self.host = host
        self.port = port
        self.state_provider = state_provider
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        handler = build_handler(self.state_provider)
        self._server = ThreadingHTTPServer((self.host, self.port), handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        if self._server is None:
            return
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2)
