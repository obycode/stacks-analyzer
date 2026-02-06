import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, Optional
from urllib.parse import urlparse
from urllib.parse import parse_qs


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
      margin-bottom: 12px;
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
    .proposal-row-in-progress {
      background: rgba(56, 189, 248, 0.1);
    }
    .proposal-row-rejected {
      background: rgba(239, 68, 68, 0.1);
    }
    .proposal-status {
      display: inline-block;
      border-radius: 999px;
      padding: 2px 8px;
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      border: 1px solid var(--line);
    }
    .proposal-status-in-progress {
      color: #bae6fd;
      background: rgba(56, 189, 248, 0.18);
      border-color: rgba(56, 189, 248, 0.45);
    }
    .proposal-status-approved {
      color: #bbf7d0;
      background: rgba(34, 197, 94, 0.16);
      border-color: rgba(34, 197, 94, 0.35);
    }
    .proposal-status-rejected {
      color: #fecaca;
      background: rgba(239, 68, 68, 0.18);
      border-color: rgba(239, 68, 68, 0.4);
    }
    .proposal-status-unknown {
      color: #cbd5e1;
      background: rgba(148, 163, 184, 0.15);
      border-color: rgba(148, 163, 184, 0.35);
    }
    .percent-accept {
      color: #86efac;
      font-weight: 600;
    }
    .percent-reject {
      color: #fca5a5;
      font-weight: 600;
    }
    .link {
      color: #bae6fd;
      text-decoration: none;
    }
    .link:hover {
      text-decoration: underline;
    }

    .sortition-grid {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 10px;
    }
    .round {
      border: 1px solid var(--line);
      border-radius: 12px;
      background: rgba(15, 23, 42, 0.45);
      padding: 10px;
    }
    .round-head {
      display: flex;
      justify-content: space-between;
      gap: 8px;
      margin-bottom: 8px;
      font-size: 12px;
      color: var(--muted);
    }
    .round-age {
      color: var(--muted);
      margin-left: 6px;
      font-size: 11px;
    }
    .badge {
      border-radius: 999px;
      padding: 2px 8px;
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      border: 1px solid var(--line);
    }
    .badge-winner {
      color: #bbf7d0;
      background: rgba(34, 197, 94, 0.16);
      border-color: rgba(34, 197, 94, 0.35);
    }
    .badge-null {
      color: #fde68a;
      background: rgba(245, 158, 11, 0.16);
      border-color: rgba(245, 158, 11, 0.35);
    }
    .commit-list {
      display: grid;
      gap: 6px;
    }
    .commit {
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 6px 8px;
      font-size: 12px;
      background: rgba(2, 6, 23, 0.45);
    }
    .commit-winner {
      border-color: rgba(34, 197, 94, 0.45);
      background: rgba(34, 197, 94, 0.08);
    }

    @media (max-width: 980px) {
      .grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .two { grid-template-columns: 1fr; }
      .sortition-grid { grid-template-columns: 1fr; }
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

    <div class="grid">
      <div class="card"><div class="label">Uptime</div><div class="value" id="uptime">-</div></div>
      <div class="card"><div class="label">Node Tip Age</div><div class="value" id="tipAge">-</div></div>
      <div class="card"><div class="label">Signer Proposal Age</div><div class="value" id="proposalAge">-</div></div>
      <div class="card"><div class="label">Avg Block Interval</div><div class="value" id="avgBlockInterval">-</div></div>
    </div>

    <div class="card">
      <div class="panel-title">Recent Proposals (Latest 5)</div>
      <table>
        <thead>
          <tr><th>Signature Hash</th><th>Status</th><th>Block Height</th><th>Age</th><th>Max Seen</th><th>Threshold</th></tr>
        </thead>
        <tbody id="proposalsBody"></tbody>
      </table>
    </div>

    <div class="card">
      <div class="panel-title">Recent Sortitions (Latest 3 Burn Heights)</div>
      <div class="sortition-grid" id="sortitionCards"></div>
    </div>

    <div class="card">
      <div class="panel-title">Last 5 Tenure Extends</div>
      <table>
        <thead>
          <tr><th>Seen</th><th>Kind</th><th>Stacks Block Height</th><th>Burn Height</th><th>Txid</th></tr>
        </thead>
        <tbody id="tenureExtendsBody"></tbody>
      </table>
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
      <div class="panel-title">Recent Reports</div>
      <table>
        <thead>
          <tr><th>Time</th><th>Severity</th><th>Alert</th><th>Report</th></tr>
        </thead>
        <tbody id="reportsBody"></tbody>
      </table>
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

    function fmtWallClock(ts) {
      if (ts === null || ts === undefined) return "-";
      return new Date(ts * 1000).toLocaleString();
    }

    function shortHash(value, size = 14) {
      if (value === null || value === undefined) return "-";
      const text = String(value);
      if (text.length <= size) return text;
      return text.slice(0, size) + "...";
    }

    function linkTo(url, label, newTab = true) {
      if (newTab) {
        return "<a class='link' href='" + url + "' target='_blank' rel='noopener noreferrer'>" + label + "</a>";
      }
      return "<a class='link' href='" + url + "'>" + label + "</a>";
    }

    function mempoolAddressLink(address) {
      if (!address) return "-";
      return linkTo("https://mempool.space/address/" + encodeURIComponent(address), escapeHtml(address));
    }

    function mempoolTxLink(txid, label) {
      if (!txid) return "-";
      return linkTo("https://mempool.space/tx/" + encodeURIComponent(txid), label);
    }

    function hiroTxLink(txid, label) {
      if (!txid) return "-";
      return linkTo("https://explorer.hiro.so/txid/" + encodeURIComponent(txid), label);
    }

    function hiroBlockLink(height, label) {
      if (height === null || height === undefined) return "-";
      return linkTo("https://explorer.hiro.so/block/" + encodeURIComponent(height), label);
    }

    function hiroBtcBlockLink(height, label) {
      if (height === null || height === undefined) return "-";
      return linkTo("https://explorer.hiro.so/btcblock/" + encodeURIComponent(height), label);
    }

    function hiroBlockHashLink(blockHash, label) {
      if (!blockHash) return "-";
      return linkTo("https://explorer.hiro.so/block/" + encodeURIComponent(blockHash), label);
    }

    function isLikelyBtcAddress(value) {
      return value.startsWith("bc1") || value.startsWith("1") || value.startsWith("3");
    }

    function linkifyAlertMessage(alert) {
      const message = String(alert.message || "");
      let rendered = escapeHtml(message);
      const key = String(alert.key || "");

      if (key.startsWith("burn-block-")) {
        rendered = rendered.replace(/height (\d+)/, (match, height) => {
          return "height " + hiroBtcBlockLink(height, escapeHtml(height));
        });
        rendered = rendered.replace(/new_miner=txid:([0-9a-fA-F]+)/, (_match, txid) => {
          return "new_miner=txid:" + mempoolTxLink(txid, escapeHtml(shortHash(txid, 20)));
        });
        rendered = rendered.replace(/new_miner=([A-Za-z0-9]+)/, (match, value) => {
          if (value === "unchanged" || value === "n/a") {
            return match;
          }
          if (isLikelyBtcAddress(value)) {
            return "new_miner=" + mempoolAddressLink(value);
          }
          return match;
        });
      }

      if (key.startsWith("tenure-extend-")) {
        rendered = rendered.replace(/txid=([0-9a-fA-F]+)/, (_match, txid) => {
          return "txid=" + hiroTxLink(txid, escapeHtml(shortHash(txid, 24)));
        });
        rendered = rendered.replace(/block_height=(\d+)/, (_match, height) => {
          return "block_height=" + hiroBlockLink(height, escapeHtml(height));
        });
        rendered = rendered.replace(/burn_height=(\d+)/, (_match, height) => {
          return "burn_height=" + hiroBtcBlockLink(height, escapeHtml(height));
        });
      }

      if (key.startsWith("proposal-timeout-")) {
        rendered = rendered.replace(/height (\d+)/, (match, height) => {
          return "height " + hiroBlockLink(height, escapeHtml(height));
        });
      }

      return rendered;
    }

    function renderSortitionCards(rounds, nowEpoch) {
      const container = document.getElementById("sortitionCards");
      if (!rounds.length) {
        container.innerHTML = "<div class='round'>No sortition data yet.</div>";
        return;
      }
      container.innerHTML = rounds.map((round) => {
        const outcome = round.null_miner_won ? "null-miner" : (round.winner_txid ? "winner-selected" : "pending");
        const badgeClass = round.null_miner_won ? "badge badge-null" : "badge badge-winner";
        const commits = round.commits || [];
        const candidateTs = [];
        if (round.winner_ts) candidateTs.push(round.winner_ts);
        if (round.rejected_ts) candidateTs.push(round.rejected_ts);
        for (const item of commits) {
          if (item.ts) candidateTs.push(item.ts);
        }
        const latestTs = candidateTs.length ? Math.max(...candidateTs) : null;
        const ageText = latestTs ? fmtAge(Math.max(0, nowEpoch - latestTs)) : "";
        const commitHtml = commits.length
          ? commits.map((item) => {
              const commitClass = item.is_winner ? "commit commit-winner" : "commit";
              const address = item.apparent_sender || "";
              const commitLabel = escapeHtml(shortHash(item.commit_txid, 20));
              const addressHtml = address ? mempoolAddressLink(address) : "-";
              const commitLink = item.commit_txid ? mempoolTxLink(item.commit_txid, commitLabel) : "-";
              const parentBurn = item.parent_burn_block;
              const parentBurnLabel = parentBurn !== null && parentBurn !== undefined
                ? hiroBtcBlockLink(parentBurn, escapeHtml(parentBurn))
                : "-";
              return "<div class='" + commitClass + "'><div class='mono'>" + addressHtml + "</div><div class='mono'>commit " + commitLink + "</div><div class='mono'>parent burn block " + parentBurnLabel + "</div></div>";
            }).join("")
          : "<div class='commit'>No commits captured for this burn height.</div>";
        const burnLabel = "Burn #" + escapeHtml(round.burn_height);
        const ageLabel = ageText ? " <span class='round-age'>" + escapeHtml(ageText) + " ago</span>" : "";
        return "<div class='round'><div class='round-head'><span>" + burnLabel + ageLabel + "</span><span class='" + badgeClass + "'>" + escapeHtml(outcome) + "</span></div><div class='commit-list'>" + commitHtml + "</div></div>";
      }).join("");
    }

    function renderTenureExtends(items) {
      const body = document.getElementById("tenureExtendsBody");
      if (!items.length) {
        body.innerHTML = "<tr><td colspan='5'>No tenure extends seen.</td></tr>";
        return;
      }
      body.innerHTML = items.map((item) => {
        const blockHeight = item.block_height === null || item.block_height === undefined ? "-" : item.block_height;
        const burnHeight = item.burn_height === null || item.burn_height === undefined ? "-" : item.burn_height;
        const blockLink = blockHeight === "-" ? "-" : hiroBlockLink(blockHeight, escapeHtml(blockHeight));
        const burnLink = burnHeight === "-" ? "-" : hiroBtcBlockLink(burnHeight, escapeHtml(burnHeight));
        const txLabel = escapeHtml(shortHash(item.txid || "-", 24));
        const txLink = item.txid ? hiroTxLink(item.txid, txLabel) : "-";
        return "<tr><td>" + escapeHtml(fmtWallClock(item.ts)) + "</td><td>" + escapeHtml(item.kind || "-") + "</td><td>" + blockLink + "</td><td>" + burnLink + "</td><td class='mono'>" + txLink + "</td></tr>";
      }).join("");
    }

    function render(data) {
      const now = new Date();
      const nowEpoch = Date.now() / 1000;
      document.getElementById("updated").textContent = "Updated " + now.toLocaleTimeString();
      document.getElementById("uptime").textContent = fmtAge(data.uptime_seconds);
      document.getElementById("tipAge").textContent = fmtAge(data.node_tip_age_seconds);
      document.getElementById("proposalAge").textContent = fmtAge(data.signer_proposal_age_seconds);
      document.getElementById("avgBlockInterval").textContent = fmtAge(data.avg_block_interval_seconds);
      const btc = data.current_bitcoin_block_height;
      const stx = data.current_stacks_block_height;
      document.getElementById("btcHeight").textContent = "BTC: " + (btc === null || btc === undefined ? "-" : btc);
      document.getElementById("stxHeight").textContent = "STX: " + (stx === null || stx === undefined ? "-" : stx);

      const alerts = data.recent_alerts || [];
      const alertsBody = document.getElementById("alertsBody");
      alertsBody.innerHTML = alerts.slice().reverse().slice(0, 20).map((item) => {
        const sev = (item.severity || "ok").toLowerCase();
        const sevClass = "sev sev-" + (sev === "warning" ? "warning" : sev === "critical" ? "critical" : sev === "info" ? "info" : "ok");
        return "<tr><td>" + escapeHtml(new Date(item.ts * 1000).toLocaleTimeString()) + "</td><td><span class='" + sevClass + "'>" + escapeHtml(sev) + "</span></td><td>" + linkifyAlertMessage(item) + "</td></tr>";
      }).join("");

      const reports = data.recent_reports || [];
      const reportsBody = document.getElementById("reportsBody");
      if (!reports.length) {
        reportsBody.innerHTML = "<tr><td colspan='4'>No reports yet.</td></tr>";
      } else {
        reportsBody.innerHTML = reports.slice().reverse().slice(0, 20).map((item) => {
          const sev = (item.severity || "ok").toLowerCase();
          const sevClass = "sev sev-" + (sev === "warning" ? "warning" : sev === "critical" ? "critical" : sev === "info" ? "info" : "ok");
          const reportId = item.report_id;
          const reportLink = reportId ? linkTo("/report?id=" + encodeURIComponent(reportId), "view", false) : "-";
          return "<tr><td>" + escapeHtml(new Date(item.ts * 1000).toLocaleTimeString()) + "</td><td><span class='" + sevClass + "'>" + escapeHtml(sev) + "</span></td><td>" + escapeHtml(item.alert_key || "-") + "</td><td>" + reportLink + "</td></tr>";
        }).join("");
      }

      const signers = data.signers || data.large_signers || [];
      document.getElementById("signersBody").innerHTML = signers.map((item) => {
        const name = item.name ? escapeHtml(item.name) : "-";
        return "<tr><td>" + name + "</td><td class='mono'>" + escapeHtml(item.pubkey.slice(0, 18)) + "...</td><td>" + Number(item.estimated_weight || 0).toFixed(1) + "</td><td>" + Number(item.weight_percent_of_total || 0).toFixed(2) + "%</td><td>" + Math.round((item.participation_ratio || 0) * 100) + "% (" + (item.participation_samples || 0) + ")</td></tr>";
      }).join("");

      const proposals = data.recent_proposals || data.open_proposals || [];
      const proposalsBody = document.getElementById("proposalsBody");
      if (!proposals.length) {
        proposalsBody.innerHTML = "<tr><td colspan='6'>No proposals seen yet.</td></tr>";
      } else {
        proposalsBody.innerHTML = proposals.slice(0, 5).map((item) => {
        const label = escapeHtml(item.signature_hash.slice(0, 14)) + "...";
        const blockHeight = item.block_height === null || item.block_height === undefined ? "-" : item.block_height;
        const status = item.status || (item.is_open ? "in_progress" : "approved");
        const statusClass = status === "in_progress"
          ? "proposal-status proposal-status-in-progress"
          : status === "rejected"
            ? "proposal-status proposal-status-rejected"
            : status === "approved"
              ? "proposal-status proposal-status-approved"
              : "proposal-status proposal-status-unknown";
        const rowClass = status === "in_progress"
          ? "proposal-row-in-progress"
          : status === "rejected"
            ? "proposal-row-rejected"
            : "";
        const statusLabel = status === "in_progress"
          ? "in progress"
          : status === "rejected"
            ? "rejected"
            : status === "approved"
              ? "approved"
              : "unknown";
        const blockLink = (status === "approved" && blockHeight !== "-")
          ? hiroBlockLink(blockHeight, escapeHtml(blockHeight))
          : escapeHtml(blockHeight);
        const maxAccepted = Number(item.max_percent_observed || 0).toFixed(1);
        const maxRejected = Number(item.max_reject_percent || 0).toFixed(1);
        const maxSeen = "<span class='percent-accept'>" + maxAccepted + "%</span> <span class='percent-reject'>" + maxRejected + "%</span>";
        return "<tr class='" + rowClass + "'><td class='mono'><button class='hash-btn mono' data-copy-hash='" + escapeHtml(item.signature_hash) + "' title='Copy full hash'>" + label + "</button></td><td><span class='" + statusClass + "'>" + statusLabel + "</span></td><td>" + blockLink + "</td><td>" + fmtAge(item.age_seconds) + "</td><td>" + maxSeen + "</td><td>" + (item.threshold_seen ? "yes" : "no") + "</td></tr>";
      }).join("");
      }

      renderSortitionCards(data.recent_sortition_details || [], nowEpoch);
      renderTenureExtends(data.recent_tenure_extends || []);

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
      } catch (_err) {
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


REPORT_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Stacks Analyzer Report</title>
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
      max-width: 1100px;
      margin: 0 auto;
      padding: 28px 24px 48px;
    }
    .header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 18px;
    }
    h1 {
      font-size: 22px;
      margin: 0;
      letter-spacing: 0.03em;
    }
    .card {
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: 16px;
      padding: 16px 18px;
      margin-bottom: 16px;
      box-shadow: 0 20px 40px rgba(15, 23, 42, 0.25);
    }
    .muted { color: var(--muted); }
    .sev {
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      padding: 2px 8px;
      border-radius: 999px;
      display: inline-block;
      border: 1px solid var(--line);
    }
    .sev-critical { background: rgba(239, 68, 68, 0.18); color: #fecaca; border-color: rgba(239, 68, 68, 0.4); }
    .sev-warning { background: rgba(245, 158, 11, 0.18); color: #fde68a; border-color: rgba(245, 158, 11, 0.4); }
    .sev-info { background: rgba(56, 189, 248, 0.18); color: #bae6fd; border-color: rgba(56, 189, 248, 0.4); }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
    .grid {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 12px;
    }
    .grid .card { margin-bottom: 0; }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }
    th, td {
      padding: 8px 6px;
      border-bottom: 1px solid var(--line);
      text-align: left;
      vertical-align: top;
    }
    th { color: var(--muted); font-weight: 600; }
    .link {
      color: #bae6fd;
      text-decoration: none;
    }
    .link:hover { text-decoration: underline; }
    .btn {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 6px 12px;
      border-radius: 999px;
      border: 1px solid rgba(56, 189, 248, 0.45);
      background: rgba(56, 189, 248, 0.18);
      color: #bae6fd;
      text-decoration: none;
      font-size: 12px;
      letter-spacing: 0.06em;
      text-transform: uppercase;
    }
    .btn:hover {
      background: rgba(56, 189, 248, 0.28);
    }
    pre {
      margin: 0;
      white-space: pre-wrap;
      word-break: break-word;
      font-size: 12px;
      color: #e2e8f0;
    }
    @media (max-width: 900px) {
      .grid { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="header">
      <h1>Alert Report</h1>
      <a class="link" href="/">Back to dashboard</a>
    </div>
    <div class="card" id="summaryCard">
      <div class="muted">Loading report...</div>
    </div>
    <div class="grid">
      <div class="card">
        <h2 style="font-size:14px; margin:0 0 8px;">Snapshot</h2>
        <pre id="snapshotBody"></pre>
      </div>
      <div class="card">
        <h2 style="font-size:14px; margin:0 0 8px;">Recent Alerts</h2>
        <div id="alertsBody"></div>
      </div>
      <div class="card">
        <h2 style="font-size:14px; margin:0 0 8px;">Recent Rejections</h2>
        <div id="rejectionsBody"></div>
      </div>
    </div>
    <div class="card">
      <h2 style="font-size:14px; margin:0 0 8px;">Recent Events</h2>
      <div id="eventsBody"></div>
    </div>
  </div>
  <script>
    function escapeHtml(value) {
      return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;");
    }
    function sevClass(sev) {
      const lower = (sev || "info").toLowerCase();
      return "sev sev-" + (lower === "warning" ? "warning" : lower === "critical" ? "critical" : "info");
    }
    function fmtTime(ts) {
      if (!ts) return "-";
      return new Date(ts * 1000).toLocaleString();
    }
    function linkTo(url, label) {
      return "<a class='link' href='" + url + "'>" + label + "</a>";
    }

    function renderReport(report) {
      if (!report) {
        document.getElementById("summaryCard").innerHTML = "<div class='muted'>Report not found.</div>";
        return;
      }
      const alert = report.data && report.data.alert ? report.data.alert : {};
      const summary = report.summary || "-";
      document.getElementById("summaryCard").innerHTML =
        "<div style='display:flex; justify-content:space-between; gap:12px; align-items:center;'>" +
        "<div><div class='muted'>Alert</div><div style='margin-top:4px;'>" + escapeHtml(summary) + "</div>" +
        "<div class='muted' style='margin-top:6px; font-size:12px;'>Key: " + escapeHtml(alert.key || report.alert_key || "-") + "</div>" +
        "</div>" +
        "<div style='text-align:right;'><div class='" + sevClass(alert.severity || report.severity) + "'>" + escapeHtml(alert.severity || report.severity) + "</div>" +
        "<div class='muted' style='margin-top:6px; font-size:12px;'>Time: " + escapeHtml(fmtTime(report.ts)) + "</div>" +
        "<div style='margin-top:10px;'><a class='btn' href='/api/report-logs?id=" + encodeURIComponent(report.id) + "'>Download Logs</a></div>" +
        "</div>" +
        "</div>";

      const snapshot = report.data && report.data.snapshot ? report.data.snapshot : null;
      document.getElementById("snapshotBody").textContent = snapshot ? JSON.stringify(snapshot, null, 2) : "n/a";

      const alerts = (report.data && report.data.recent_alerts) || [];
      if (!alerts.length) {
        document.getElementById("alertsBody").innerHTML = "<div class='muted'>No alerts captured.</div>";
      } else {
        document.getElementById("alertsBody").innerHTML = "<table><thead><tr><th>Time</th><th>Severity</th><th>Message</th></tr></thead><tbody>" +
          alerts.map((item) => {
            return "<tr><td>" + escapeHtml(fmtTime(item.ts)) + "</td><td><span class='" + sevClass(item.severity) + "'>" + escapeHtml(item.severity) + "</span></td><td>" + escapeHtml(item.message || "") + "</td></tr>";
          }).join("") +
          "</tbody></table>";
      }

      const rejections = (report.data && report.data.recent_rejections) || [];
      if (!rejections.length) {
        document.getElementById("rejectionsBody").innerHTML = "<div class='muted'>No rejections captured.</div>";
      } else {
        document.getElementById("rejectionsBody").innerHTML = "<table><thead><tr><th>Sig</th><th>Reject%</th><th>Accept%</th><th>Reason</th></tr></thead><tbody>" +
          rejections.map((item) => {
            return "<tr><td class='mono'>" + escapeHtml((item.signature_hash || "").slice(0, 12)) + "</td><td>" + escapeHtml(item.max_reject_percent || 0) + "</td><td>" + escapeHtml(item.max_approved_percent || 0) + "</td><td>" + escapeHtml(item.reject_reason || "-") + "</td></tr>";
          }).join("") +
          "</tbody></table>";
      }

      const events = (report.data && report.data.recent_events) || [];
      if (!events.length) {
        document.getElementById("eventsBody").innerHTML = "<div class='muted'>No events captured.</div>";
      } else {
        document.getElementById("eventsBody").innerHTML = "<table><thead><tr><th>Time</th><th>Kind</th><th>Source</th><th>Details</th></tr></thead><tbody>" +
          events.map((item) => {
            const details = item.data ? JSON.stringify(item.data) : (item.line || "");
            return "<tr><td>" + escapeHtml(fmtTime(item.ts)) + "</td><td class='mono'>" + escapeHtml(item.kind || "") + "</td><td>" + escapeHtml(item.source || "") + "</td><td><pre>" + escapeHtml(details) + "</pre></td></tr>";
          }).join("") +
          "</tbody></table>";
      }
    }

    async function load() {
      const params = new URLSearchParams(window.location.search);
      const id = params.get("id");
      if (!id) {
        document.getElementById("summaryCard").innerHTML = "<div class='muted'>Missing report id.</div>";
        return;
      }
      const response = await fetch("/api/report?id=" + encodeURIComponent(id), { cache: "no-store" });
      if (!response.ok) {
        document.getElementById("summaryCard").innerHTML = "<div class='muted'>Failed to load report.</div>";
        return;
      }
      const payload = await response.json();
      renderReport(payload.report);
    }

    load();
  </script>
</body>
</html>
"""


def build_handler(
    state_provider: Callable[[], Dict[str, Any]],
    history_provider: Optional[Callable[[Dict[str, list]], Dict[str, Any]]] = None,
    alerts_provider: Optional[Callable[[Dict[str, list]], Dict[str, Any]]] = None,
    reports_provider: Optional[Callable[[Dict[str, list]], Dict[str, Any]]] = None,
    report_provider: Optional[Callable[[Dict[str, list]], Dict[str, Any]]] = None,
    report_logs_provider: Optional[Callable[[Dict[str, list]], Dict[str, Any]]] = None,
) -> type:
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
            if parsed.path == "/api/history":
                if history_provider is None:
                    self._send_bytes(
                        b"history disabled\n", "text/plain; charset=utf-8", status=404
                    )
                    return
                params = parse_qs(parsed.query)
                payload = json.dumps(history_provider(params), sort_keys=True).encode("utf-8")
                self._send_bytes(payload, "application/json; charset=utf-8")
                return
            if parsed.path == "/api/alerts":
                if alerts_provider is None:
                    self._send_bytes(
                        b"history disabled\n", "text/plain; charset=utf-8", status=404
                    )
                    return
                params = parse_qs(parsed.query)
                payload = json.dumps(alerts_provider(params), sort_keys=True).encode("utf-8")
                self._send_bytes(payload, "application/json; charset=utf-8")
                return
            if parsed.path == "/api/reports":
                if reports_provider is None:
                    self._send_bytes(
                        b"history disabled\n", "text/plain; charset=utf-8", status=404
                    )
                    return
                params = parse_qs(parsed.query)
                payload = json.dumps(reports_provider(params), sort_keys=True).encode("utf-8")
                self._send_bytes(payload, "application/json; charset=utf-8")
                return
            if parsed.path == "/api/report":
                if report_provider is None:
                    self._send_bytes(
                        b"history disabled\n", "text/plain; charset=utf-8", status=404
                    )
                    return
                params = parse_qs(parsed.query)
                payload = json.dumps(report_provider(params), sort_keys=True).encode("utf-8")
                self._send_bytes(payload, "application/json; charset=utf-8")
                return
            if parsed.path == "/api/report-logs":
                if report_logs_provider is None:
                    self._send_bytes(
                        b"history disabled\n", "text/plain; charset=utf-8", status=404
                    )
                    return
                params = parse_qs(parsed.query)
                payload = report_logs_provider(params)
                status = int(payload.get("status", 200))
                filename = payload.get("filename")
                content = payload.get("content", "")
                if not isinstance(content, (bytes, bytearray)):
                    content = str(content).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                if filename:
                    self.send_header(
                        "Content-Disposition",
                        "attachment; filename=\"%s\"" % filename,
                    )
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return
            if parsed.path == "/report":
                if report_provider is None:
                    self._send_bytes(
                        b"history disabled\n", "text/plain; charset=utf-8", status=404
                    )
                    return
                self._send_bytes(REPORT_HTML.encode("utf-8"), "text/html; charset=utf-8")
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
        history_provider: Optional[Callable[[Dict[str, list]], Dict[str, Any]]] = None,
        alerts_provider: Optional[Callable[[Dict[str, list]], Dict[str, Any]]] = None,
        reports_provider: Optional[Callable[[Dict[str, list]], Dict[str, Any]]] = None,
        report_provider: Optional[Callable[[Dict[str, list]], Dict[str, Any]]] = None,
        report_logs_provider: Optional[Callable[[Dict[str, list]], Dict[str, Any]]] = None,
    ) -> None:
        self.host = host
        self.port = port
        self.state_provider = state_provider
        self.history_provider = history_provider
        self.alerts_provider = alerts_provider
        self.reports_provider = reports_provider
        self.report_provider = report_provider
        self.report_logs_provider = report_logs_provider
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        handler = build_handler(
            self.state_provider,
            history_provider=self.history_provider,
            alerts_provider=self.alerts_provider,
            reports_provider=self.reports_provider,
            report_provider=self.report_provider,
            report_logs_provider=self.report_logs_provider,
        )
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
