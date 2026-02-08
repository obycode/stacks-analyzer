function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

function fmtDateTime(ts) {
  if (ts === null || ts === undefined) return "-";
  return new Date(Number(ts) * 1000).toLocaleString();
}

function fmtAge(seconds) {
  if (!Number.isFinite(Number(seconds))) return "-";
  const value = Number(seconds);
  if (value < 60) return Math.round(value) + "s";
  if (value < 3600) return Math.round(value / 60) + "m";
  if (value < 86400) return Math.round(value / 3600) + "h";
  return Math.round(value / 86400) + "d";
}

function toLocalInputValue(ts) {
  if (!Number.isFinite(Number(ts))) return "";
  const date = new Date(Number(ts) * 1000);
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  const hour = String(date.getHours()).padStart(2, "0");
  const minute = String(date.getMinutes()).padStart(2, "0");
  return year + "-" + month + "-" + day + "T" + hour + ":" + minute;
}

function fromLocalInputValue(text) {
  if (!text) return null;
  const millis = new Date(text).getTime();
  if (!Number.isFinite(millis)) return null;
  return millis / 1000;
}

function shortHash(value, size = 14) {
  const text = String(value || "");
  if (text.length <= size) return text;
  return text.slice(0, size) + "...";
}

function severityClass(sev) {
  const lower = String(sev || "").toLowerCase();
  if (lower === "critical") return "sev sev-critical";
  if (lower === "warning") return "sev sev-warning";
  if (lower === "info") return "sev sev-info";
  return "sev sev-ok";
}

function proposalStatusClass(status) {
  if (status === "approved") return "status status-approved";
  if (status === "rejected") return "status status-rejected";
  return "status status-in-progress";
}

function reportLink(reportId) {
  if (!reportId) return "-";
  return "<a class='link' href='/report?id=" + encodeURIComponent(reportId) + "'>view</a>";
}

function explorerBlockLink(height) {
  if (height === null || height === undefined) return "-";
  return "<a class='link' href='https://explorer.hiro.so/block/" + encodeURIComponent(height) + "' target='_blank' rel='noopener noreferrer'>" + escapeHtml(height) + "</a>";
}

function renderSummary(payload) {
  const summary = payload.summary || {};
  document.getElementById("sumEvents").textContent = summary.events ?? 0;
  document.getElementById("sumAlerts").textContent = summary.alerts ?? 0;
  document.getElementById("sumReports").textContent = summary.reports ?? 0;
  document.getElementById("sumBurnBlocks").textContent = summary.burn_blocks ?? 0;
  document.getElementById("sumSortitions").textContent = summary.sortitions ?? 0;
  document.getElementById("sumTenureExtends").textContent = summary.tenure_extends ?? 0;
  document.getElementById("sumAnom").textContent = summary.anomalous_proposals ?? 0;
  const sev = summary.severity_counts || {};
  document.getElementById("sumSeverity").textContent =
    "i:" + (sev.info || 0) + " w:" + (sev.warning || 0) + " c:" + (sev.critical || 0);
}

function renderTimeline(payload) {
  const body = document.getElementById("timelineBody");
  const timeline = payload.timeline || [];
  if (!timeline.length) {
    body.innerHTML = "<tr><td colspan='4'>No timeline events in this window.</td></tr>";
    return;
  }
  body.innerHTML = timeline
    .slice()
    .reverse()
    .map((item) => {
      return "<tr><td>" + escapeHtml(fmtDateTime(item.ts)) + "</td><td>" +
        escapeHtml(item.source || "-") + "</td><td class='mono'>" +
        escapeHtml(item.kind || "-") + "</td><td>" +
        escapeHtml(item.message || "-") + "</td></tr>";
    })
    .join("");
}

function renderProposals(payload) {
  const body = document.getElementById("proposalsBody");
  const proposals = payload.anomalous_proposals || [];
  if (!proposals.length) {
    body.innerHTML = "<tr><td colspan='7'>No anomalous proposals in this window.</td></tr>";
    return;
  }
  body.innerHTML = proposals.map((item) => {
    const status = String(item.status || "in_progress");
    const statusLabel = status.replaceAll("_", " ");
    return "<tr><td class='mono'>" + escapeHtml(shortHash(item.signature_hash, 16)) +
      "</td><td><span class='" + proposalStatusClass(status) + "'>" + escapeHtml(statusLabel) +
      "</span></td><td>" + explorerBlockLink(item.block_height) +
      "</td><td>" + escapeHtml(item.accept_count ?? 0) +
      "</td><td>" + escapeHtml(item.reject_count ?? 0) +
      "</td><td>" + escapeHtml(item.top_reject_reason || "-") +
      "</td><td>" + escapeHtml(fmtDateTime(item.last_ts)) + "</td></tr>";
  }).join("");
}

function renderAlerts(payload) {
  const body = document.getElementById("alertsBody");
  const alerts = payload.alerts || [];
  if (!alerts.length) {
    body.innerHTML = "<tr><td colspan='4'>No alerts in this window.</td></tr>";
    return;
  }
  body.innerHTML = alerts.map((item) => {
    return "<tr><td>" + escapeHtml(fmtDateTime(item.ts)) + "</td><td><span class='" +
      severityClass(item.severity) + "'>" + escapeHtml(item.severity || "info") +
      "</span></td><td>" + escapeHtml(item.message || "-") + "</td><td>" +
      reportLink(item.report_id) + "</td></tr>";
  }).join("");
}

function renderReports(payload) {
  const body = document.getElementById("reportsBody");
  const reports = payload.reports || [];
  if (!reports.length) {
    body.innerHTML = "<tr><td colspan='4'>No reports in this window.</td></tr>";
    return;
  }
  body.innerHTML = reports.map((item) => {
    return "<tr><td>" + escapeHtml(fmtDateTime(item.ts)) + "</td><td><span class='" +
      severityClass(item.severity) + "'>" + escapeHtml(item.severity || "info") +
      "</span></td><td>" + escapeHtml(item.summary || "-") + "</td><td>" +
      reportLink(item.id) + "</td></tr>";
  }).join("");
}

function renderEventKinds(payload) {
  const container = document.getElementById("kindCounts");
  const counts = payload.event_kind_counts || {};
  const entries = Object.entries(counts).sort((a, b) => Number(b[1]) - Number(a[1]));
  if (!entries.length) {
    container.innerHTML = "<div class='muted'>No events in this window.</div>";
    return;
  }
  container.innerHTML = entries
    .map(([kind, count]) => {
      return "<div class='kind-item'><div class='kind-name mono'>" + escapeHtml(kind) +
        "</div><div class='kind-value'>" + escapeHtml(count) + "</div></div>";
    })
    .join("");
}

async function loadWindow() {
  const startInput = document.getElementById("startTime");
  const stopInput = document.getElementById("stopTime");
  const startTs = fromLocalInputValue(startInput.value);
  const stopTs = fromLocalInputValue(stopInput.value);
  if (startTs === null || stopTs === null) return;
  const params = new URLSearchParams({
    start: String(startTs),
    stop: String(stopTs),
    events_limit: "2200",
    timeline_limit: "500",
    proposal_limit: "120",
  });
  const response = await fetch("/api/history-window?" + params.toString(), {
    cache: "no-store",
  });
  if (!response.ok) {
    throw new Error("history query failed");
  }
  const payload = await response.json();
  renderSummary(payload);
  renderTimeline(payload);
  renderProposals(payload);
  renderAlerts(payload);
  renderReports(payload);
  renderEventKinds(payload);

  const duration = Number(payload.duration_seconds || 0);
  const windowLabel = document.getElementById("windowLabel");
  windowLabel.textContent =
    "Window: " +
    fmtDateTime(payload.start_ts) +
    " -> " +
    fmtDateTime(payload.stop_ts) +
    " (" +
    fmtAge(duration) +
    ")";
  document.getElementById("updated").textContent =
    "Updated " + new Date().toLocaleTimeString();
}

function setRelativeWindow(minutes) {
  const stop = Date.now() / 1000;
  const start = stop - minutes * 60;
  document.getElementById("startTime").value = toLocalInputValue(start);
  document.getElementById("stopTime").value = toLocalInputValue(stop);
}

function init() {
  setRelativeWindow(10);
  loadWindow().catch(() => {
    document.getElementById("updated").textContent = "History unavailable";
  });

  document.getElementById("applyWindow").addEventListener("click", () => {
    loadWindow().catch(() => {
      document.getElementById("updated").textContent = "History unavailable";
    });
  });

  document.querySelectorAll("[data-minutes]").forEach((button) => {
    button.addEventListener("click", () => {
      const minutes = Number(button.getAttribute("data-minutes") || 10);
      setRelativeWindow(minutes);
      loadWindow().catch(() => {
        document.getElementById("updated").textContent = "History unavailable";
      });
    });
  });
}

init();
