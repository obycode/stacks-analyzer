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

    function humanReadableAlertFallback(alert) {
      const key = String((alert && alert.key) || "");
      const severity = String((alert && alert.severity) || "info").toLowerCase();
      let title = "Network event detected";
      let description = "The analyzer detected an event that may require review.";
      if (key.startsWith("proposal-timeout-boundary-")) {
        title = "Proposal delayed near burn-block boundary";
        description =
          "This proposal timed out while signers were likely split around a new burn block.";
      } else if (key.startsWith("proposal-timeout-")) {
        title = "Proposal did not finalize in time";
        description =
          "The proposal stayed in progress and did not reach the 70% approval threshold in time.";
      } else if (key.startsWith("proposal-reject-boundary-")) {
        title = "Proposal rejected near burn-block boundary";
        description =
          "Signer rejections likely came from differing burn-chain views at boundary timing.";
      } else if (key.startsWith("signer-reject-")) {
        title = "Signer rejection observed";
        description = "One or more signer responses rejected a proposal.";
      } else if (key.startsWith("signer-accept-then-reject-")) {
        title = "Inconsistent signer response order";
        description = "A signer appears to have accepted and then rejected the same proposal.";
      } else if (key.startsWith("node-stall")) {
        title = "Node tip progression stalled";
        description = "The node did not advance to a new tip in the expected interval.";
      } else if (key.startsWith("signer-stall")) {
        title = "Signer proposal flow stalled";
        description = "No signer proposal activity was seen in the expected interval.";
      } else if (key.startsWith("burnchain-reorg-")) {
        title = "Burnchain reorg detected";
        description = "The burnchain switched branches and may affect downstream behavior.";
      } else if (key.startsWith("sortition-winner-rejected-")) {
        title = "Sortition winner rejected";
        description =
          "The selected sortition winner was rejected and the burn block proceeded with a null-miner outcome.";
      } else if (key.startsWith("node-block-proposal-rejected-")) {
        title = "Node rejected block proposal";
        description =
          "The local stacks node rejected a proposal during validation; check reason and nearby signer responses.";
      } else if (key.startsWith("miner-signers-rejected-")) {
        title = "Miner proposal rejected by signers";
        description =
          "The miner reached signer rejection threshold for a proposal and retried after a pause.";
      } else if (key.startsWith("signer-validation-slow-")) {
        title = "Slow signer validation";
        description =
          "Signer-side proposal validation took longer than expected and may delay threshold progress.";
      } else if (key.startsWith("mempool-iteration-deadline")) {
        title = "Miner mempool iteration hit deadline";
        description =
          "Mempool iteration ended by deadline rather than exhausting candidates.";
      } else if (key.startsWith("mempool-empty")) {
        title = "Mempool has stayed empty";
        description =
          "No transactions were ready to mine for an extended period.";
      }
      const severityHint =
        severity === "critical"
          ? "Critical: immediate investigation recommended."
          : severity === "warning"
          ? "Warning: investigate soon."
          : "Info: monitor and correlate with nearby events.";
      return {
        title,
        description,
        severity_hint: severityHint,
      };
    }

    function shortHash(value, chars) {
      if (!value) return "-";
      const text = String(value);
      if (text.length <= chars) return text;
      return text.slice(0, chars) + "..";
    }

    function formatTimelineItem(item, targetSig) {
      const data = item.data || {};
      const kind = item.kind || "event";
      const signer = data.signer_pubkey ? shortHash(data.signer_pubkey, 12) : null;
      const sig = data.signer_signature_hash ? shortHash(data.signer_signature_hash, 12) : null;
      const sigNote = sig && targetSig && sig !== targetSig ? " | sig " + sig : "";
      const height = data.block_height || data.burn_height;
      let title = kind;
      let meta = "";
      if (kind === "signer_block_proposal") {
        title = "Proposal received";
        meta = "block_height " + (data.block_height ?? "-") + " | burn_height " + (data.burn_height ?? "-") + sigNote;
      } else if (kind === "signer_block_acceptance") {
        title = "Signer acceptance";
        meta = (signer ? "signer " + signer + " | " : "") + "approved " + (data.percent_approved ? data.percent_approved.toFixed(1) + "%" : "n/a") + sigNote;
      } else if (kind === "signer_block_rejection") {
        title = "Signer rejection";
        meta = (signer ? "signer " + signer + " | " : "") + "rejected " + (data.percent_rejected ? data.percent_rejected.toFixed(1) + "%" : "n/a") + " | reason " + (data.reject_reason || "-") + sigNote;
      } else if (kind === "signer_threshold_reached") {
        title = "Threshold reached";
        meta = (signer ? "signer " + signer + " | " : "") + "approved " + (data.percent_approved ? data.percent_approved.toFixed(1) + "%" : "n/a") + sigNote;
      } else if (kind === "signer_block_pushed") {
        title = "Block pushed";
        meta = "block_height " + (data.block_height ?? "-") + sigNote;
      } else if (kind === "signer_new_block_event") {
        title = "New block event";
        meta = "block_height " + (data.block_height ?? "-") + sigNote;
      } else if (kind === "node_consensus") {
        title = "Burn block consensus";
        meta = "burn_height " + (data.burn_height ?? "-") + " | " + shortHash(data.consensus_hash, 16);
      } else if (kind === "node_tenure_change") {
        title = "Tenure change";
        meta = "kind " + (data.tenure_change_kind || "-") + " | block_height " + (data.block_height ?? "-");
      } else if (kind === "node_sortition_winner_selected") {
        title = "Sortition winner selected";
        meta = "burn_height " + (data.burn_height ?? "-") + " | " + shortHash(data.winner_txid, 12);
      } else if (kind === "node_sortition_winner_rejected") {
        title = "Sortition winner rejected";
        meta = "burn_height " + (data.burn_height ?? "-") + " | " + (data.rejection_reason || "unknown");
      } else if (height) {
        meta = "height " + height;
      }
      return "<div class='timeline-item'>" +
        "<div class='timeline-time'>" + escapeHtml(fmtTime(item.ts)) + "</div>" +
        "<div>" +
        "<div class='timeline-title'>" + escapeHtml(title) + "</div>" +
        "<div class='timeline-meta'>" + escapeHtml(meta) + "</div>" +
        "</div>" +
        "</div>";
    }

    function renderReport(report) {
      if (!report) {
        document.getElementById("summaryCard").innerHTML = "<div class='muted'>Report not found.</div>";
        return;
      }
      const alert = report.data && report.data.alert ? report.data.alert : {};
      const summary = report.summary || "-";
      const readable =
        alert.readable && typeof alert.readable === "object"
          ? alert.readable
          : humanReadableAlertFallback(alert);
      document.getElementById("summaryCard").innerHTML =
        "<div>" +
        "<div class='muted'>Alert Report</div>" +
        "<div class='summary-title'>" + escapeHtml(readable.title || summary) + "</div>" +
        "<div class='summary-meta'>" + escapeHtml(readable.description || "") + "</div>" +
        "<div class='summary-meta'>" + escapeHtml(readable.severity_hint || "") + "</div>" +
        "<div class='summary-meta'>Raw alert: " + escapeHtml(summary) + "</div>" +
        "<div class='summary-meta'>Key: " + escapeHtml(alert.key || report.alert_key || "-") + "</div>" +
        "</div>" +
        "<div class='report-actions'>" +
        "<div class='" + sevClass(alert.severity || report.severity) + "'>" + escapeHtml(alert.severity || report.severity) + "</div>" +
        "<div class='summary-meta'>Time: " + escapeHtml(fmtTime(report.ts)) + "</div>" +
        "<div class='downloads-box'>" +
        "<div class='downloads-title'>Downloads</div>" +
        "<div class='downloads-list'>" +
        "<a class='btn btn-download' href='/api/report-logs?id=" + encodeURIComponent(report.id) + "'><span class='btn-icon' aria-hidden='true'>&#8681;</span><span>Raw logs</span></a>" +
        "<a class='btn btn-download' href='/api/report-filtered-logs?id=" + encodeURIComponent(report.id) + "'><span class='btn-icon' aria-hidden='true'>&#8681;</span><span>Filtered</span></a>" +
        "<a class='btn btn-download' href='/api/report-ai-package?id=" + encodeURIComponent(report.id) + "'><span class='btn-icon' aria-hidden='true'>&#8681;</span><span>AI package</span></a>" +
        "</div>" +
        "</div>" +
        "</div>";

      const proposalTimeline = report.data && report.data.proposal_timeline ? report.data.proposal_timeline : null;
      const timelineCard = document.getElementById("proposalTimelineCard");
      if (!proposalTimeline || !proposalTimeline.events || !proposalTimeline.events.length) {
        timelineCard.style.display = "none";
      } else {
        const meta = proposalTimeline.meta || {};
        const targetSig = meta.signature_hash ? shortHash(meta.signature_hash, 12) : null;
        const metaLine = [
          meta.signature_hash ? "sig " + shortHash(meta.signature_hash, 12) : null,
          meta.block_height ? "height " + meta.block_height : null,
          meta.burn_height ? "burn " + meta.burn_height : null,
        ].filter(Boolean).join(" | ");
        const items = proposalTimeline.events.map((item) => formatTimelineItem(item, targetSig)).join("");
        timelineCard.style.display = "block";
        timelineCard.innerHTML =
          "<div class='card-title'><h2>Proposal Timeline</h2></div>" +
          "<div class='muted'>" + escapeHtml(metaLine || "Proposal context") + "</div>" +
          "<div class='timeline'>" + items + "</div>";
      }

      const snapshot = report.data && report.data.snapshot ? report.data.snapshot : null;
      document.getElementById("snapshotBody").textContent = snapshot ? JSON.stringify(snapshot, null, 2) : "n/a";
      const contextItems = [];
      if (snapshot) {
        contextItems.push(["BTC Height", snapshot.current_bitcoin_block_height]);
        contextItems.push(["STX Height", snapshot.current_stacks_block_height]);
        contextItems.push(["Consensus Hash", snapshot.current_consensus_hash]);
        contextItems.push(["Burn Height", snapshot.current_consensus_burn_height]);
        contextItems.push(["Active Stalls", (snapshot.active_stalls || []).join(", ") || "none"]);
        contextItems.push(["Open Proposals", snapshot.open_proposals_count]);
        contextItems.push(["Mempool Ready Txs", snapshot.mempool_ready_txs]);
        contextItems.push(["Last Tenure Extend", snapshot.last_tenure_extend_kind || "-"]);
        contextItems.push(["Last Tenure Extend Age", snapshot.last_tenure_extend_age_seconds ? Math.round(snapshot.last_tenure_extend_age_seconds) + "s" : "-"]);
      }
      const contextBody = document.getElementById("contextBody");
      contextBody.innerHTML = contextItems.length
        ? contextItems.map((pair) => {
            const label = escapeHtml(pair[0]);
            const value = pair[1] === null || pair[1] === undefined || pair[1] === "" ? "-" : escapeHtml(pair[1]);
            return "<div class='kv-row'><span class='muted'>" + label + "</span><span class='value'>" + value + "</span></div>";
          }).join("")
        : "<div class='muted'>No snapshot data.</div>";

      const alerts = (report.data && report.data.recent_alerts) || [];
      alerts.sort((a, b) => (b.ts || 0) - (a.ts || 0));
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
        document.getElementById("eventsBody").innerHTML = events.map((item) => {
          const details = item.data ? JSON.stringify(item.data) : (item.line || "");
          return "<div class='event-row'>" +
            "<div class='event-head'><span class='mono'>" + escapeHtml(item.kind || "") + "</span><span class='muted'>" + escapeHtml(fmtTime(item.ts)) + "</span></div>" +
            "<div class='muted'>Source: " + escapeHtml(item.source || "") + "</div>" +
            "<details class='event-details'><summary>Details</summary><pre>" + escapeHtml(details) + "</pre></details>" +
            "</div>";
        }).join("");
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
