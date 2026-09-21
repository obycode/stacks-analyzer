// Stall diagnostics renderer, shared by the dashboard and the report page.
//
// Takes one entry from `stall_diagnostics.active` / `.recent` in /api/state
// (or `report.data.stall_diagnostics`) and renders the shape of the stall:
// where in the tenure it sat, who should have been mining, what Bitcoin and
// the mempool were doing, and whether a proposal was stuck with the signers.
(function () {
  function esc(value) {
    return String(value)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll("\"", "&quot;")
      .replaceAll("'", "&#39;");
  }

  function isNum(value) {
    return value !== null && value !== undefined && Number.isFinite(Number(value));
  }

  function fmtSeconds(value) {
    if (!isNum(value)) return "-";
    const n = Math.max(0, Number(value));
    if (n < 60) return Math.round(n) + "s";
    if (n < 3600) return Math.floor(n / 60) + "m " + Math.round(n % 60) + "s";
    return Math.floor(n / 3600) + "h " + Math.floor((n % 3600) / 60) + "m";
  }

  function fmtClock(ts) {
    if (!isNum(ts)) return "-";
    const date = new Date(Number(ts) * 1000);
    const today = new Date();
    const sameDay = date.toDateString() === today.toDateString();
    return sameDay ? date.toLocaleTimeString() : date.toLocaleString();
  }

  function shortHash(value, size) {
    if (!value) return "-";
    const text = String(value);
    return text.length <= size ? text : text.slice(0, size) + "..";
  }

  function extLink(url, label) {
    return (
      "<a class='link' href='" + esc(url) + "' target='_blank' rel='noopener noreferrer'>" +
      label +
      "</a>"
    );
  }

  function stxBlockLink(height) {
    if (!isNum(height)) return "-";
    return extLink("https://explorer.hiro.so/block/" + encodeURIComponent(height), esc(height));
  }

  function btcBlockLink(height) {
    if (!isNum(height)) return "-";
    return extLink("https://explorer.hiro.so/btcblock/" + encodeURIComponent(height), esc(height));
  }

  function minerLink(address) {
    if (!address) return "-";
    const text = String(address);
    const looksBtc = text.startsWith("bc1") || text.startsWith("1") || text.startsWith("3");
    const label = "<span class='mono'>" + esc(shortHash(text, 20)) + "</span>";
    if (!looksBtc) return label;
    return extLink("https://mempool.space/address/" + encodeURIComponent(text), label);
  }

  function tile(label, value, note, tone) {
    return (
      "<div class='stall-tile" + (tone ? " stall-tile-" + tone : "") + "'>" +
      "<div class='stall-tile-label'>" + esc(label) + "</div>" +
      "<div class='stall-tile-value'>" + value + "</div>" +
      (note ? "<div class='stall-tile-note'>" + note + "</div>" : "") +
      "</div>"
    );
  }

  function positionLabel(tenure) {
    const position = tenure && tenure.position;
    if (position === "tenure_start") return "Start of tenure";
    if (position === "mid_tenure") return "Mid-tenure";
    return "Unknown";
  }

  function tiles(diag) {
    const stacks = diag.stacks || {};
    const bitcoin = diag.bitcoin || {};
    const tenure = diag.tenure || {};
    const miner = diag.miner || {};
    const mempool = diag.mempool || {};
    const proposals = diag.proposals || {};
    const out = [];

    // Tenure position
    const blocksIn = tenure.blocks_in_tenure;
    const positionNote = [];
    if (tenure.position === "tenure_start") {
      positionNote.push("no block yet, " + fmtSeconds(miner.sortition_age_seconds) + " since sortition");
    } else if (isNum(blocksIn)) {
      positionNote.push(blocksIn + " block" + (Number(blocksIn) === 1 ? "" : "s") + " so far");
    }
    if (isNum(tenure.age_seconds) && tenure.position !== "tenure_start") {
      positionNote.push("tenure age " + fmtSeconds(tenure.age_seconds));
    }
    out.push(
      tile(
        "Tenure position",
        esc(positionLabel(tenure)),
        esc(positionNote.join(" | ")),
        tenure.position === "tenure_start" ? "warn" : null
      )
    );

    // Expected miner
    const minerNote = [];
    if (isNum(miner.expected_burn_height)) minerNote.push("won burn " + btcBlockLink(miner.expected_burn_height));
    if (miner.signer_view_pkh) {
      minerNote.push("signer view pkh <span class='mono'>" + esc(shortHash(miner.signer_view_pkh, 12)) + "</span>");
    }
    if (isNum(miner.signer_view_burn_height) && isNum(miner.expected_burn_height) &&
        Number(miner.signer_view_burn_height) < Number(miner.expected_burn_height)) {
      minerNote.push("signer view lags at burn " + esc(miner.signer_view_burn_height));
    }
    out.push(tile("Expected miner", minerLink(miner.expected_apparent_sender), minerNote.join(" | ")));

    // Last Stacks block
    const stxNote = [];
    if (isNum(stacks.last_confirmed_age_seconds)) stxNote.push(fmtSeconds(stacks.last_confirmed_age_seconds) + " before detection");
    if (isNum(stacks.highest_height_seen) && isNum(stacks.last_confirmed_height) &&
        Number(stacks.highest_height_seen) > Number(stacks.last_confirmed_height)) {
      stxNote.push("height " + esc(stacks.highest_height_seen) + " proposed, unconfirmed");
    }
    out.push(tile("Last Stacks block", stxBlockLink(stacks.last_confirmed_height), stxNote.join(" | ")));

    // Bitcoin height
    const btcNote = [];
    if (isNum(bitcoin.last_burn_block_age_seconds)) btcNote.push("last burn block " + fmtSeconds(bitcoin.last_burn_block_age_seconds) + " before detection");
    if (isNum(bitcoin.last_burn_interval_seconds)) btcNote.push("prior gap " + fmtSeconds(bitcoin.last_burn_interval_seconds));
    out.push(tile("Bitcoin height", btcBlockLink(bitcoin.height), btcNote.join(" | ")));

    // Reorg
    const reorg = bitcoin.reorg;
    out.push(
      reorg
        ? tile(
            "Bitcoin reorg",
            "Yes",
            "ancestor " + btcBlockLink(reorg.common_ancestor_height) + ", " + fmtSeconds(reorg.age_seconds) + " before detection" +
              (Number(reorg.count) > 1 ? " (" + esc(reorg.count) + " reorgs)" : ""),
            "critical"
          )
        : tile("Bitcoin reorg", "No", "none in lookback window")
    );

    // Flash block
    const flash = bitcoin.flash_block || {};
    const pairs = flash.pairs || [];
    out.push(
      flash.seen
        ? tile(
            "Flash block",
            "Yes",
            pairs
              .map((pair) => btcBlockLink(pair.from_height) + " &rarr; " + btcBlockLink(pair.to_height) + " in " + fmtSeconds(pair.interval_seconds))
              .join("; "),
            "warn"
          )
        : tile("Flash block", "No", isNum(flash.threshold_seconds) ? "no burn blocks under " + esc(flash.threshold_seconds) + "s apart" : "")
    );

    // Mempool
    const ready = mempool.ready_txs;
    const mempoolNote = [];
    if (isNum(mempool.ready_age_seconds)) mempoolNote.push("sampled " + fmtSeconds(mempool.ready_age_seconds) + " before detection");
    if (mempool.stop_reason) mempoolNote.push(esc(mempool.stop_reason));
    if (isNum(mempool.max_considered_in_window) && Number(mempool.max_considered_in_window) > 0) {
      mempoolNote.push("up to " + esc(mempool.max_considered_in_window) + " considered in window");
    }
    out.push(
      tile(
        "Mempool ready txs",
        isNum(ready) ? esc(ready) : "-",
        mempoolNote.join(" | "),
        isNum(ready) && Number(ready) > 0 ? "warn" : null
      )
    );

    // Open proposals
    const open = proposals.open || [];
    const first = open[0];
    out.push(
      tile(
        "Open proposals",
        esc(isNum(proposals.open_count) ? proposals.open_count : open.length),
        first
          ? "height " + esc(first.block_height ?? "?") + ", " + fmtSeconds(first.age_seconds) + " old" +
              (first.phase ? "<br/>" + esc(first.phase) : "")
          : "miner is not proposing",
        open.length ? "warn" : null
      )
    );

    // Burn blocks since last block
    const since = bitcoin.burn_blocks_since_last_stacks_block || [];
    out.push(
      tile(
        "Burn blocks since last block",
        esc(since.length),
        since.map((row) => btcBlockLink(row.burn_height) + " " + esc(row.outcome || "?")).join("<br/>"),
        since.length ? "warn" : null
      )
    );

    // Last tenure extend
    const extend = tenure.last_extend;
    const extendNote = [];
    if (extend && isNum(extend.age_seconds)) extendNote.push(fmtSeconds(extend.age_seconds) + " before detection");
    if (isNum(tenure.extend_overdue_seconds) && Number(tenure.extend_overdue_seconds) > 0 && !(extend && extend.after_last_block)) {
      extendNote.push("network eligible " + fmtSeconds(tenure.extend_overdue_seconds) + " ago");
    }
    out.push(tile("Last tenure extend", extend ? esc(extend.kind || "extend") : "none seen", extendNote.join(" | ")));

    if (diag.active === false) {
      const recoveredNote = [];
      if (isNum(diag.recovered_ts)) recoveredNote.push("at " + esc(fmtClock(diag.recovered_ts)));
      if (isNum(diag.recovered_height)) recoveredNote.push("height " + stxBlockLink(diag.recovered_height));
      out.push(tile("Recovered", "after " + fmtSeconds(diag.duration_seconds), recoveredNote.join(" | "), "ok"));
    }
    return out.join("");
  }

  function detailsSections(diag) {
    const proposals = diag.proposals || {};
    const open = proposals.open || [];
    const rejections = proposals.recent_rejections || [];
    const warnings = diag.log_warnings || [];
    const parts = [];
    if (open.length) {
      parts.push(
        "<details class='stall-details'><summary>Open proposals (" + open.length + ")</summary>" +
          "<table><thead><tr><th>Height</th><th>Age</th><th>Phase</th><th>Accept / Reject</th><th>Sig</th></tr></thead><tbody>" +
          open
            .map(
              (row) =>
                "<tr><td>" + esc(row.block_height ?? "-") + "</td><td>" + fmtSeconds(row.age_seconds) + "</td><td>" +
                esc(row.phase || "-") + "</td><td>" + esc(Number(row.max_percent_observed || 0).toFixed(1)) + "% / " +
                esc(Number(row.max_reject_percent || 0).toFixed(1)) + "%" +
                (row.reject_reasons && row.reject_reasons.length ? " (" + esc(row.reject_reasons.join(", ")) + ")" : "") +
                "</td><td class='mono'>" + esc(shortHash(row.signature_hash, 12)) + "</td></tr>"
            )
            .join("") +
          "</tbody></table></details>"
      );
    }
    if (rejections.length) {
      parts.push(
        "<details class='stall-details'><summary>Recent rejections (" + rejections.length + ")</summary>" +
          "<table><thead><tr><th>Time</th><th>Height</th><th>Reason</th><th>Reject %</th></tr></thead><tbody>" +
          rejections
            .map(
              (row) =>
                "<tr><td>" + esc(fmtClock(row.ts)) + "</td><td>" + esc(row.block_height ?? "-") + "</td><td>" +
                esc(row.reject_reason || "-") + "</td><td>" + esc(Number(row.max_reject_percent || 0).toFixed(1)) + "%</td></tr>"
            )
            .join("") +
          "</tbody></table></details>"
      );
    }
    if (warnings.length) {
      parts.push(
        "<details class='stall-details'><summary>Warnings and errors in window (" + warnings.length + ")</summary>" +
          "<div class='stall-log'>" +
          warnings
            .map(
              (row) =>
                "<div class='stall-log-row'><span class='muted'>" + esc(fmtClock(row.ts)) + " " + esc(row.source || "") +
                "</span> <span class='mono'>" + esc(row.line || "") + "</span></div>"
            )
            .join("") +
          "</div></details>"
      );
    }
    return parts.join("");
  }

  function render(diag, options) {
    const opts = options || {};
    if (!diag || typeof diag !== "object") {
      return "<div class='muted'>" + esc(opts.emptyText || "No stall diagnostics available.") + "</div>";
    }
    const active = diag.active !== false;
    const sev = active ? String(diag.severity || "critical").toLowerCase() : "ok";
    const badge = "<span class='sev sev-" + esc(sev) + "'>" + (active ? "active" : "resolved") + "</span>";
    const kindLabel = diag.kind === "signer" ? "signer stall" : "node stall";
    const factors = (diag.factors || []).map((text) => "<span class='stall-factor'>" + esc(text) + "</span>").join("");
    const headMeta = [
      esc(kindLabel),
      "detected " + esc(fmtClock(diag.detected_ts)),
      active
        ? "stalled " + fmtSeconds(diag.gap_seconds) + " (threshold " + fmtSeconds(diag.threshold_seconds) + ")"
        : "lasted " + fmtSeconds(diag.duration_seconds),
    ];
    if (opts.reportUrl) {
      headMeta.push("<a class='link' href='" + esc(opts.reportUrl) + "'>report</a>");
    }
    return (
      "<div class='stall-head'>" +
      badge +
      "<span class='stall-shape'>" + esc(diag.shape_label || diag.shape || "Unknown shape") + "</span>" +
      "<span class='stall-head-meta muted'>" + headMeta.join(" &middot; ") + "</span>" +
      "</div>" +
      (factors ? "<div class='stall-factors'>" + factors + "</div>" : "") +
      "<div class='stall-grid'>" + tiles(diag) + "</div>" +
      detailsSections(diag)
    );
  }

  function historyTable(entries, reportUrlFor) {
    if (!entries || !entries.length) return "";
    const rows = entries
      .map((diag) => {
        const url = reportUrlFor ? reportUrlFor(diag) : null;
        const status = diag.active === false ? "resolved" : "active";
        return (
          "<tr><td>" + esc(fmtClock(diag.detected_ts)) + "</td><td>" + esc(diag.kind === "signer" ? "signer" : "node") +
          "</td><td>" + esc(diag.shape_label || diag.shape || "-") + "</td><td>" +
          (diag.active === false ? fmtSeconds(diag.duration_seconds) : fmtSeconds(diag.gap_seconds) + " so far") +
          "</td><td>" + esc(positionLabel(diag.tenure)) + "</td><td>" + minerLink((diag.miner || {}).expected_apparent_sender) +
          "</td><td>" + esc(status) + (url ? " &middot; <a class='link' href='" + esc(url) + "'>report</a>" : "") + "</td></tr>"
        );
      })
      .join("");
    return (
      "<table class='stall-history'><thead><tr><th>Detected</th><th>Kind</th><th>Shape</th><th>Duration</th><th>Position</th><th>Miner</th><th>Status</th></tr></thead><tbody>" +
      rows +
      "</tbody></table>"
    );
  }

  window.StallView = { render: render, historyTable: historyTable, fmtSeconds: fmtSeconds };
})();
