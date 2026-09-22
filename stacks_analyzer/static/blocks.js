// Block fullness renderer, shared by the dashboard card and the /blocks page.
//
// Takes block records as served by /api/blocks (or `recent_execution_costs`
// in /api/state) and renders one row per confirmed Stacks block. The cost the
// node logs for a block is the tenure budget consumed through that block, so
// each row shows that running usage ("budget used") next to what the block
// itself added ("this block"), with a marker where a tenure change or extend
// reset the budget.
(function () {
  const DIMENSIONS = [
    { key: "runtime", label: "Runtime", short: "rt", color: "#f59e0b" },
    { key: "write_len", label: "Write Len", short: "wl", color: "#22d3ee" },
    { key: "write_cnt", label: "Write Cnt", short: "wc", color: "#a78bfa" },
    { key: "read_len", label: "Read Len", short: "rl", color: "#34d399" },
    { key: "read_cnt", label: "Read Cnt", short: "rc", color: "#fb7185" },
  ];

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

  function fmtAge(seconds) {
    if (!isNum(seconds)) return "-";
    const n = Math.max(0, Number(seconds));
    if (n < 60) return Math.round(n) + "s";
    if (n < 3600) return Math.floor(n / 60) + "m " + Math.round(n % 60) + "s";
    if (n < 86400) return Math.floor(n / 3600) + "h " + Math.floor((n % 3600) / 60) + "m";
    return Math.floor(n / 86400) + "d " + Math.floor((n % 86400) / 3600) + "h";
  }

  function fmtClock(ts) {
    if (!isNum(ts)) return "-";
    return new Date(Number(ts) * 1000).toLocaleString();
  }

  function fmtStx(microstacks) {
    if (!isNum(microstacks)) return "-";
    const stx = Number(microstacks) / 1e6;
    if (stx === 0) return "0";
    if (stx < 0.01) return stx.toFixed(4);
    if (stx < 1) return stx.toFixed(3);
    return stx.toLocaleString(undefined, { maximumFractionDigits: 2 });
  }

  function fmtBytes(bytes) {
    if (!isNum(bytes)) return "-";
    const n = Number(bytes);
    if (n < 1024) return n + " B";
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
    return (n / (1024 * 1024)).toFixed(2) + " MB";
  }

  function fillColor(pct) {
    if (pct >= 85) return "#ef4444";
    if (pct >= 70) return "#f59e0b";
    return "#38bdf8";
  }

  function largest(percentMap) {
    if (!percentMap) return null;
    let best = null;
    for (const dim of DIMENSIONS) {
      const value = percentMap[dim.key];
      if (!isNum(value)) continue;
      if (best === null || Number(value) > best.pct) best = { dim, pct: Number(value) };
    }
    return best;
  }

  function breakdown(block, limits) {
    const costs = block.costs || {};
    const pct = block.costs_percent || {};
    const delta = block.costs_delta || {};
    const deltaPct = block.costs_delta_percent || {};
    const lines = [];
    for (const dim of DIMENSIONS) {
      const raw = costs[dim.key];
      const limit = limits ? limits[dim.key] : undefined;
      let line = dim.label + ": ";
      if (isNum(raw)) {
        line += Number(raw).toLocaleString();
        if (isNum(limit)) line += " / " + Number(limit).toLocaleString();
        if (isNum(pct[dim.key])) line += " (" + Number(pct[dim.key]).toFixed(1) + "%)";
      } else {
        line += "-";
      }
      if (isNum(delta[dim.key])) {
        line += "  this block +" + Number(delta[dim.key]).toLocaleString();
        if (isNum(deltaPct[dim.key])) line += " (+" + Number(deltaPct[dim.key]).toFixed(2) + "%)";
      }
      lines.push(line);
    }
    if (block.block_header_hash) lines.push("hash " + block.block_header_hash);
    if (block.consensus_hash) lines.push("tenure " + block.consensus_hash);
    if (isNum(block.validation_time_ms)) lines.push("validated in " + block.validation_time_ms + " ms");
    return lines.join("\n");
  }

  function dimensionBars(percentMap, opts) {
    const scale = opts && opts.scale ? Number(opts.scale) : 100;
    return (
      "<span class='bf-dims'>" +
      DIMENSIONS.map((dim) => {
        const value = percentMap && isNum(percentMap[dim.key]) ? Number(percentMap[dim.key]) : 0;
        const height = Math.max(value > 0 ? 1 : 0, Math.min(100, (value / scale) * 100));
        return (
          "<span class='bf-dim' title='" + esc(dim.label + " " + value.toFixed(1) + "%") + "'>" +
          "<span class='bf-dim-fill' style='height:" + height.toFixed(1) + "%; background:" + dim.color + ";'></span>" +
          "</span>"
        );
      }).join("") +
      "</span>"
    );
  }

  function heightCell(block, opts) {
    const height = block.block_height;
    if (!isNum(height)) return "<td class='mono'>-</td>";
    const internal = "/blocks?height=" + encodeURIComponent(height);
    const external = "https://explorer.hiro.so/block/" + encodeURIComponent(height);
    const label = Number(height).toLocaleString();
    const inner = opts.linkHeights === false
      ? "<span class='mono'>" + esc(label) + "</span>"
      : "<a class='link mono' href='" + internal + "'>" + esc(label) + "</a>";
    return (
      "<td class='bf-height'>" + inner +
      " <a class='link bf-ext' href='" + external + "' target='_blank' rel='noopener noreferrer' title='Open in explorer'>&#8599;</a>" +
      "</td>"
    );
  }

  function burnCell(block) {
    const tenure = block.burn_height;
    const tip = block.tip_burn_height;
    if (!isNum(tenure) && !isNum(tip)) return "<td class='mono'>-</td>";
    const primary = isNum(tenure) ? Number(tenure) : Number(tip);
    let html = "<a class='link mono' href='/blocks?burn_height=" + encodeURIComponent(primary) + "' title='" +
      (isNum(tenure) ? "Bitcoin block whose sortition started this tenure" : "Bitcoin tip when this block was confirmed") +
      "'>" + esc(primary.toLocaleString()) + "</a>";
    if (isNum(tenure) && isNum(tip) && Number(tip) !== Number(tenure)) {
      html += " <span class='muted bf-tip' title='Bitcoin tip when this block was confirmed'>+" + (Number(tip) - Number(tenure)) + "</span>";
    }
    return "<td class='bf-burn'>" + html + "</td>";
  }

  function usageCell(block) {
    const top = largest(block.costs_percent);
    const pct = isNum(block.percent_full) ? Number(block.percent_full) : top ? top.pct : null;
    if (!isNum(pct)) return "<td class='bf-usage'><span class='muted'>-</span></td>";
    const width = Math.max(0, Math.min(100, pct));
    return (
      "<td class='bf-usage'>" +
      "<div class='bf-usage-row'>" +
      "<div class='bf-track'><div class='bf-fill' style='width:" + width.toFixed(1) + "%; background:" + fillColor(pct) + ";'></div></div>" +
      "<span class='bf-pct'>" + pct.toFixed(1) + "%</span>" +
      "</div>" +
      (top ? "<div class='bf-sub muted'>bound by " + esc(top.dim.label.toLowerCase()) + "</div>" : "") +
      "</td>"
    );
  }

  function deltaCell(block) {
    const reset = block.budget_reset === true;
    const top = largest(block.costs_delta_percent);
    if (!top && !reset) {
      return "<td class='bf-delta'><span class='muted' title='Previous height not observed'>-</span></td>";
    }
    let html = "";
    if (top) {
      html += "<span class='bf-delta-pct' style='color:" + top.dim.color + ";'>+" + top.pct.toFixed(2) + "%</span>";
      html += "<div class='bf-sub muted'>" + esc(top.dim.label.toLowerCase()) + "</div>";
    }
    if (reset) {
      html += "<span class='bf-reset' title='Budget reset: first block of a new tenure or after a tenure extend'>&#8635; reset</span>";
    }
    return "<td class='bf-delta'>" + html + "</td>";
  }

  function rowHtml(block, opts) {
    const nowEpoch = opts.nowEpoch || Date.now() / 1000;
    const age = isNum(block.ts) ? nowEpoch - Number(block.ts) : null;
    const seen = opts.absoluteTime
      ? fmtClock(block.ts)
      : (isNum(age) ? fmtAge(age) + " ago" : "-");
    const tooltip = breakdown(block, opts.limits);
    return (
      "<tr class='bf-row' title='" + esc(tooltip) + "'>" +
      heightCell(block, opts) +
      burnCell(block) +
      "<td class='bf-seen' title='" + esc(fmtClock(block.ts)) + "'>" + esc(seen) + "</td>" +
      "<td class='bf-num'>" + (isNum(block.tx_count) ? esc(block.tx_count) : "-") + "</td>" +
      "<td class='bf-num'>" + esc(fmtStx(block.tx_fees_microstacks)) + "</td>" +
      "<td class='bf-num'>" + esc(fmtBytes(block.block_size)) + "</td>" +
      usageCell(block) +
      "<td class='bf-dims-cell'>" + dimensionBars(block.costs_percent) + "</td>" +
      deltaCell(block) +
      "</tr>"
    );
  }

  function headerHtml() {
    return (
      "<tr>" +
      "<th>Height</th>" +
      "<th title='Bitcoin block whose sortition started the tenure; +N when the block was confirmed N Bitcoin blocks later'>BTC</th>" +
      "<th>Seen</th>" +
      "<th class='bf-num'>Txs</th>" +
      "<th class='bf-num'>Fees (STX)</th>" +
      "<th class='bf-num'>Size</th>" +
      "<th title='Tenure budget consumed through this block, largest dimension'>Budget used</th>" +
      "<th title='Runtime, write len, write cnt, read len, read cnt'>Dims</th>" +
      "<th title='What this block alone added, largest dimension'>This block</th>" +
      "</tr>"
    );
  }

  function renderTable(container, blocks, opts) {
    const options = opts || {};
    if (!container) return;
    const rows = Array.isArray(blocks) ? blocks : [];
    if (!rows.length) {
      container.innerHTML = "<div class='muted'>" + esc(options.emptyText || "No confirmed blocks yet.") + "</div>";
      return;
    }
    container.innerHTML =
      "<div class='bf-scroll'><table class='bf-table'>" +
      "<thead>" + headerHtml() + "</thead>" +
      "<tbody>" + rows.map((block) => rowHtml(block, options)).join("") + "</tbody>" +
      "</table></div>";
  }

  function legendHtml() {
    return DIMENSIONS.map((dim) =>
      "<span><span class='legend-dot' style='background:" + dim.color + ";'></span>" + esc(dim.label) + "</span>"
    ).join("");
  }

  window.BlockFullness = {
    DIMENSIONS,
    renderTable,
    rowHtml,
    headerHtml,
    legendHtml,
    largest,
    fmtStx,
    fmtBytes,
    fmtAge,
  };
})();
