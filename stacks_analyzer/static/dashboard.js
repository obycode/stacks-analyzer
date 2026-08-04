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

    function escapeAttr(value) {
      return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("\"", "&quot;")
        .replaceAll("'", "&#39;")
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

    function hashString(value) {
      let hash = 0;
      for (let i = 0; i < value.length; i += 1) {
        hash = (hash * 31 + value.charCodeAt(i)) >>> 0;
      }
      return hash;
    }

    function minerKey(item) {
      return item.apparent_sender || item.commit_txid || "";
    }

    function minerColor(key) {
      if (!key) return "#94a3b8";
      const hash = hashString(key);
      const hue = (hash * 137.508) % 360;
      const sat = 78;
      const light = 56;
      return "hsl(" + hue.toFixed(0) + ", " + sat + "%, " + light + "%)";
    }

    function minerName(key) {
      if (!key) return "Miner ?";
      const letter = String.fromCharCode(65 + (hashString(key) % 26));
      return "Miner " + letter;
    }

    function formatSecondsTick(value, range) {
      if (!Number.isFinite(value)) return "-";
      const absRange = Math.abs(range || 0);
      if (absRange < 2) return value.toFixed(1) + "s";
      if (absRange < 10) return Math.round(value) + "s";
      return Math.round(value) + "s";
    }

    function formatCountTick(value, range) {
      if (!Number.isFinite(value)) return "-";
      if (Math.abs(range || 0) < 2) return value.toFixed(1);
      return Math.round(value).toString();
    }

    function formatStxFromMicro(micro) {
      if (!Number.isFinite(Number(micro))) return "-";
      const stx = Number(micro) / 1_000_000;
      if (stx >= 1000) return stx.toLocaleString(undefined, { maximumFractionDigits: 1 }) + " STX";
      if (stx >= 10) return stx.toFixed(1) + " STX";
      return stx.toFixed(3) + " STX";
    }

    function formatTxMix(counts) {
      const safe = counts && typeof counts === "object" ? counts : {};
      const pairs = [
        ["transfer", "transfer"],
        ["contract_call", "call"],
        ["contract_deploy", "deploy"],
        ["coinbase", "coinbase"],
        ["tenure_change", "tenure-change"],
        ["other", "other"],
      ];
      return pairs
        .map(([key, label]) => {
          const value = Number(safe[key]) || 0;
          return label + " " + value.toLocaleString(undefined);
        })
        .join(" | ");
    }

    function formatSats(value) {
      if (!Number.isFinite(Number(value))) return "-";
      return Number(value).toLocaleString(undefined) + " sats";
    }

    function formatWindowTick(seconds) {
      if (!Number.isFinite(seconds) || seconds <= 0) return "now";
      if (seconds < 60) return Math.round(seconds) + "s";
      if (seconds < 3600) return Math.round(seconds / 60) + "m";
      if (seconds < 86400) return Math.round(seconds / 3600) + "h";
      return Math.round(seconds / 86400) + "d";
    }

    const blockCadenceHistory = [];
    const mempoolHistory = [];
    const REPORTS_PAGE_SIZE = 5;
    let reportsPage = 0;
    let reportsNewestFirst = [];
    let lastBlockHeight = null;
    let lastMempoolEventTs = null;
    let lastMempoolSampleKey = null;
    let seededBlockCadence = false;
    let seededMempoolHistory = false;
    const COST_DIMENSIONS = [
      { key: "runtime", label: "Runtime", color: "#f59e0b" },
      { key: "write_len", label: "Write Len", color: "#22d3ee" },
      { key: "write_cnt", label: "Write Cnt", color: "#a78bfa" },
      { key: "read_len", label: "Read Len", color: "#34d399" },
      { key: "read_cnt", label: "Read Cnt", color: "#fb7185" },
    ];

    function pushHistory(list, item, maxLen) {
      list.push(item);
      while (list.length > maxLen) list.shift();
    }

    function seedBlockCadenceFromState(data) {
      if (seededBlockCadence || blockCadenceHistory.length) return;
      const all = (data.recent_confirmed_blocks || [])
        .filter((item) => Number.isFinite(Number(item && item.ts)))
        .slice()
        .sort((a, b) => Number(a.ts) - Number(b.ts));
      if (!all.length) return;
      const byBlock = new Map();
      for (const item of all) {
        let key = null;
        const blockHeight = Number(item && item.block_height);
        if (Number.isFinite(blockHeight)) {
          key = "h:" + blockHeight + ":" + String((item && item.consensus_hash) || "");
        } else if (item && item.block_id) {
          key = "id:" + String(item.block_id);
        } else if (item && item.block_header_hash) {
          key = "hdr:" + String(item.block_header_hash);
        } else if (item && item.consensus_hash) {
          key = "c:" + String(item.consensus_hash) + ":" + String(Math.floor(Number(item.ts)));
        }
        if (!key) continue;
        const existing = byBlock.get(key);
        if (!existing) {
          byBlock.set(key, item);
          continue;
        }
        const existingIsNode = existing.source === "node";
        const itemIsNode = item.source === "node";
        if (!existingIsNode && itemIsNode) {
          byBlock.set(key, item);
          continue;
        }
        if (existingIsNode === itemIsNode && Number(item.ts) < Number(existing.ts)) {
          byBlock.set(key, item);
        }
      }
      const deduped = Array.from(byBlock.values()).sort(
        (a, b) => Number(a.ts) - Number(b.ts)
      );
      const nodeOnly = deduped.filter((item) => item.source === "node");
      const source = nodeOnly.length >= 2 ? nodeOnly : deduped;
      for (let i = 1; i < source.length; i += 1) {
        const prevTs = Number(source[i - 1].ts);
        const ts = Number(source[i].ts);
        const interval = ts - prevTs;
        if (Number.isFinite(interval) && interval >= 0.25 && interval <= 600) {
          pushHistory(
            blockCadenceHistory,
            {
              value: interval,
              ts,
            },
            120
          );
        }
      }
      seededBlockCadence = true;
    }

    function seedMempoolFromState(data) {
      if (seededMempoolHistory || mempoolHistory.length) return;
      const rows = (data.recent_mempool_iterations || [])
        .filter((item) => Number.isFinite(Number(item && item.ts)))
        .slice()
        .sort((a, b) => Number(a.ts) - Number(b.ts));
      if (!rows.length) return;
      for (const row of rows) {
        const considered = Number(row && row.considered_txs);
        if (!Number.isFinite(considered)) continue;
        pushHistory(
          mempoolHistory,
          {
            value: considered,
            ts: Number(row.ts),
            deadline: row.stop_reason === "DeadlineReached",
          },
          160
        );
      }
      if (mempoolHistory.length) {
        const lastRow = rows[rows.length - 1];
        lastMempoolEventTs = mempoolHistory[mempoolHistory.length - 1].ts;
        lastMempoolSampleKey =
          String(Number(lastRow.ts)) +
          "|" +
          String(Number(lastRow.considered_txs)) +
          "|" +
          String(lastRow.stop_reason || "");
      }
      seededMempoolHistory = true;
    }

    function renderSparkline(svgId, series, options) {
      const svg = document.getElementById(svgId);
      if (!svg) return;
      if (!series.length) {
        svg.innerHTML = "";
        return;
      }
      const rect = svg.getBoundingClientRect();
      const width = Math.max(180, Math.round(rect.width || svg.clientWidth || 0));
      const height = Math.max(48, Math.round(rect.height || svg.clientHeight || 0));
      svg.setAttribute("viewBox", "0 0 " + width + " " + height);
      svg.setAttribute("preserveAspectRatio", "xMinYMin meet");
      const topPad = 8;
      const rightPad = 8;
      const bottomPad = options && options.showXAxis ? 16 : 8;
      const labelPad = 4;
      const values = series.map((item) => item.value);
      const minValue = options && options.minZero ? 0 : Math.min(...values);
      const maxValue = Math.max(...values);
      const range = maxValue - minValue || 1;
      const labelFor = options && options.labelFormat
        ? (value, meta) => options.labelFormat(value, meta)
        : (value) => String(value);
      const meta = { min: minValue, max: maxValue, range };
      let maxLabel = labelFor(maxValue, meta);
      let midLabel = labelFor(minValue + range / 2, meta);
      let minLabel = labelFor(minValue, meta);
      if (maxLabel === midLabel) midLabel = "";
      if (midLabel === minLabel) midLabel = "";
      const leftColumn = [maxLabel, midLabel, minLabel].filter((label) => label !== "");
      const leftWidth = Math.min(
        42,
        Math.max(24, ...leftColumn.map((label) => (String(label).length || 1) * 6.2))
      );
      const axisX = leftWidth + 2;
      const plotWidth = width - axisX - rightPad;
      const points = values.map((value, index) => {
        const x = axisX + (index / Math.max(1, values.length - 1)) * plotWidth;
        const y =
          height - bottomPad - ((value - minValue) / range) * (height - topPad - bottomPad);
        return [x, y];
      });
      const line = points
        .map((pt, index) => (index === 0 ? "M" : "L") + pt[0].toFixed(2) + " " + pt[1].toFixed(2))
        .join(" ");
      const area =
        line +
        " L " +
        points[points.length - 1][0].toFixed(2) +
        " " +
        (height - bottomPad).toFixed(2) +
        " L " +
        points[0][0].toFixed(2) +
        " " +
        (height - bottomPad).toFixed(2) +
        " Z";
      let markers = "";
      if (options && options.markerKey) {
        const markerKey = options.markerKey;
        markers = series.map((item, index) => {
          if (!item[markerKey]) return "";
          const x = axisX + (index / Math.max(1, values.length - 1)) * plotWidth;
          return (
            "<line x1='" +
            x.toFixed(2) +
            "' x2='" +
            x.toFixed(2) +
            "' y1='" +
            topPad +
            "' y2='" +
            (height - bottomPad) +
            "' stroke='rgba(239, 68, 68, 0.8)' stroke-width='1'/>"
          );
        }).join("");
      }
      const yTop = topPad;
      const yMid = (height - bottomPad + topPad) / 2;
      const yBot = height - bottomPad;
      const firstTs = Number(series[0] && series[0].ts);
      const lastTs = Number(series[series.length - 1] && series[series.length - 1].ts);
      const windowSeconds =
        Number.isFinite(firstTs) && Number.isFinite(lastTs) ? Math.max(0, lastTs - firstTs) : null;
      const xLeft = windowSeconds === null ? "" : "-" + formatWindowTick(windowSeconds);
      const xRight = windowSeconds === null ? "" : "now";
      svg.innerHTML =
        "<line x1='" + axisX + "' x2='" + axisX + "' y1='" + yTop + "' y2='" + yBot + "' stroke='rgba(148, 163, 184, 0.24)' stroke-width='0.6' />" +
        "<line x1='" + axisX + "' x2='" + (axisX + plotWidth) + "' y1='" + yTop + "' y2='" + yTop + "' stroke='rgba(148, 163, 184, 0.2)' stroke-width='0.6' />" +
        "<line x1='" + axisX + "' x2='" + (axisX + plotWidth) + "' y1='" + yMid + "' y2='" + yMid + "' stroke='rgba(148, 163, 184, 0.16)' stroke-width='0.6' />" +
        "<line x1='" + axisX + "' x2='" + (axisX + plotWidth) + "' y1='" + yBot + "' y2='" + yBot + "' stroke='rgba(148, 163, 184, 0.2)' stroke-width='0.6' />" +
        (maxLabel ? "<text class='chart-axis' x='" + (labelPad) + "' y='" + (yTop + 3) + "' fill='#94a3b8'>" + maxLabel + "</text>" : "") +
        (midLabel ? "<text class='chart-axis' x='" + (labelPad) + "' y='" + (yMid + 3) + "' fill='#94a3b8'>" + midLabel + "</text>" : "") +
        (minLabel ? "<text class='chart-axis' x='" + (labelPad) + "' y='" + (yBot + 3) + "' fill='#94a3b8'>" + minLabel + "</text>" : "") +
        (xLeft ? "<text class='chart-axis' x='" + axisX + "' y='" + (height - 2) + "' fill='#94a3b8'>" + xLeft + "</text>" : "") +
        (xRight ? "<text class='chart-axis' x='" + (axisX + plotWidth) + "' y='" + (height - 2) + "' text-anchor='end' fill='#94a3b8'>" + xRight + "</text>" : "") +
        "<path d='" + area + "' fill='rgba(56, 189, 248, 0.08)' />" +
        "<path d='" + line + "' fill='none' stroke='rgba(56, 189, 248, 0.9)' stroke-width='1.0' />" +
        markers;
    }

    function tenureChangeStyle(kind) {
      const text = String(kind || "").toLowerCase();
      if (text.includes("extendread")) {
        return { color: "#a855f7", dash: "3 3", label: "ExtendReadCount" };
      }
      if (text.includes("extendall")) {
        return { color: "#f59e0b", dash: "8 3", label: "ExtendAll" };
      }
      if (text.includes("blockfound")) {
        return { color: "#f97316", dash: "", label: "BlockFound" };
      }
      return { color: "#94a3b8", dash: "4 3", label: String(kind || "TenureChange") };
    }

    function renderExecutionCostTrend(svgId, samples, tenureChanges) {
      const svg = document.getElementById(svgId);
      if (!svg) return;
      if (!samples.length) {
        svg.innerHTML = "";
        return;
      }
      const rect = svg.getBoundingClientRect();
      const width = Math.max(180, Math.round(rect.width || svg.clientWidth || 0));
      const height = Math.max(48, Math.round(rect.height || svg.clientHeight || 0));
      svg.setAttribute("viewBox", "0 0 " + width + " " + height);
      svg.setAttribute("preserveAspectRatio", "xMinYMin meet");

      const topPad = 8;
      const rightPad = 8;
      const bottomPad = 16;
      const leftPad = 26;
      const plotWidth = width - leftPad - rightPad;
      const plotHeight = height - topPad - bottomPad;

      const yForPct = (pct) =>
        height - bottomPad - (Math.max(0, Math.min(100, Number(pct) || 0)) / 100) * plotHeight;
      const xForIdx = (idx, count) =>
        leftPad + (idx / Math.max(1, count - 1)) * plotWidth;

      const firstTs = Number(samples[0] && samples[0].ts);
      const lastTs = Number(samples[samples.length - 1] && samples[samples.length - 1].ts);
      const windowSeconds =
        Number.isFinite(firstTs) && Number.isFinite(lastTs) ? Math.max(0, lastTs - firstTs) : null;
      const xLeft = windowSeconds === null ? "" : "-" + formatWindowTick(windowSeconds);

      let changeMarkers = "";
      const hasWindow = Number.isFinite(firstTs) && Number.isFinite(lastTs) && lastTs > firstTs;
      if (Array.isArray(tenureChanges) && hasWindow) {
        const orderedChanges = tenureChanges
          .filter((item) => Number.isFinite(Number(item && item.ts)))
          .slice()
          .sort((a, b) => Number(a.ts) - Number(b.ts));
        const seenXs = new Set();
        changeMarkers = orderedChanges
          .map((item) => {
            const ts = Number(item.ts);
            if (ts < firstTs || ts > lastTs) return "";
            const ratio = (ts - firstTs) / (lastTs - firstTs);
            const x = leftPad + ratio * plotWidth;
            const xKey = Math.round(x);
            if (seenXs.has(xKey)) return "";
            seenXs.add(xKey);
            const kind = String(item.kind || "unknown");
            const style = tenureChangeStyle(kind);
            const title = "Tenure change: " + style.label + " at " + fmtWallClock(ts);
            const dashAttr = style.dash ? " stroke-dasharray='" + style.dash + "'" : "";
            return (
              "<line x1='" +
              x.toFixed(2) +
              "' x2='" +
              x.toFixed(2) +
              "' y1='" +
              yForPct(100).toFixed(2) +
              "' y2='" +
              yForPct(0).toFixed(2) +
              "' stroke='" +
              style.color +
              "' stroke-width='6.0' opacity='0.16'></line>" +
              "<line x1='" +
              x.toFixed(2) +
              "' x2='" +
              x.toFixed(2) +
              "' y1='" +
              yForPct(100).toFixed(2) +
              "' y2='" +
              yForPct(0).toFixed(2) +
              "' stroke='" +
              style.color +
              "' stroke-width='2.2'" +
              dashAttr +
              " opacity='1.0'><title>" +
              escapeHtml(title) +
              "</title></line>" +
              "<circle cx='" +
              x.toFixed(2) +
              "' cy='" +
              yForPct(100).toFixed(2) +
              "' r='2.8' fill='" +
              style.color +
              "' stroke='rgba(2, 6, 23, 0.9)' stroke-width='0.9'><title>" +
              escapeHtml(title) +
              "</title></circle>"
            );
          })
          .join("");
      }

      const grid =
        "<line x1='" + leftPad + "' x2='" + (leftPad + plotWidth) + "' y1='" + yForPct(100) + "' y2='" + yForPct(100) + "' stroke='rgba(148, 163, 184, 0.2)' stroke-width='0.6' />" +
        "<line x1='" + leftPad + "' x2='" + (leftPad + plotWidth) + "' y1='" + yForPct(50) + "' y2='" + yForPct(50) + "' stroke='rgba(148, 163, 184, 0.16)' stroke-width='0.6' />" +
        "<line x1='" + leftPad + "' x2='" + (leftPad + plotWidth) + "' y1='" + yForPct(0) + "' y2='" + yForPct(0) + "' stroke='rgba(148, 163, 184, 0.2)' stroke-width='0.6' />" +
        "<line x1='" + leftPad + "' x2='" + leftPad + "' y1='" + yForPct(100) + "' y2='" + yForPct(0) + "' stroke='rgba(148, 163, 184, 0.24)' stroke-width='0.6' />" +
        "<text class='chart-axis' x='3' y='" + (yForPct(100) + 3) + "' fill='#94a3b8'>100%</text>" +
        "<text class='chart-axis' x='7' y='" + (yForPct(50) + 3) + "' fill='#94a3b8'>50%</text>" +
        "<text class='chart-axis' x='10' y='" + (yForPct(0) + 3) + "' fill='#94a3b8'>0%</text>" +
        (xLeft ? "<text class='chart-axis' x='" + leftPad + "' y='" + (height - 2) + "' fill='#94a3b8'>" + xLeft + "</text>" : "") +
        "<text class='chart-axis' x='" + (leftPad + plotWidth) + "' y='" + (height - 2) + "' text-anchor='end' fill='#94a3b8'>now</text>";

      const lines = COST_DIMENSIONS.map((dim) => {
        const points = samples.map((sample, idx) => {
          const costs = sample.costs_percent || {};
          const pct = costs[dim.key];
          return [xForIdx(idx, samples.length), yForPct(pct)];
        });
        const path = points
          .map((pt, idx) => (idx === 0 ? "M" : "L") + pt[0].toFixed(2) + " " + pt[1].toFixed(2))
          .join(" ");
        const last = points[points.length - 1];
        return (
          "<path d='" +
          path +
          "' fill='none' stroke='" +
          dim.color +
          "' stroke-width='1.2' opacity='0.95' />" +
          "<circle cx='" +
          last[0].toFixed(2) +
          "' cy='" +
          last[1].toFixed(2) +
          "' r='1.7' fill='" +
          dim.color +
          "' />"
        );
      }).join("");

      svg.innerHTML = grid + changeMarkers + lines;
    }

    function renderTenureBlocksChart(svgId, tenuresRaw, tenureChanges) {
      const svg = document.getElementById(svgId);
      if (!svg) return;
      if (!Array.isArray(tenuresRaw) || !tenuresRaw.length) {
        svg.innerHTML = "";
        return;
      }

      const orderedTenures = tenuresRaw
        .slice()
        .filter((item) => item && typeof item === "object" && Number.isFinite(Number(item.block_count)))
        .sort((a, b) => Number(a.start_ts || 0) - Number(b.start_ts || 0));
      if (!orderedTenures.length) {
        svg.innerHTML = "";
        return;
      }
      const windowTenures = orderedTenures.slice(-8);
      if (!windowTenures.length) {
        svg.innerHTML = "";
        return;
      }

      const changeEvents = (tenureChanges || [])
        .slice()
        .filter((item) => Number.isFinite(Number(item && item.ts)))
        .sort((a, b) => Number(a.ts) - Number(b.ts));

      const rect = svg.getBoundingClientRect();
      const width = Math.max(180, Math.round(rect.width || svg.clientWidth || 0));
      const height = Math.max(64, Math.round(rect.height || svg.clientHeight || 0));
      svg.setAttribute("viewBox", "0 0 " + width + " " + height);
      svg.setAttribute("preserveAspectRatio", "xMinYMin meet");

      const topPad = 8;
      const rightPad = 36;
      const bottomPad = 30;
      const leftPad = 30;
      const plotWidth = width - leftPad - rightPad;
      const plotHeight = height - topPad - bottomPad;

      const tenureCount = windowTenures.length;
      const maxTxs = Math.max(1, ...windowTenures.map((item) => Number(item.tx_count_total) || 0));
      const maxCount = Math.max(maxTxs, 1);
      const maxFeeMicro = Math.max(0, ...windowTenures.map((item) => Number(item.fee_microstx_total) || 0));
      const maxFeeStx = maxFeeMicro > 0 ? maxFeeMicro / 1_000_000 : 1;
      const yForCount = (count) =>
        height - bottomPad - (Math.max(0, Number(count) || 0) / maxCount) * plotHeight;
      const yForFee = (feeMicro) =>
        height - bottomPad - ((Math.max(0, Number(feeMicro) || 0) / 1_000_000) / maxFeeStx) * plotHeight;
      const slotWidth = plotWidth / Math.max(1, tenureCount);
      const groupWidth = Math.max(16, slotWidth - 8);
      const barWidth = Math.max(8, groupWidth * 0.66);

      const bars = windowTenures
        .map((tenure, idx) => {
          const slotX = leftPad + idx * slotWidth;
          const xGroup = slotX + (slotWidth - groupWidth) / 2;
          const xBar = xGroup + (groupWidth - barWidth) / 2;
          const xCenter = slotX + slotWidth / 2;
          const blockCount = Number(tenure.block_count) || 0;
          const txCount = Number(tenure.tx_count_total) || 0;
          const feeMicro = Number(tenure.fee_microstx_total) || 0;
          const yTxTop = yForCount(txCount);
          const yBottom = yForCount(0);
          const hashLabel = tenure.consensus_hash === "unknown" ? "unknown" : shortHash(tenure.consensus_hash, 10);
          const typeCounts = tenure.tx_type_counts || {};
          const typeSummary = [
            "transfer=" + String(typeCounts.transfer || 0),
            "call=" + String(typeCounts.contract_call || 0),
            "deploy=" + String(typeCounts.contract_deploy || 0),
            "coinbase=" + String(typeCounts.coinbase || 0),
            "tenure_change=" + String(typeCounts.tenure_change || 0),
          ].join(", ");
          const tooltip =
            "tenure " +
            hashLabel +
            " | blocks " +
            blockCount +
            " | txs " +
            txCount +
            " | fees " +
            formatStxFromMicro(feeMicro) +
            " | start " +
            fmtWallClock(tenure.start_ts) +
            " | end " +
            fmtWallClock(tenure.end_ts) +
            " | tx types [" +
            typeSummary +
            "]";

          const markers = changeEvents
            .map((change) => {
              const ts = Number(change.ts);
              const startTs = Number(tenure.start_ts || 0);
              const nextStartTs = Number(
                idx < windowTenures.length - 1 ? windowTenures[idx + 1].start_ts : NaN
              );
              const fallbackEndTs = Number(tenure.end_ts || startTs);
              const hasNextStart =
                Number.isFinite(nextStartTs) && nextStartTs > startTs;
              if (hasNextStart) {
                if (ts < startTs || ts >= nextStartTs) return "";
              } else if (ts < startTs || ts > fallbackEndTs) {
                return "";
              }
              let ratio = 0.5;
              const intervalEndTs = hasNextStart ? nextStartTs : fallbackEndTs;
              if (
                Number.isFinite(startTs) &&
                Number.isFinite(intervalEndTs) &&
                intervalEndTs > startTs
              ) {
                ratio = (ts - startTs) / (intervalEndTs - startTs);
              }
              ratio = Math.max(0, Math.min(1, ratio));
              const markerY = yBottom - ratio * (yBottom - yTxTop);
              const style = tenureChangeStyle(change.kind);
              const markerTitle =
                "Tenure change: " + style.label + " at " + fmtWallClock(ts);
              const dashAttr = style.dash ? " stroke-dasharray='" + style.dash + "'" : "";
              return (
                "<line x1='" +
                xBar.toFixed(2) +
                "' x2='" +
                (xBar + barWidth).toFixed(2) +
                "' y1='" +
                markerY.toFixed(2) +
                "' y2='" +
                markerY.toFixed(2) +
                "' stroke='" +
                style.color +
                "' stroke-width='4.6' opacity='0.2'></line>" +
                "<line x1='" +
                xBar.toFixed(2) +
                "' x2='" +
                (xBar + barWidth).toFixed(2) +
                "' y1='" +
                markerY.toFixed(2) +
                "' y2='" +
                markerY.toFixed(2) +
                "' stroke='" +
                style.color +
                "' stroke-width='2.0'" +
                dashAttr +
                "><title>" +
                escapeHtml(markerTitle) +
                "</title></line>"
              );
            })
            .join("");

          const xLabelHash = tenure.consensus_hash === "unknown" ? "?" : tenure.consensus_hash.slice(0, 6);
          const burnHeightLabel =
            tenure.burn_height === null || tenure.burn_height === undefined
              ? "?"
              : String(tenure.burn_height);
          return (
            "<rect x='" +
            xBar.toFixed(2) +
            "' y='" +
            yTxTop.toFixed(2) +
            "' width='" +
            barWidth.toFixed(2) +
            "' height='" +
            Math.max(1, yBottom - yTxTop).toFixed(2) +
            "' fill='rgba(34, 211, 238, 0.30)' stroke='rgba(34, 211, 238, 0.95)' stroke-width='0.9'><title>" +
            escapeHtml(tooltip) +
            "</title></rect>" +
            markers +
            "<text class='chart-axis' x='" +
            xCenter.toFixed(2) +
            "' y='" +
            (height - 12) +
            "' text-anchor='middle' fill='#94a3b8'>" +
            escapeHtml(xLabelHash) +
            "</text>" +
            "<text class='chart-axis' x='" +
            xCenter.toFixed(2) +
            "' y='" +
            (height - 2) +
            "' text-anchor='middle' fill='#64748b'>" +
            escapeHtml(burnHeightLabel) +
            "</text>"
          );
        })
        .join("");

      const feePoints = windowTenures.map((tenure, idx) => {
        const slotX = leftPad + idx * slotWidth;
        const centerX = slotX + slotWidth / 2;
        return [centerX, yForFee(tenure.fee_microstx_total)];
      });
      const feePath = feePoints
        .map((pt, idx) => (idx === 0 ? "M" : "L") + pt[0].toFixed(2) + " " + pt[1].toFixed(2))
        .join(" ");
      const feeLine =
        "<path d='" +
        feePath +
        "' fill='none' stroke='rgba(245, 158, 11, 0.95)' stroke-width='1.4'></path>" +
        feePoints
          .map((pt, idx) => {
            const feeMicro = Number(windowTenures[idx].fee_microstx_total) || 0;
            return (
              "<circle cx='" +
              pt[0].toFixed(2) +
              "' cy='" +
              pt[1].toFixed(2) +
              "' r='1.9' fill='rgba(245, 158, 11, 1)'><title>fees " +
              escapeHtml(formatStxFromMicro(feeMicro)) +
              "</title></circle>"
            );
          })
          .join("");

      const feeTopLabel = formatStxFromMicro(maxFeeMicro).replace(" STX", "");
      const feeMidLabel = formatStxFromMicro(maxFeeMicro / 2).replace(" STX", "");
      const grid =
        "<line x1='" + leftPad + "' x2='" + leftPad + "' y1='" + yForCount(maxCount) + "' y2='" + yForCount(0) + "' stroke='rgba(148, 163, 184, 0.24)' stroke-width='0.6' />" +
        "<line x1='" + (leftPad + plotWidth) + "' x2='" + (leftPad + plotWidth) + "' y1='" + yForFee(maxFeeMicro) + "' y2='" + yForFee(0) + "' stroke='rgba(148, 163, 184, 0.24)' stroke-width='0.6' />" +
        "<line x1='" + leftPad + "' x2='" + (leftPad + plotWidth) + "' y1='" + yForCount(maxCount) + "' y2='" + yForCount(maxCount) + "' stroke='rgba(148, 163, 184, 0.2)' stroke-width='0.6' />" +
        "<line x1='" + leftPad + "' x2='" + (leftPad + plotWidth) + "' y1='" + yForCount(maxCount / 2) + "' y2='" + yForCount(maxCount / 2) + "' stroke='rgba(148, 163, 184, 0.16)' stroke-width='0.6' />" +
        "<line x1='" + leftPad + "' x2='" + (leftPad + plotWidth) + "' y1='" + yForCount(0) + "' y2='" + yForCount(0) + "' stroke='rgba(148, 163, 184, 0.2)' stroke-width='0.6' />" +
        "<text class='chart-axis' x='6' y='" + (yForCount(maxCount) + 3) + "' fill='#94a3b8'>" + Math.round(maxCount) + "</text>" +
        "<text class='chart-axis' x='10' y='" + (yForCount(maxCount / 2) + 3) + "' fill='#94a3b8'>" + Math.round(maxCount / 2) + "</text>" +
        "<text class='chart-axis' x='14' y='" + (yForCount(0) + 3) + "' fill='#94a3b8'>0</text>" +
        "<text class='chart-axis' x='" + (leftPad + plotWidth + 2) + "' y='" + (yForFee(maxFeeMicro) + 3) + "' fill='#f59e0b' text-anchor='start'>" + escapeHtml(feeTopLabel) + "</text>" +
        "<text class='chart-axis' x='" + (leftPad + plotWidth + 2) + "' y='" + (yForFee(maxFeeMicro / 2) + 3) + "' fill='#f59e0b' text-anchor='start'>" + escapeHtml(feeMidLabel) + "</text>" +
        "<text class='chart-axis' x='" + (leftPad + plotWidth + 2) + "' y='" + (yForFee(0) + 3) + "' fill='#f59e0b' text-anchor='start'>0</text>";

      svg.innerHTML = grid + bars + feeLine;
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
        const commits = round.commits || [];
        const winnerCommit = round.winner_txid
          ? commits.find((item) => item.commit_txid === round.winner_txid)
          : null;
        const winnerKey = winnerCommit ? minerKey(winnerCommit) : "";
        const winnerTag = winnerKey ? minerName(winnerKey) : "winner-selected";
        const winnerColor = winnerKey ? minerColor(winnerKey) : null;
        // Rounds now include burn blocks that no one committed to, which are
        // neither a null-miner win nor still pending.
        const outcomeKey = round.outcome || (round.null_miner_won ? "null_with_commits" : "pending");
        const outcome =
          outcomeKey === "winner" || (!round.outcome && round.winner_txid)
            ? winnerTag
            : outcomeKey === "null_with_commits"
            ? "null-miner"
            : outcomeKey === "null_no_commits"
            ? "no commits"
            : outcomeKey === "unresolved"
            ? "not logged"
            : "pending";
        const badgeClass =
          outcomeKey === "null_with_commits"
            ? "badge badge-null"
            : outcomeKey === "null_no_commits" || outcomeKey === "unresolved"
            ? "badge badge-empty"
            : "badge badge-winner";
        const sortedCommits = commits.slice().sort((a, b) => {
          const keyA = minerKey(a);
          const keyB = minerKey(b);
          if (keyA === keyB) {
            const winA = a.is_winner ? 1 : 0;
            const winB = b.is_winner ? 1 : 0;
            return winB - winA;
          }
          return keyA.localeCompare(keyB);
        });
        const candidateTs = [];
        if (round.winner_ts) candidateTs.push(round.winner_ts);
        if (round.rejected_ts) candidateTs.push(round.rejected_ts);
        for (const item of commits) {
          if (item.ts) candidateTs.push(item.ts);
        }
        const latestTs = candidateTs.length ? Math.max(...candidateTs) : null;
        const ageText = latestTs ? fmtAge(Math.max(0, nowEpoch - latestTs)) : "";
        const totalBurnFee = round.total_burn_fee;
        const totalBurnFeeLabel = Number.isFinite(Number(totalBurnFee))
          ? "total burn " + formatSats(totalBurnFee)
          : "";
        const commitHtml = sortedCommits.length
          ? sortedCommits.map((item) => {
              const commitClass = item.is_winner ? "commit commit-winner" : "commit";
              const address = item.apparent_sender || "";
              const key = minerKey(item);
              const color = minerColor(key);
              const tag = minerName(key);
              const commitLabel = escapeHtml(shortHash(item.commit_txid, 20));
              const addressHtml = address ? mempoolAddressLink(address) : "-";
              const commitLink = item.commit_txid ? mempoolTxLink(item.commit_txid, commitLabel) : "-";
              const parentBurn = item.parent_burn_block;
              const parentBurnLabel = parentBurn !== null && parentBurn !== undefined
                ? hiroBtcBlockLink(parentBurn, escapeHtml(parentBurn))
                : "-";
              const burnFee = item.burn_fee;
              const burnFeeLabel = Number.isFinite(Number(burnFee))
                ? formatSats(burnFee)
                : "-";
              const minerBadge = "<span class='miner-line'><span class='miner-dot' style='--miner-color: " + color + "'></span><span class='miner-tag' style='--miner-color: " + color + "'>" + escapeHtml(tag) + "</span></span>";
              return "<div class='" + commitClass + "' style='border-left: 3px solid " + color + ";'><div class='mono'>" + minerBadge + " " + addressHtml + "</div><div class='mono'>commit " + commitLink + "</div><div class='mono'>parent burn block " + parentBurnLabel + "</div><div class='mono'>burn fee " + escapeHtml(burnFeeLabel) + "</div></div>";
            }).join("")
          : "<div class='commit'>No commits captured for this burn height.</div>";
        const burnLabel = "Burn #" + escapeHtml(round.burn_height);
        const ageLabel = ageText ? " <span class='round-age'>" + escapeHtml(ageText) + " ago</span>" : "";
        let badgeHtml = "<span class='" + badgeClass + "'>" + escapeHtml(outcome) + "</span>";
        if (!round.null_miner_won && round.winner_txid && winnerColor) {
          badgeHtml = "<span class='" + badgeClass + "' style='--miner-color: " + winnerColor + ";'>" +
            "<span class='miner-dot' style='--miner-color: " + winnerColor + ";'></span>" +
            escapeHtml(outcome) +
            "</span>";
        }
        const totalsHtml = totalBurnFeeLabel
          ? "<div class='round-summary'>" + escapeHtml(totalBurnFeeLabel) + "</div>"
          : "";
        return "<div class='round'><div class='round-head'><span>" + burnLabel + ageLabel + "</span>" + badgeHtml + "</div>" + totalsHtml + "<div class='commit-list'>" + commitHtml + "</div></div>";
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

    function shortContractId(value) {
      if (!value) return "-";
      const text = String(value);
      const dot = text.indexOf(".");
      if (dot <= 0) return shortHash(text, 20);
      const principal = text.slice(0, dot);
      const contractName = text.slice(dot + 1);
      if (principal.length <= 12) return text;
      return principal.slice(0, 5) + ".." + principal.slice(-4) + "." + contractName;
    }

    function renderExpensiveCalls(items, thresholdPercent) {
      const title = document.getElementById("expensiveCallsTitle");
      const body = document.getElementById("expensiveCallsBody");
      if (thresholdPercent !== null && thresholdPercent !== undefined) {
        title.textContent = "Expensive Contract Calls (>" + thresholdPercent + "% of block budget)";
      }
      if (!items.length) {
        body.innerHTML = "<tr><td colspan='5'>No expensive contract calls seen.</td></tr>";
        return;
      }
      body.innerHTML = items.slice(0, 10).map((item) => {
        const pct = Number(item.max_percent || 0);
        const budgetLabel = pct.toFixed(1) + "% " + (item.max_dimension || "-");
        const txLabel = escapeHtml(shortHash(item.txid || "-", 24));
        const txLink = item.txid ? hiroTxLink(item.txid, txLabel) : "-";
        return "<tr><td>" + escapeHtml(fmtWallClock(item.ts)) +
          "</td><td class='mono' title='" + escapeAttr(item.contract_name || "-") + "'>" + escapeHtml(shortContractId(item.contract_name)) +
          "</td><td class='mono'>" + escapeHtml(item.function_name || "-") +
          "</td><td>" + escapeHtml(budgetLabel) +
          "</td><td class='mono'>" + txLink + "</td></tr>";
      }).join("");
    }

    function renderReportsTable() {
      const reportsBody = document.getElementById("reportsBody");
      const prevBtn = document.getElementById("reportsPrev");
      const nextBtn = document.getElementById("reportsNext");
      const pageLabel = document.getElementById("reportsPageLabel");
      const total = reportsNewestFirst.length;
      const totalPages = Math.max(1, Math.ceil(total / REPORTS_PAGE_SIZE));
      if (reportsPage >= totalPages) reportsPage = totalPages - 1;
      if (reportsPage < 0) reportsPage = 0;

      if (!total) {
        reportsBody.innerHTML = "<tr><td colspan='4'>No reports yet.</td></tr>";
      } else {
        const start = reportsPage * REPORTS_PAGE_SIZE;
        const end = start + REPORTS_PAGE_SIZE;
        const pageItems = reportsNewestFirst.slice(start, end);
        reportsBody.innerHTML = pageItems.map((item) => {
          const sev = (item.severity || "ok").toLowerCase();
          const sevClass = "sev sev-" + (sev === "warning" ? "warning" : sev === "critical" ? "critical" : sev === "info" ? "info" : "ok");
          const reportId = item.report_id;
          const reportLink = reportId ? linkTo("/report?id=" + encodeURIComponent(reportId), "view", false) : "-";
          const alertTitle = humanReadableReportAlertTitle(item);
          const itemDate = new Date(item.ts * 1000);
          const today = new Date();
          const isToday = itemDate.toDateString() === today.toDateString();
          const timeLabel = isToday ? itemDate.toLocaleTimeString() : itemDate.toLocaleDateString();
          return "<tr><td>" + escapeHtml(timeLabel) + "</td><td><span class='" + sevClass + "'>" + escapeHtml(sev) + "</span></td><td title='" + escapeAttr(alertTitle) + "'>" + escapeHtml(alertTitle) + "</td><td>" + reportLink + "</td></tr>";
        }).join("");
      }

      pageLabel.textContent = "Page " + (reportsPage + 1) + "/" + totalPages;
      prevBtn.disabled = reportsPage <= 0;
      nextBtn.disabled = reportsPage >= totalPages - 1;
    }

    function compactStatusMessage(alert) {
      if (!alert) return "No recent alerts";
      const message = String(alert.message || alert.key || "No recent alerts");
      if (message.length <= 120) return message;
      return message.slice(0, 117) + "...";
    }

    function renderMobileStatus(data, alerts) {
      const badge = document.getElementById("mobileStatusBadge");
      const text = document.getElementById("mobileStatusText");
      const meta = document.getElementById("mobileStatusMeta");
      if (!badge || !text || !meta) return;

      const newest = alerts.length ? alerts[alerts.length - 1] : null;
      const sev = String((newest && newest.severity) || "ok").toLowerCase();
      const sevClass =
        "sev sev-" +
        (sev === "warning"
          ? "warning"
          : sev === "critical"
            ? "critical"
            : sev === "info"
              ? "info"
              : "ok");
      badge.className = sevClass;
      badge.textContent = sev;
      text.textContent = compactStatusMessage(newest);

      const tipAge = fmtAge(data.node_tip_age_seconds);
      const proposalAge = fmtAge(data.signer_proposal_age_seconds);
      const mempoolReady =
        data.mempool_ready_txs === null || data.mempool_ready_txs === undefined
          ? "-"
          : String(data.mempool_ready_txs);
      meta.textContent =
        "Tip " +
        tipAge +
        " | Proposal " +
        proposalAge +
        " | Mempool " +
        mempoolReady +
        " txs";
    }

    function humanReadableReportAlertTitle(item) {
      if (item && item.summary) {
        return String(item.summary);
      }
      const key = String((item && item.alert_key) || "");
      if (key.startsWith("proposal-timeout-boundary-")) return "Proposal delayed near burn-block boundary";
      if (key.startsWith("proposal-timeout-")) return "Proposal did not finalize in time";
      if (key.startsWith("proposal-reject-boundary-")) return "Proposal rejected near burn-block boundary";
      if (key.startsWith("signer-reject-")) return "Signer rejection observed";
      if (key.startsWith("signer-accept-then-reject-")) return "Inconsistent signer response order";
      if (key.startsWith("node-stall")) return "Node tip progression stalled";
      if (key.startsWith("signer-stall")) return "Signer proposal flow stalled";
      if (key.startsWith("burn-block-")) return "New burn block observed";
      if (key.startsWith("tenure-extend-")) return "Tenure extend observed";
      if (key.startsWith("burnchain-reorg-")) return "Burnchain reorg detected";
      if (key.startsWith("sortition-winner-rejected-")) return "Sortition winner rejected";
      if (key.startsWith("node-block-proposal-rejected-")) return "Node rejected block proposal";
      if (key.startsWith("miner-signers-rejected-")) return "Miner proposal rejected by signers";
      if (key.startsWith("signer-validation-slow")) return "Slow signer validation";
      if (key.startsWith("large-signer-participation-")) return "Signer participation drop detected";
      if (key.startsWith("sortition-parent-burn-mismatch-")) return "Sortition parent-burn mismatch";
      if (key.startsWith("mempool-iteration-deadline")) return "Miner mempool iteration hit deadline";
      if (key.startsWith("mempool-empty")) return "Mempool has stayed empty";
      return key || "-";
    }

    // One row per Bitcoin block in a tenure's label. Only the burn block that
    // won the sortition produced a coinbase; the rest arrived while this tenure
    // stayed active, which is what an extend is for.
    const BURN_OUTCOME_STYLES = {
      winner: { cls: "burn-row-won", mark: "⛏" },
      null_with_commits: { cls: "burn-row-null", mark: "∅" },
      null_no_commits: { cls: "burn-row-empty", mark: "∅" },
      unresolved: { cls: "burn-row-unknown", mark: "?" },
      pending: { cls: "burn-row-pending", mark: "···" },
      // No ledger row for this burn height: it sits inside a tenure's span, so
      // it produced no coinbase - we just cannot say which cause.
      missing: { cls: "burn-row-empty", mark: "∅" },
    };

    // Number(null) is 0, which would turn an absent metric into a real zero.
    function numOrNull(value) {
      if (value === null || value === undefined || value === "") return null;
      const parsed = Number(value);
      return Number.isFinite(parsed) ? parsed : null;
    }

    function burnRowTitle(height, row, outcome) {
      if (!row) {
        // The ledger keeps a bounded window of burn heights, so rows can be
        // absent for what the strip still shows. What the strip knows from the
        // tenure grouping alone is stated anyway.
        return outcome === "winner"
          ? "burn block " + height +
            ": coinbase - started this tenure (sortition details outside the tracked window)"
          : "burn block " + height +
            ": NO coinbase - cause outside the tracked window";
      }
      const sats = Number(row.burn_fee_sats);
      const commits = Number(row.commit_count) || 0;
      const spend = Number.isFinite(sats) && sats > 0 ? ", " + formatSats(sats) : "";
      const reason = row.null_reason ? " (" + row.null_reason + ")" : "";
      switch (outcome) {
        case "winner":
          return (
            "burn block " + height + ": coinbase - sortition won by " +
            (row.winner_apparent_sender || "unknown miner") +
            ", " + commits + " commit" + (commits === 1 ? "" : "s") + spend
          );
        case "null_with_commits":
          return (
            "burn block " + height + ": NO coinbase - null miner beat " + commits +
            " commit" + (commits === 1 ? "" : "s") + spend + reason
          );
        case "null_no_commits":
          return "burn block " + height + ": NO coinbase - no block commits, nobody spent BTC";
        case "unresolved":
          return (
            "burn block " + height + ": outcome never logged, " + commits +
            " commit" + (commits === 1 ? "" : "s") + " seen"
          );
        default:
          return "burn block " + height + ": sortition still in flight";
      }
    }

    function burnRowHtml(height, row, extendTally, isTenureStart) {
      // A tenure exists only because its first burn block won a sortition, so
      // that row is a coinbase whatever the ledger does or does not hold.
      const outcome = isTenureStart
        ? "winner"
        : (row && row.outcome) || "missing";
      const style = BURN_OUTCOME_STYLES[outcome] || BURN_OUTCOME_STYLES.missing;
      const partial = row && row.partial_window ? " burn-row-partial" : "";
      let badge = "";
      let title = burnRowTitle(height, row, outcome);
      if (extendTally && extendTally.total) {
        const kinds = Array.from(extendTally.kinds, ([kind, count]) =>
          count > 1 ? kind + " x" + count : kind
        ).join(", ");
        // Full extends and read-count-only extends are both possible on one
        // burn block; the badge takes the colour of the stronger kind.
        const cls = extendTally.kinds.has("ExtendAll")
          ? "burn-ext-all"
          : "burn-ext-read";
        badge =
          "<span class='burn-ext " + cls + "'>&uarr;" + extendTally.total + "</span>";
        title += " | " + extendTally.total + " tenure extend" +
          (extendTally.total === 1 ? "" : "s") + " (" + kinds + ")";
      }
      return (
        "<div class='burn-row " + style.cls + partial + "' title='" +
          escapeAttr(title) + "'>" +
          "<span class='burn-glyph'>₿</span>" +
          "<span class='burn-height'>" + hiroBtcBlockLink(height, escapeHtml(height)) + "</span>" +
          "<span class='burn-mark'>" + escapeHtml(style.mark) + "</span>" +
          badge +
        "</div>"
      );
    }

    // Burn blocks covered by a tenure: the one it won, then every later one up
    // to (but not including) the burn block that started the next tenure.
    function tenureBurnHeights(burnHeight, nextBurnHeight, latestBurnHeight) {
      if (!Number.isFinite(burnHeight)) return [];
      const end = Number.isFinite(nextBurnHeight)
        ? nextBurnHeight - 1
        : Math.max(burnHeight, Number.isFinite(latestBurnHeight) ? latestBurnHeight : burnHeight);
      const heights = [];
      // Capped so a burnchain reorg or a stale mapping cannot produce a
      // runaway column of rows.
      for (let h = burnHeight; h <= end && heights.length < 9; h += 1) heights.push(h);
      return heights;
    }

    function tenureMoreTitle(count) {
      return (
        count + " earlier block" + (count === 1 ? "" : "s") +
        " in this tenure not shown"
      );
    }

    function tenureMoreHtml(count) {
      return (
        "<div class='tenure-more' data-count='" + count + "' title='" +
        escapeAttr(tenureMoreTitle(count)) + "'>+" + count + "</div>"
      );
    }

    function burnStatHtml(label, value, note, title) {
      return (
        "<div class='burn-stat'" + (title ? " title='" + escapeAttr(title) + "'" : "") + ">" +
          "<div class='label'>" + escapeHtml(label) + "</div>" +
          "<div class='value'>" + value + "</div>" +
          "<div class='burn-note'>" + (note || "&nbsp;") + "</div>" +
        "</div>"
      );
    }

    // Share of Bitcoin blocks that produced no Stacks coinbase, split by cause.
    // These are outcome states rather than series, so each one is carried by a
    // glyph and a labelled count as well as its colour.
    function renderBurnOutcomes(data) {
      const el = document.getElementById("burnOutcomes");
      if (!el) return;
      const stats = data.burn_block_stats || {};
      const rated = Number(stats.rounds_rated) || 0;
      if (!rated) {
        el.innerHTML =
          "<div class='muted'>No burn block outcomes recorded yet - the first " +
          "one resolves when the node logs CONSENSUS for a new Bitcoin block.</div>";
        return;
      }
      const won = Number(stats.with_coinbase) || 0;
      const nullWithCommits = Number(stats.null_with_commits) || 0;
      const nullNoCommits = Number(stats.null_no_commits) || 0;
      const percent = numOrNull(stats.no_coinbase_percent);
      const contested = numOrNull(stats.null_win_percent_of_contested);
      const satsPerNull = numOrNull(stats.sats_per_null_win);
      const satsPerCoinbase = numOrNull(stats.sats_per_coinbase);
      const commitsPerNull = numOrNull(stats.commits_per_null_win);
      const satsWasted = numOrNull(stats.sats_wasted);
      const since = Number(stats.burn_blocks_since_coinbase) || 0;
      const unresolved = Number(stats.rounds_unresolved) || 0;

      const share = (count) => ((100 * count) / rated).toFixed(0) + "%";
      const segments = [
        { key: "won", glyph: "⛏", count: won, label: "with coinbase" },
        { key: "null", glyph: "∅", count: nullWithCommits, label: "null-miner win" },
        { key: "empty", glyph: "∅", count: nullNoCommits, label: "no block commits" },
      ];
      const bar =
        "<div class='burn-bar'>" +
          segments
            .filter((seg) => seg.count > 0)
            .map(
              (seg) =>
                "<span class='burn-seg burn-seg-" + seg.key + "' style='flex:" +
                seg.count + "' title='" +
                escapeAttr(seg.count + " " + seg.label + " (" + share(seg.count) + ")") +
                "'></span>"
            )
            .join("") +
        "</div>";
      const legend =
        "<div class='burn-legend'>" +
          segments
            .map(
              (seg) =>
                "<span class='burn-legend-item'>" +
                  "<span class='burn-key burn-seg-" + seg.key + "'></span>" +
                  "<strong>" + seg.count + "</strong> " + escapeHtml(seg.glyph) + " " +
                  escapeHtml(seg.label) + " <span class='muted'>" + share(seg.count) +
                  "</span>" +
                "</span>"
            )
            .join("") +
        "</div>";

      // Sats per null win is the headline BTC figure, with commits per null win
      // standing in on node builds that omit burn_fee.
      const spendValue =
        satsPerNull !== null
          ? formatSats(Math.round(satsPerNull))
          : commitsPerNull !== null
          ? commitsPerNull.toFixed(1) + " commits"
          : "-";
      const spendNote =
        satsPerNull !== null
          ? (satsWasted !== null ? formatSats(satsWasted) + " burned for nothing" : "&nbsp;")
          : commitsPerNull !== null
          ? "no burn_fee logged for those rounds"
          : "no null-miner wins yet";

      const tiles =
        "<div class='burn-grid'>" +
          burnStatHtml(
            "No coinbase",
            (percent !== null ? percent.toFixed(percent < 10 ? 1 : 0) : "-") + "%",
            "of " + rated + " rated BTC block" + (rated === 1 ? "" : "s"),
            "Bitcoin blocks that started no Stacks tenure, over all whose outcome we saw"
          ) +
          burnStatHtml(
            "Null-miner wins",
            String(nullWithCommits),
            contested !== null ? contested.toFixed(contested < 10 ? 1 : 0) + "% of contested rounds" : "",
            "Rounds where miners did commit BTC but the null miner won anyway"
          ) +
          burnStatHtml(
            "No block commits",
            String(nullNoCommits),
            "nobody spent BTC",
            "Bitcoin blocks that drew no block commit at all"
          ) +
          burnStatHtml(
            "Per null-miner win",
            spendValue,
            spendNote,
            "What the null miner beat: BTC committed in rounds it took"
          ) +
          burnStatHtml(
            "Per coinbase",
            satsPerCoinbase !== null ? formatSats(Math.round(satsPerCoinbase)) : "-",
            "committed per won sortition",
            "Average BTC committed across rounds that produced a coinbase"
          ) +
          burnStatHtml(
            "Since last coinbase",
            String(since),
            since === 1 ? "BTC block" : "BTC blocks",
            "Resolved Bitcoin blocks since the most recent one that won a sortition"
          ) +
        "</div>";

      const reasons = Object.entries(stats.null_reason_counts || {}).sort(
        (a, b) => b[1] - a[1]
      );
      const reasonRows = reasons.length
        ? "<table class='burn-reasons'><thead><tr><th>Null-miner reason</th><th>Rounds</th></tr>" +
          "</thead><tbody>" +
          reasons
            .map(
              ([reason, count]) =>
                "<tr><td>" + escapeHtml(reason) + "</td><td>" + escapeHtml(count) + "</td></tr>"
            )
            .join("") +
          "</tbody></table>"
        : "";
      const caveat = unresolved
        ? "<div class='burn-note muted'>" + unresolved + " burn block" +
          (unresolved === 1 ? "" : "s") + " unresolved (commits seen, outcome never " +
          "logged) - excluded from the rates above.</div>"
        : "";

      el.innerHTML = tiles + bar + legend + reasonRows + caveat;
    }

    function renderBlockStrip(data, nowEpoch) {
      // Fall back to the whole strip when the page shell predates the track
      // element, so the blocks still render instead of vanishing.
      const container =
        document.getElementById("blockStripTrack") ||
        document.getElementById("blockStrip");
      if (!container) return;
      const raw = data.recent_confirmed_blocks || [];

      // The same height appears many times across log sources (sibling
      // blocks and re-observations can produce dozens of node_nakamoto_block
      // entries over many minutes). The signer's new-block event fires once
      // per accepted height, so prefer its timestamp; otherwise use the
      // latest node observation.
      const byHeight = new Map();
      for (const entry of raw) {
        const height = Number(entry && entry.block_height);
        if (!Number.isFinite(height)) continue;
        let rec = byHeight.get(height);
        if (!rec) {
          rec = { height, signerTs: null, lastNodeTs: null, consensusHash: null };
          byHeight.set(height, rec);
        }
        const ts = Number(entry.ts);
        if (entry.source === "signer_new_block_event") {
          if (rec.signerTs === null || ts < rec.signerTs) rec.signerTs = ts;
        } else if (rec.lastNodeTs === null || ts > rec.lastNodeTs) {
          rec.lastNodeTs = ts;
        }
        if (!rec.consensusHash && entry.consensus_hash) {
          rec.consensusHash = entry.consensus_hash;
        }
      }
      const allBlocks = Array.from(byHeight.values())
        .map((rec) => ({
          height: rec.height,
          ts: rec.signerTs !== null ? rec.signerTs : rec.lastNodeTs,
          consensusHash: rec.consensusHash,
        }))
        .filter((b) => Number.isFinite(b.ts))
        .sort((a, b) => a.height - b.height);

      // Blocks per tenure across everything observed, not just the window
      // rendered below: a tenure's "+N" has to count the blocks the window
      // leaves out as well as the ones trimmed to fit.
      const tenureObserved = new Map();
      for (const block of allBlocks) {
        const key = block.consensusHash || "?";
        tenureObserved.set(key, (tenureObserved.get(key) || 0) + 1);
      }

      const blocks = allBlocks.slice(-14);
      if (!blocks.length) {
        container.innerHTML = "<span class='muted'>No confirmed blocks yet</span>";
        return;
      }

      const extendKinds = new Map();
      // Extends fire on each idle timeout, so a single burn block can collect
      // several. They are tallied per burn height and shown as one count on the
      // row: the label stacks Bitcoin blocks, not extends.
      const extendsByBurn = new Map();
      for (const ext of data.tenure_extend_history || []) {
        const height = Number(ext && ext.block_height);
        if (Number.isFinite(height) && ext.kind) extendKinds.set(height, String(ext.kind));
        const burn = Number(ext && ext.burn_height);
        if (Number.isFinite(burn) && ext.kind) {
          const tally = extendsByBurn.get(burn) || { total: 0, kinds: new Map() };
          tally.total += 1;
          const kind = String(ext.kind);
          tally.kinds.set(kind, (tally.kinds.get(kind) || 0) + 1);
          extendsByBurn.set(burn, tally);
        }
      }
      const burnLedger = new Map();
      for (const row of data.burn_block_ledger || []) {
        const height = Number(row && row.burn_height);
        if (Number.isFinite(height)) burnLedger.set(height, row);
      }
      const latestBurnHeight = Number(data.current_bitcoin_block_height);
      const burnByConsensus = data.burn_height_by_consensus_hash || {};
      const avgInterval = Number(data.avg_block_interval_seconds) || 15;
      const gapThreshold = Math.max(45, avgInterval * 3);

      // Group consecutive blocks into tenures by consensus hash
      const tenures = [];
      for (const block of blocks) {
        const key = block.consensusHash || "?";
        const last = tenures[tenures.length - 1];
        if (last && last.consensusHash === key) {
          last.blocks.push(block);
        } else {
          tenures.push({ consensusHash: key, blocks: [block] });
        }
      }

      const latestHeight = blocks[blocks.length - 1].height;
      const pieces = [];
      let prevTs = null;
      for (let index = 0; index < tenures.length; index += 1) {
        const tenure = tenures[index];
        const isCurrent = index === tenures.length - 1;
        const burnHeight = Number(burnByConsensus[tenure.consensusHash]);
        const nextTenure = tenures[index + 1];
        const nextBurnHeight = nextTenure
          ? Number(burnByConsensus[nextTenure.consensusHash])
          : NaN;
        const parts = [];
        const burnHeights = tenureBurnHeights(
          burnHeight,
          nextBurnHeight,
          isCurrent ? latestBurnHeight : NaN
        );
        if (burnHeights.length) {
          parts.push(
            "<div class='tenure-label'>" +
              burnHeights
                .map((height, offset) =>
                  burnRowHtml(
                    height,
                    burnLedger.get(height),
                    extendsByBurn.get(height),
                    offset === 0
                  )
                )
                .join("") +
            "</div>"
          );
        } else {
          // No burn height mapped for this consensus hash yet.
          parts.push(
            "<div class='tenure-label'><div class='tenure-btc'>₿</div><div class='tenure-burn'>" +
              escapeHtml(shortHash(tenure.consensusHash, 6)) +
              "</div></div>"
          );
        }
        // Blocks of this tenure the 14-block window already left out. The trim
        // pass adds to this count rather than starting from zero, so "+N" is the
        // tenure's real hidden total instead of just what did not fit.
        const windowed = (tenureObserved.get(tenure.consensusHash) || tenure.blocks.length) -
          tenure.blocks.length;
        if (windowed > 0) parts.push(tenureMoreHtml(windowed));
        for (const block of tenure.blocks) {
          if (prevTs !== null && block.ts - prevTs >= gapThreshold) {
            parts.push(
              "<div class='stall-gap' title='gap between confirmed blocks'>" +
                fmtAge(block.ts - prevTs) + " gap</div>"
            );
          }
          prevTs = block.ts;
          const age = Math.max(0, nowEpoch - block.ts);
          const isLatest = block.height === latestHeight;
          const extendKind = extendKinds.get(block.height);
          let chipClass = "block-chip";
          if (extendKind === "ExtendAll") chipClass += " chip-extend-all";
          else if (extendKind) chipClass += " chip-extend-read";
          if (isLatest) {
            chipClass +=
              age < 30 ? " chip-fresh-ok" : age < 60 ? " chip-fresh-warn" : " chip-fresh-critical";
          }
          const ribbon = extendKind
            ? "<div class='chip-ribbon " +
              (extendKind === "ExtendAll" ? "ribbon-extend-all" : "ribbon-extend-read") +
              "'>" +
              (extendKind === "ExtendAll" ? "EXTEND" : "READ-CT") +
              "</div>"
            : "";
          // The age carries no " ago" suffix so that every chip is exactly as
          // wide as its block height: a chip whose width grew with the age text
          // changed how many chips fit between polls, which made the trimmed
          // "+N" drift up and down by one.
          parts.push(
            "<div class='" + chipClass + "' title='" +
              escapeAttr("#" + block.height + " confirmed " + fmtAge(age) + " ago") + "'>" +
              ribbon +
              "<div class='chip-height'>" + hiroBlockLink(block.height, "#" + block.height) + "</div>" +
              "<div class='chip-age'>" + fmtAge(age) + "</div>" +
            "</div>"
          );
        }
        pieces.push(
          "<div class='tenure-bracket" + (isCurrent ? " tenure-current" : "") + "'>" +
            parts.join("") + "</div>"
        );
      }

      // Ghost chip: the newest in-flight proposal above the confirmed tip
      const openProposals = (data.recent_proposals || []).filter(
        (p) => p && p.is_open === true && Number(p.block_height) > latestHeight
      );
      openProposals.sort((a, b) => Number(a.block_height) - Number(b.block_height));
      const ghost = openProposals[openProposals.length - 1];
      if (ghost) {
        const pct = Number(ghost.max_percent_observed) || 0;
        pieces.push(
          "<div class='block-chip ghost-chip' title='block proposal in flight'>" +
            "<div class='chip-height'>#" + escapeHtml(ghost.block_height) + "</div>" +
            "<div class='chip-age'>" + pct.toFixed(0) + "% signed</div>" +
          "</div>"
        );
      }

      container.innerHTML = pieces.join("");
      trimBlockStripToFit(container);
    }

    // CSS overflow would clip a bracket's burn-height label and leave
    // half-cut chips. Instead, remove the oldest chips until everything
    // fits, keeping each visible bracket's label and adding a "+N" cue
    // for the clipped earlier blocks of that tenure.
    function blockStripOverflows(container) {
      // The track is right-aligned (flex-end), so overflow normally spills LEFT,
      // which scrollWidth does not report - compare edges instead. The right
      // edge is checked too: whenever the track ends up wider than the space the
      // rail leaves it, the newest chips are the ones clipped.
      const first = container.firstElementChild;
      const last = container.lastElementChild;
      if (!first) return false;
      const box = container.getBoundingClientRect();
      return (
        first.getBoundingClientRect().left < box.left - 1 ||
        (last && last.getBoundingClientRect().right > box.right + 1)
      );
    }

    function trimBlockStripToFit(container) {
      let guard = 0;
      while (blockStripOverflows(container) && guard < 200) {
        guard += 1;
        const bracket = container.querySelector(".tenure-bracket");
        if (!bracket) break;
        const chips = bracket.querySelectorAll(".block-chip");
        if (chips.length <= 1) {
          // Keep the newest tenure even when it cannot fit: an empty strip is
          // worse than a clipped one.
          if (container.querySelectorAll(".tenure-bracket").length <= 1) break;
          // Not even room for label + one chip: drop the whole bracket
          bracket.remove();
          continue;
        }
        const chip = chips[0];
        const prev = chip.previousElementSibling;
        const next = chip.nextElementSibling;
        chip.remove();
        // Remove a stall-gap marker orphaned at the leading edge
        if (prev && prev.classList.contains("stall-gap")) prev.remove();
        else if (next && next.classList.contains("stall-gap")) next.remove();

        let more = bracket.querySelector(".tenure-more");
        if (!more) {
          more = document.createElement("div");
          more.className = "tenure-more";
          more.dataset.count = "0";
          const label = bracket.querySelector(".tenure-label");
          if (label && label.nextSibling) {
            bracket.insertBefore(more, label.nextSibling);
          } else {
            bracket.prepend(more);
          }
        }
        const count = Number(more.dataset.count) + 1;
        more.dataset.count = String(count);
        more.textContent = "+" + count;
        more.title = tenureMoreTitle(count);
      }
    }

    // Countdown until signers will accept the next tenure extend, from the
    // eligibility timestamps signers include in their block-accept responses
    function renderExtendEta(data, nowEpoch) {
      const el = document.getElementById("extendEta");
      if (!el) return;
      const eta = (ts) => {
        if (ts === null || ts === undefined) return null;
        const delta = Number(ts) - nowEpoch;
        if (delta > 0) return "in " + fmtAge(delta);
        // Past-due: show how long the miner has left this extend on the table
        return "<span class='eta-now'>now</span> <span class='eta-since'>(for " +
          fmtAge(-delta) + ")</span>";
      };
      // Only the weighted 70th-percentile timestamps across all signers are
      // shown: that is what actually gates the miner's extend. Our own signer
      // counts for its own weight alone, so its local countdown says little.
      const parts = [];
      const full = eta(data.tenure_extend_agg_eligible_ts);
      const readCt = eta(data.tenure_extend_agg_read_count_eligible_ts);
      if (full !== null) parts.push("extend " + full);
      if (readCt !== null) parts.push("read-ct " + readCt);
      el.innerHTML = parts.length
        ? "network 70%: " + parts.join(" &middot; ")
        : "";
    }

    function render(data) {
      const now = new Date();
      const nowEpoch = Date.now() / 1000;
      document.getElementById("updated").textContent = "Updated " + now.toLocaleTimeString();
      document.getElementById("uptime").textContent = fmtAge(data.uptime_seconds);
      document.getElementById("tipAge").textContent = fmtAge(data.node_tip_age_seconds);
      document.getElementById("proposalAge").textContent = fmtAge(data.signer_proposal_age_seconds);
      document.getElementById("avgBlockInterval").textContent = fmtAge(data.avg_block_interval_seconds);
      const mempoolReady = data.mempool_ready_txs;
      document.getElementById("mempoolReady").textContent =
        mempoolReady === null || mempoolReady === undefined ? "-" : mempoolReady;
      const btc = data.current_bitcoin_block_height;
      const stx = data.current_stacks_block_height;
      document.getElementById("btcHeight").textContent = "BTC: " + (btc === null || btc === undefined ? "-" : btc);
      document.getElementById("stxHeight").textContent = "STX: " + (stx === null || stx === undefined ? "-" : stx);

      renderBlockStrip(data, nowEpoch);
      renderExtendEta(data, nowEpoch);
      renderBurnOutcomes(data);

      seedBlockCadenceFromState(data);
      seedMempoolFromState(data);

      if (stx !== null && stx !== undefined && stx !== lastBlockHeight) {
        if (data.last_block_interval_seconds !== null && data.last_block_interval_seconds !== undefined) {
          pushHistory(blockCadenceHistory, {
            value: Number(data.last_block_interval_seconds),
            ts: data.timestamp || nowEpoch,
          }, 120);
        }
        lastBlockHeight = stx;
      }
      renderSparkline("blockCadenceChart", blockCadenceHistory, {
        showXAxis: true,
        labelFormat: (value, meta) => formatSecondsTick(value, meta.range),
      });
      const cadenceMeta = document.getElementById("blockCadenceMeta");
      if (blockCadenceHistory.length) {
        const latest = blockCadenceHistory[blockCadenceHistory.length - 1];
        const avg = data.avg_block_interval_seconds;
        cadenceMeta.textContent = "last " + fmtAge(latest.value) + " | avg " + (avg ? fmtAge(avg) : "-");
      } else {
        cadenceMeta.textContent = "No cadence samples yet";
      }

      const recentMempool = data.recent_mempool_iterations || [];
      const latestIteration = recentMempool.length
        ? recentMempool[recentMempool.length - 1]
        : null;
      if (
        latestIteration &&
        Number.isFinite(Number(latestIteration.ts)) &&
        Number.isFinite(Number(latestIteration.considered_txs))
      ) {
        const sampleKey =
          String(Number(latestIteration.ts)) +
          "|" +
          String(Number(latestIteration.considered_txs)) +
          "|" +
          String(latestIteration.stop_reason || "");
        if (sampleKey !== lastMempoolSampleKey) {
          pushHistory(
            mempoolHistory,
            {
              value: Number(latestIteration.considered_txs),
              ts: Number(latestIteration.ts),
              deadline: latestIteration.stop_reason === "DeadlineReached",
            },
            160
          );
          lastMempoolSampleKey = sampleKey;
          lastMempoolEventTs = Number(latestIteration.ts);
        }
      } else {
        const mempoolAge = data.mempool_age_seconds;
        const mempoolEventTs = (mempoolAge !== null && mempoolAge !== undefined && data.timestamp)
          ? data.timestamp - mempoolAge
          : null;
        if (
          mempoolEventTs !== null &&
          mempoolEventTs !== undefined &&
          mempoolEventTs !== lastMempoolEventTs
        ) {
          pushHistory(mempoolHistory, {
            value: Number(data.mempool_ready_txs || 0),
            ts: mempoolEventTs,
            deadline: data.mempool_stop_reason === "DeadlineReached",
          }, 160);
          lastMempoolEventTs = mempoolEventTs;
        }
      }
      renderSparkline("mempoolChart", mempoolHistory, {
        minZero: true,
        markerKey: "deadline",
        showXAxis: true,
        labelFormat: (value, meta) => formatCountTick(value, meta.range),
      });
      const mempoolMeta = document.getElementById("mempoolMeta");
      if (mempoolHistory.length) {
        const latest = mempoolHistory[mempoolHistory.length - 1];
        const reason = data.mempool_stop_reason ? " | " + data.mempool_stop_reason : "";
        mempoolMeta.textContent = "ready " + latest.value + " txs" + reason;
      } else {
        mempoolMeta.textContent = "No mempool samples yet";
      }

      const alerts = data.recent_alerts || [];
      const alertsBody = document.getElementById("alertsBody");
      alertsBody.innerHTML = alerts.slice().reverse().slice(0, 20).map((item) => {
        const sev = (item.severity || "ok").toLowerCase();
        const sevClass = "sev sev-" + (sev === "warning" ? "warning" : sev === "critical" ? "critical" : sev === "info" ? "info" : "ok");
        return "<tr><td>" + escapeHtml(new Date(item.ts * 1000).toLocaleTimeString()) + "</td><td><span class='" + sevClass + "'>" + escapeHtml(sev) + "</span></td><td>" + linkifyAlertMessage(item) + "</td></tr>";
      }).join("");
      renderMobileStatus(data, alerts);

      const costBars = document.getElementById("executionCostBars");
      const costMeta = document.getElementById("executionCostMeta");
      const costTrendSamples = (data.recent_execution_costs || []).slice(-300);
      const tenureChanges = data.tenure_change_history || data.recent_tenure_extends || [];
      renderExecutionCostTrend(
        "executionCostTrend",
        costTrendSamples,
        tenureChanges
      );
      const costLimits = data.execution_cost_limits || {};
      const latestCostPercent = data.latest_execution_costs_percent || {};
      const latestCosts = data.latest_execution_costs || {};
      const latestCostHeight = data.latest_execution_cost_block_height;
      const latestCostTxCount = data.latest_execution_cost_tx_count;
      const latestCostFull = data.latest_execution_cost_percent_full;
      const latestCostAge = data.latest_execution_cost_age_seconds;
      const previousCosts =
        costTrendSamples.length >= 2 ? (costTrendSamples[costTrendSamples.length - 2] || {}) : {};
      const previousCostsRaw = previousCosts.costs || {};
      const previousCostsPercent = previousCosts.costs_percent || {};
      const hasCosts = COST_DIMENSIONS.some((dim) => latestCostPercent[dim.key] !== undefined && latestCostPercent[dim.key] !== null);
      if (!hasCosts) {
        costBars.innerHTML = "<div class='muted'>No mined block costs yet.</div>";
        costMeta.textContent = "No mined block costs yet";
      } else {
        costBars.innerHTML =
          "<div class='cost-grid'>" +
          COST_DIMENSIONS
            .map((dim) => {
              const key = dim.key;
              const label = dim.label;
              const pct = Number(latestCostPercent[key] || 0);
              const raw = latestCosts[key];
              const limit = costLimits[key];
              const prevRaw = Number(previousCostsRaw[key]);
              const prevPct = Number(previousCostsPercent[key]);
              const hasPrev = Number.isFinite(prevRaw) && Number.isFinite(prevPct);
              const deltaRaw = hasPrev && Number.isFinite(raw) ? Number(raw) - prevRaw : null;
              const deltaPct = hasPrev ? pct - prevPct : null;
              const deltaRawText =
                deltaRaw === null
                  ? "n/a"
                  : (deltaRaw >= 0 ? "+" : "") + Math.round(deltaRaw).toLocaleString();
              const deltaPctText =
                deltaPct === null
                  ? "n/a"
                  : (deltaPct >= 0 ? "+" : "") + deltaPct.toFixed(1) + "%";
              const valueText =
                Number.isFinite(raw) && Number.isFinite(limit)
                  ? Number(raw).toLocaleString() + "/" + Number(limit).toLocaleString()
                  : "-";
              const tooltip =
                label +
                ": " +
                valueText +
                " (" +
                pct.toFixed(1) +
                "%)\nΔ raw vs prior: " +
                deltaRawText +
                "\nΔ pct vs prior: " +
                deltaPctText;
              const fillColor =
                pct >= 85 ? "#ef4444" : pct >= 70 ? "#f59e0b" : "#38bdf8";
              return (
                "<div class='cost-row'>" +
                "<div class='cost-label'>" +
                escapeHtml(label) +
                "</div>" +
                "<div class='cost-track' title='" +
                escapeAttr(tooltip) +
                "'>" +
                "<div class='cost-fill' style='width:" +
                Math.max(0, Math.min(100, pct)).toFixed(1) +
                "%; background:" +
                fillColor +
                ";'></div>" +
                "</div>" +
                "<div class='cost-value'>" +
                pct.toFixed(1) +
                "%</div>" +
                "</div>"
              );
            })
            .join("") +
          "</div>";
        const metaParts = [];
        if (Number.isFinite(latestCostHeight)) metaParts.push("height " + latestCostHeight);
        if (Number.isFinite(latestCostTxCount)) metaParts.push("txs " + latestCostTxCount);
        if (Number.isFinite(latestCostFull)) metaParts.push("percent_full " + latestCostFull + "%");
        if (Number.isFinite(latestCostAge)) metaParts.push("updated " + fmtAge(Number(latestCostAge)) + " ago");
        if (costTrendSamples.length > 1) metaParts.push("trend " + costTrendSamples.length + " mined blocks");
        costMeta.textContent = metaParts.join(" | ") || "Latest mined block costs";
      }

      const tenureBlocksMeta = document.getElementById("tenureBlocksMeta");
      const tenureCounts = data.recent_tenure_block_counts || [];
      const tenureBlockChanges = data.tenure_change_history || data.recent_tenure_extends || [];
      renderTenureBlocksChart("tenureBlocksChart", tenureCounts, tenureBlockChanges);
      if (!tenureCounts.length) {
        tenureBlocksMeta.textContent = "No tenure block samples yet";
      } else {
        const totalBlocks = tenureCounts.reduce((sum, item) => {
          const count = Number(item && item.block_count);
          return sum + (Number.isFinite(count) ? count : 0);
        }, 0);
        const totalTxs = tenureCounts.reduce((sum, item) => {
          const count = Number(item && item.tx_count_total);
          return sum + (Number.isFinite(count) ? count : 0);
        }, 0);
        const totalFees = tenureCounts.reduce((sum, item) => {
          const fee = Number(item && item.fee_microstx_total);
          return sum + (Number.isFinite(fee) ? fee : 0);
        }, 0);
        const currentTenure =
          data.current_tenure_metrics ||
          tenureCounts[tenureCounts.length - 1] ||
          null;
        const windowTypeCountsFromSnapshot =
          data.tenure_window_totals &&
          data.tenure_window_totals.tx_type_counts &&
          typeof data.tenure_window_totals.tx_type_counts === "object"
            ? data.tenure_window_totals.tx_type_counts
            : null;
        const aggregatedTypeCounts = windowTypeCountsFromSnapshot || tenureCounts.reduce((acc, row) => {
          const rowTypes = row && row.tx_type_counts && typeof row.tx_type_counts === "object"
            ? row.tx_type_counts
            : {};
          const keys = ["transfer", "contract_call", "contract_deploy", "coinbase", "tenure_change", "other"];
          for (const key of keys) {
            acc[key] = (Number(acc[key]) || 0) + (Number(rowTypes[key]) || 0);
          }
          return acc;
        }, {});
        const currentBlocks = Number(currentTenure && currentTenure.block_count) || 0;
        const currentTxs = Number(currentTenure && currentTenure.tx_count_total) || 0;
        const currentFees = Number(currentTenure && currentTenure.fee_microstx_total) || 0;
        tenureBlocksMeta.innerHTML =
          "<span><strong>Current:</strong> " +
          currentBlocks +
          " blocks, " +
          currentTxs.toLocaleString(undefined) +
          " txs, " +
          escapeHtml(formatStxFromMicro(currentFees)) +
          " fees</span>" +
          "<span><strong>Last " +
          tenureCounts.length +
          " tenures:</strong> " +
          totalBlocks.toLocaleString(undefined) +
          " blocks, " +
          totalTxs.toLocaleString(undefined) +
          " txs, " +
          escapeHtml(formatStxFromMicro(totalFees)) +
          " fees</span>" +
          "<span><strong>Tx mix (last " +
          tenureCounts.length +
          "):</strong> " +
          escapeHtml(formatTxMix(aggregatedTypeCounts)) +
          "</span>";
      }

      const reports = data.recent_reports || [];
      reportsNewestFirst = reports.slice().reverse();
      renderReportsTable();

      const signers = data.signers || data.large_signers || [];
      document.getElementById("signersBody").innerHTML = signers.map((item) => {
        const name = item.name ? escapeHtml(item.name) : "-";
        // null weight means the signer never reported an attributable weight
        // (pre-patch signers log the weight on a line without the pubkey), which
        // is distinct from a real zero -- show it as unknown.
        const w = item.estimated_weight === null || item.estimated_weight === undefined
          ? "<span class='muted' title='signer did not report an attributable weight'>&mdash;</span>"
          : Number(item.estimated_weight).toFixed(1);
        const wp = item.weight_percent_of_total === null || item.weight_percent_of_total === undefined
          ? "<span class='muted'>&mdash;</span>"
          : Number(item.weight_percent_of_total).toFixed(2) + "%";
        return "<tr><td>" + name + "</td><td class='mono'>" + escapeHtml(item.pubkey.slice(0, 18)) + "...</td><td>" + w + "</td><td>" + wp + "</td><td>" + Math.round((item.participation_ratio || 0) * 100) + "% (" + (item.participation_samples || 0) + ")</td></tr>";
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
      renderExpensiveCalls(
        data.expensive_contract_calls || [],
        data.expensive_call_percent_threshold,
      );

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

      renderPhaseChart(data);
      renderSignerPhases(data);
    }

    // Phases are consecutive and sum to each block's total, so they stack. A normal
    // block is a 1-2s sliver; a stall is a tall bar whose fattest segment is the cause.
    const PHASE_SEGMENTS = [
      ["validate", "#38bdf8", "validate"],
      ["precommit_wait", "#f59e0b", "wait for 70% pre-commit"],
      ["to_first_accept", "#a78bfa", "to first acceptance"],
      ["approval_gather", "#22c55e", "gather to 70% approval"]
    ];
    const PHASE_UNATTRIBUTED = ["#475569", "unattributed (log not present)"];

    function formatSeconds(value) {
      if (value === null || value === undefined) return "-";
      const n = Number(value);
      const sign = n < 0 ? "-" : "";
      const abs = Math.abs(n);
      if (abs < 1) return sign + (abs * 1000).toFixed(0) + "ms";
      if (abs < 60) return sign + abs.toFixed(1) + "s";
      return sign + Math.floor(abs / 60) + "m" + Math.round(abs % 60) + "s";
    }

    function renderPhaseChart(data) {
      const svg = document.getElementById("phaseChart");
      const meta = document.getElementById("phaseMeta");
      if (!svg) return;

      document.getElementById("phaseLegend").innerHTML = PHASE_SEGMENTS.map((seg) => {
        return "<span class='phase-legend-item'><span class='phase-key' style='background:" +
          seg[1] + "'></span>" + escapeHtml(seg[2]) + "</span>";
      }).concat([
        "<span class='phase-legend-item'><span class='phase-key' style='background:" +
          PHASE_UNATTRIBUTED[0] + "'></span>" + escapeHtml(PHASE_UNATTRIBUTED[1]) + "</span>"
      ]).join("");

      const rows = (data.block_phases || []).slice(-60);
      if (!rows.length) {
        svg.innerHTML = "";
        meta.textContent = "No completed blocks yet (needs the pre-commit signer log)";
        renderPhasePercentiles(data);
        return;
      }

      const rect = svg.getBoundingClientRect();
      const width = Math.max(240, Math.round(rect.width || svg.clientWidth || 0));
      const height = Math.max(120, Math.round(rect.height || svg.clientHeight || 0));
      svg.setAttribute("viewBox", "0 0 " + width + " " + height);
      svg.setAttribute("preserveAspectRatio", "xMinYMin meet");

      const topPad = 8;
      const bottomPad = 14;
      const plotHeight = height - topPad - bottomPad;
      const maxTotal = Math.max.apply(null, rows.map((r) => Number(r.total_seconds) || 0)) || 1;
      const slot = width / rows.length;
      const barWidth = Math.max(2, Math.min(18, slot - 2));

      let markup = "";
      rows.forEach((row, index) => {
        const x = index * slot + (slot - barWidth) / 2;
        let cursor = 0;
        const heightLabel = (row.block_height === null || row.block_height === undefined)
          ? "?" : row.block_height;
        let tooltip = "height " + heightLabel + " total=" + formatSeconds(row.total_seconds);
        let attributed = 0;
        PHASE_SEGMENTS.forEach((seg) => {
          const raw = row[seg[0]];
          if (raw === null || raw === undefined) return;
          const value = Number(raw);
          attributed += value;
          tooltip += " | " + seg[2] + "=" + formatSeconds(value);
          const segHeight = (value / maxTotal) * plotHeight;
          if (segHeight <= 0) return;
          const y = topPad + plotHeight - cursor - segHeight;
          markup += "<rect x='" + x.toFixed(1) + "' y='" + y.toFixed(1) +
            "' width='" + barWidth.toFixed(1) + "' height='" + segHeight.toFixed(1) +
            "' fill='" + seg[1] + "'></rect>";
          cursor += segHeight;
        });
        // Milestones the current signer build does not log leave a hole between the
        // segments and the block's real total. Draw it explicitly in neutral grey so
        // bar heights stay comparable and unexplained time is visible rather than
        // silently dropped.
        const unattributed = Math.max(0, (Number(row.total_seconds) || 0) - attributed);
        if (unattributed > 0.001) {
          tooltip += " | unattributed=" + formatSeconds(unattributed);
          const segHeight = (unattributed / maxTotal) * plotHeight;
          if (segHeight > 0) {
            const y = topPad + plotHeight - cursor - segHeight;
            markup += "<rect x='" + x.toFixed(1) + "' y='" + y.toFixed(1) +
              "' width='" + barWidth.toFixed(1) + "' height='" + segHeight.toFixed(1) +
              "' fill='#475569'></rect>";
            cursor += segHeight;
          }
        }
        markup += "<rect x='" + x.toFixed(1) + "' y='" + topPad +
          "' width='" + barWidth.toFixed(1) + "' height='" + plotHeight +
          "' fill='transparent'><title>" + escapeHtml(tooltip) + "</title></rect>";
      });
      svg.innerHTML = markup;

      const worst = rows.reduce((acc, row) =>
        (Number(row.total_seconds) || 0) > (Number(acc.total_seconds) || 0) ? row : acc, rows[0]);
      const worstHeight = (worst.block_height === null || worst.block_height === undefined)
        ? "?" : worst.block_height;
      meta.innerHTML = "<span>" + rows.length + " blocks</span><span>slowest: height " +
        escapeHtml(String(worstHeight)) + " at " +
        escapeHtml(formatSeconds(worst.total_seconds)) + "</span>";
      renderPhasePercentiles(data);
    }

    const MILESTONE_LABELS = [
      ["to_first_pre_commit", "proposal → 1st pre-commit"],
      ["to_pre_commit_threshold", "proposal → 70% pre-commit"],
      ["to_first_acceptance", "proposal → 1st acceptance"],
      ["to_approval_threshold", "proposal → 70% approval"]
    ];

    function renderPhasePercentiles(data) {
      const host = document.getElementById("phasePercentiles");
      if (!host) return;
      const pct = data.phase_percentiles || {};
      host.innerHTML = MILESTONE_LABELS.map((entry) => {
        const stats = pct[entry[0]];
        const body = stats
          ? "p50 " + escapeHtml(formatSeconds(stats.p50)) +
            " &middot; p95 " + escapeHtml(formatSeconds(stats.p95)) +
            " &middot; max " + escapeHtml(formatSeconds(stats.max))
          : "<span class='muted'>no data</span>";
        return "<div class='phase-pct'><div class='phase-pct-label'>" + escapeHtml(entry[1]) +
          "</div><div class='phase-pct-value'>" + body + "</div></div>";
      }).join("");
    }

    function renderSignerPhases(data) {
      const body = document.getElementById("signerPhasesBody");
      const meta = document.getElementById("signerPhasesMeta");
      if (!body) return;
      const rows = data.signer_phase_rows || [];
      if (!rows.length) {
        body.innerHTML = "<tr><td colspan='5' class='muted'>No per-signer phase samples yet.</td></tr>";
        meta.textContent = "";
        return;
      }
      body.innerHTML = rows.slice(0, 20).map((row) => {
        const median = Number(row.median_seconds);
        // Negative pre-commit lateness means that signer was ahead of us.
        const cls = median < 0
          ? "phase-ahead"
          : median > 30 ? "phase-very-late" : median > 5 ? "phase-late" : "";
        const label = row.name
          ? escapeHtml(row.name)
          : escapeHtml(String(row.identifier).slice(0, 16)) + "...";
        const phase = row.kind === "pre_commit" ? "pre-commit lateness" : "acceptance reaction";
        return "<tr><td class='mono'>" + label + "</td><td>" + escapeHtml(phase) +
          "</td><td class='" + cls + "'>" + escapeHtml(formatSeconds(median)) +
          "</td><td>" + escapeHtml(formatSeconds(row.worst_seconds)) +
          "</td><td>" + (row.samples || 0) + "</td></tr>";
      }).join("");
      const ahead = rows.filter((row) =>
        row.kind === "pre_commit" && Number(row.median_seconds) < 0).length;
      meta.textContent = ahead
        ? ahead + " signer(s) consistently ahead of this node — proposals are reaching us late"
        : "pre-commit lateness measured from our proposal receipt; acceptance reaction from the 70% pre-commit crossing";
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

    document.getElementById("reportsPrev").addEventListener("click", () => {
      reportsPage -= 1;
      renderReportsTable();
    });

    document.getElementById("reportsNext").addEventListener("click", () => {
      reportsPage += 1;
      renderReportsTable();
    });
