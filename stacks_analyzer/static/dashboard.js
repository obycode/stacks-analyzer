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
        .filter((item) => {
          if (!item || typeof item !== "object") return false;
          const count = Number(item.block_count);
          return Number.isFinite(count) && count > 0;
        })
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

      for (const tenure of windowTenures) {
        const markers = [];
        const startTs = Number(tenure.start_ts || 0);
        const endTs = Number(tenure.end_ts || startTs);
        for (const change of changeEvents) {
          const ts = Number(change.ts);
          if (ts < startTs || ts > endTs) continue;
          let ratio = 0.5;
          if (Number.isFinite(startTs) && Number.isFinite(endTs) && endTs > startTs) {
            ratio = (ts - startTs) / (endTs - startTs);
          }
          ratio = Math.max(0, Math.min(1, ratio));
          markers.push({
            kind: String(change.kind || "unknown"),
            ts,
            ratio,
          });
        }
        tenure.markers = markers;
      }

      const rect = svg.getBoundingClientRect();
      const width = Math.max(180, Math.round(rect.width || svg.clientWidth || 0));
      const height = Math.max(64, Math.round(rect.height || svg.clientHeight || 0));
      svg.setAttribute("viewBox", "0 0 " + width + " " + height);
      svg.setAttribute("preserveAspectRatio", "xMinYMin meet");

      const topPad = 8;
      const rightPad = 8;
      const bottomPad = 16;
      const leftPad = 26;
      const plotWidth = width - leftPad - rightPad;
      const plotHeight = height - topPad - bottomPad;

      const tenureCount = windowTenures.length;
      const maxTotal = Math.max(1, ...windowTenures.map((item) => Number(item.block_count) || 0));
      const yForCount = (count) => height - bottomPad - (Math.max(0, Number(count) || 0) / maxTotal) * plotHeight;
      const slotWidth = plotWidth / Math.max(1, tenureCount);
      const barWidth = Math.max(10, slotWidth - 8);

      const bars = windowTenures
        .map((tenure, idx) => {
          const x = leftPad + idx * slotWidth + (slotWidth - barWidth) / 2;
          const yTop = yForCount(tenure.block_count);
          const yBottom = yForCount(0);
          const hashLabel = tenure.consensus_hash === "unknown" ? "unknown" : shortHash(tenure.consensus_hash, 10);
          const tooltip =
            "tenure " +
            hashLabel +
            " | blocks " +
            tenure.block_count +
            " | start " +
            fmtWallClock(tenure.start_ts) +
            " | end " +
            fmtWallClock(tenure.end_ts);
          const markers = (tenure.markers || [])
            .map((marker) => {
              const markerRatio = Math.max(0, Math.min(1, Number(marker.ratio) || 0));
              const markerY = yBottom - markerRatio * (yBottom - yTop);
              const style = tenureChangeStyle(marker.kind);
              const markerTitle =
                "Tenure change: " + style.label + " at " + fmtWallClock(marker.ts);
              const dashAttr = style.dash ? " stroke-dasharray='" + style.dash + "'" : "";
              return (
                "<line x1='" +
                x.toFixed(2) +
                "' x2='" +
                (x + barWidth).toFixed(2) +
                "' y1='" +
                markerY.toFixed(2) +
                "' y2='" +
                markerY.toFixed(2) +
                "' stroke='" +
                style.color +
                "' stroke-width='6.0' opacity='0.2'></line>" +
                "<line x1='" +
                x.toFixed(2) +
                "' x2='" +
                (x + barWidth).toFixed(2) +
                "' y1='" +
                markerY.toFixed(2) +
                "' y2='" +
                markerY.toFixed(2) +
                "' stroke='" +
                style.color +
                "' stroke-width='2.6'" +
                dashAttr +
                "><title>" +
                escapeHtml(markerTitle) +
                "</title></line>"
              );
            })
            .join("");
          const xLabel = tenure.consensus_hash === "unknown" ? "?" : tenure.consensus_hash.slice(0, 6);
          return (
            "<rect x='" +
            x.toFixed(2) +
            "' y='" +
            yTop.toFixed(2) +
            "' width='" +
            barWidth.toFixed(2) +
            "' height='" +
            Math.max(1, yBottom - yTop).toFixed(2) +
            "' fill='rgba(56, 189, 248, 0.35)' stroke='rgba(56, 189, 248, 0.95)' stroke-width='0.9'><title>" +
            escapeHtml(tooltip) +
            "</title></rect>" +
            markers +
            "<text class='chart-axis' x='" +
            (x + barWidth / 2).toFixed(2) +
            "' y='" +
            (height - 2) +
            "' text-anchor='middle' fill='#94a3b8'>" +
            escapeHtml(xLabel) +
            "</text>"
          );
        })
        .join("");

      const grid =
        "<line x1='" + leftPad + "' x2='" + leftPad + "' y1='" + yForCount(maxTotal) + "' y2='" + yForCount(0) + "' stroke='rgba(148, 163, 184, 0.24)' stroke-width='0.6' />" +
        "<line x1='" + leftPad + "' x2='" + (leftPad + plotWidth) + "' y1='" + yForCount(maxTotal) + "' y2='" + yForCount(maxTotal) + "' stroke='rgba(148, 163, 184, 0.2)' stroke-width='0.6' />" +
        "<line x1='" + leftPad + "' x2='" + (leftPad + plotWidth) + "' y1='" + yForCount(maxTotal / 2) + "' y2='" + yForCount(maxTotal / 2) + "' stroke='rgba(148, 163, 184, 0.16)' stroke-width='0.6' />" +
        "<line x1='" + leftPad + "' x2='" + (leftPad + plotWidth) + "' y1='" + yForCount(0) + "' y2='" + yForCount(0) + "' stroke='rgba(148, 163, 184, 0.2)' stroke-width='0.6' />" +
        "<text class='chart-axis' x='6' y='" + (yForCount(maxTotal) + 3) + "' fill='#94a3b8'>" + maxTotal + "</text>" +
        "<text class='chart-axis' x='10' y='" + (yForCount(maxTotal / 2) + 3) + "' fill='#94a3b8'>" + Math.round(maxTotal / 2) + "</text>" +
        "<text class='chart-axis' x='14' y='" + (yForCount(0) + 3) + "' fill='#94a3b8'>0</text>";

      svg.innerHTML = grid + bars;
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
        const outcome = round.null_miner_won ? "null-miner" : (round.winner_txid ? winnerTag : "pending");
        const badgeClass = round.null_miner_won ? "badge badge-null" : "badge badge-winner";
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
              const minerBadge = "<span class='miner-line'><span class='miner-dot' style='--miner-color: " + color + "'></span><span class='miner-tag' style='--miner-color: " + color + "'>" + escapeHtml(tag) + "</span></span>";
              return "<div class='" + commitClass + "' style='border-left: 3px solid " + color + ";'><div class='mono'>" + minerBadge + " " + addressHtml + "</div><div class='mono'>commit " + commitLink + "</div><div class='mono'>parent burn block " + parentBurnLabel + "</div></div>";
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
        return "<div class='round'><div class='round-head'><span>" + burnLabel + ageLabel + "</span>" + badgeHtml + "</div><div class='commit-list'>" + commitHtml + "</div></div>";
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
          return "<tr><td>" + escapeHtml(new Date(item.ts * 1000).toLocaleTimeString()) + "</td><td><span class='" + sevClass + "'>" + escapeHtml(sev) + "</span></td><td>" + escapeHtml(item.alert_key || "-") + "</td><td>" + reportLink + "</td></tr>";
        }).join("");
      }

      pageLabel.textContent = "Page " + (reportsPage + 1) + "/" + totalPages;
      prevBtn.disabled = reportsPage <= 0;
      nextBtn.disabled = reportsPage >= totalPages - 1;
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

      const mempoolAge = data.mempool_age_seconds;
      const mempoolEventTs = (mempoolAge !== null && mempoolAge !== undefined && data.timestamp)
        ? data.timestamp - mempoolAge
        : null;
      if (mempoolEventTs !== null && mempoolEventTs !== undefined && mempoolEventTs !== lastMempoolEventTs) {
        pushHistory(mempoolHistory, {
          value: Number(data.mempool_ready_txs || 0),
          ts: mempoolEventTs,
          deadline: data.mempool_stop_reason === "DeadlineReached",
        }, 160);
        lastMempoolEventTs = mempoolEventTs;
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
        tenureBlocksMeta.textContent =
          "last " +
          tenureCounts.length +
          " tenures | " +
          totalBlocks +
          " confirmed blocks | source node tips";
      }

      const reports = data.recent_reports || [];
      reportsNewestFirst = reports.slice().reverse();
      renderReportsTable();

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

    document.getElementById("reportsPrev").addEventListener("click", () => {
      reportsPage -= 1;
      renderReportsTable();
    });

    document.getElementById("reportsNext").addEventListener("click", () => {
      reportsPage += 1;
      renderReportsTable();
    });
