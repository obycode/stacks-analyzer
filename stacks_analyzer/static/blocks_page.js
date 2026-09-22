// /blocks page: browse confirmed blocks and their budget usage, newest first,
// or look one up by Stacks height or by Bitcoin height. Reads /api/blocks,
// which is backed by the history database (or the in-memory window when
// history is disabled).
(function () {
  const PAGE_SIZE = 40;
  const state = {
    height: null,
    burnHeight: null,
    before: null,
    after: null,
    blocks: [],
    bounds: null,
    limits: null,
    source: null,
  };
  let refreshTimer = null;

  function isNum(value) {
    return value !== null && value !== undefined && Number.isFinite(Number(value));
  }

  function readUrl() {
    const params = new URLSearchParams(window.location.search);
    const height = params.get("height");
    const burn = params.get("burn_height");
    const before = params.get("before");
    const after = params.get("after");
    state.height = isNum(height) ? Number(height) : null;
    state.burnHeight = isNum(burn) ? Number(burn) : null;
    state.before = isNum(before) ? Number(before) : null;
    state.after = isNum(after) ? Number(after) : null;
  }

  function writeUrl() {
    const params = new URLSearchParams();
    if (state.height !== null) params.set("height", String(state.height));
    if (state.burnHeight !== null) params.set("burn_height", String(state.burnHeight));
    if (state.before !== null) params.set("before", String(state.before));
    if (state.after !== null) params.set("after", String(state.after));
    const query = params.toString();
    const url = window.location.pathname + (query ? "?" + query : "");
    window.history.replaceState(null, "", url);
  }

  function isLatestView() {
    return state.height === null && state.burnHeight === null &&
      state.before === null && state.after === null;
  }

  function apiUrl() {
    const params = new URLSearchParams();
    if (state.height !== null) params.set("height", String(state.height));
    if (state.burnHeight !== null) params.set("burn_height", String(state.burnHeight));
    if (state.before !== null) params.set("before", String(state.before));
    if (state.after !== null) params.set("after", String(state.after));
    params.set("limit", String(state.height !== null || state.burnHeight !== null ? 500 : PAGE_SIZE));
    return "/api/blocks?" + params.toString();
  }

  function fmtNum(value) {
    return isNum(value) ? Number(value).toLocaleString() : "-";
  }

  function renderBounds() {
    const label = document.getElementById("boundsLabel");
    const bounds = state.bounds;
    if (!bounds || !bounds.count) {
      label.textContent = state.source === "memory"
        ? "History is disabled: showing the in-memory window only."
        : "No blocks stored yet.";
      return;
    }
    let text = fmtNum(bounds.count) + " blocks stored, heights " +
      fmtNum(bounds.min_height) + " to " + fmtNum(bounds.max_height);
    if (isNum(bounds.min_burn_height) && isNum(bounds.max_burn_height)) {
      text += ", BTC " + fmtNum(bounds.min_burn_height) + " to " + fmtNum(bounds.max_burn_height);
    }
    if (state.source === "memory") text += " (in-memory window; history disabled)";
    label.textContent = text;
  }

  function renderFilter() {
    const chip = document.getElementById("filterChip");
    const title = document.getElementById("tableTitle");
    if (state.height !== null) {
      title.textContent = "Stacks Block";
      chip.innerHTML = "<span class='filter-chip'>height " + fmtNum(state.height) +
        "<a href='/blocks' title='Clear'>&times;</a></span>";
    } else if (state.burnHeight !== null) {
      title.textContent = "Blocks in Bitcoin Block";
      chip.innerHTML = "<span class='filter-chip'>BTC " + fmtNum(state.burnHeight) +
        "<a href='/blocks' title='Clear'>&times;</a></span>";
    } else if (state.before !== null || state.after !== null) {
      title.textContent = "Blocks";
      chip.innerHTML = "";
    } else {
      title.textContent = "Latest Blocks";
      chip.innerHTML = "";
    }
  }

  function renderPager() {
    const label = document.getElementById("pageLabel");
    const newer = document.getElementById("newerBtn");
    const older = document.getElementById("olderBtn");
    const blocks = state.blocks;
    const filtered = state.height !== null || state.burnHeight !== null;
    if (filtered) {
      // A lookup shows everything it matched; paging walks the neighbourhood.
      const anchor = blocks.length ? blocks[0].block_height : state.height;
      label.textContent = blocks.length
        ? blocks.length + " block" + (blocks.length === 1 ? "" : "s") + " matched"
        : "No stored block matched";
      newer.disabled = !isNum(anchor);
      older.disabled = !isNum(anchor);
      newer.onclick = () => go({ after: Number(blocks.length ? blocks[0].block_height : anchor) });
      older.onclick = () => go({ before: Number(blocks.length ? blocks[blocks.length - 1].block_height : anchor) });
      return;
    }
    if (!blocks.length) {
      label.textContent = "";
      newer.disabled = true;
      older.disabled = true;
      return;
    }
    const top = blocks[0].block_height;
    const bottom = blocks[blocks.length - 1].block_height;
    label.textContent = "Heights " + fmtNum(bottom) + " to " + fmtNum(top);
    const maxHeight = state.bounds ? state.bounds.max_height : null;
    const minHeight = state.bounds ? state.bounds.min_height : null;
    newer.disabled = isLatestView() || (isNum(maxHeight) && Number(top) >= Number(maxHeight));
    older.disabled = isNum(minHeight) && Number(bottom) <= Number(minHeight);
    newer.onclick = () => go({ after: Number(top) });
    older.onclick = () => go({ before: Number(bottom) });
  }

  function render() {
    renderBounds();
    renderFilter();
    window.BlockFullness.renderTable(document.getElementById("blocksTable"), state.blocks, {
      limits: state.limits,
      absoluteTime: true,
      emptyText: state.height !== null
        ? "No stored block at height " + fmtNum(state.height) + "."
        : state.burnHeight !== null
          ? "No stored blocks for Bitcoin block " + fmtNum(state.burnHeight) + "."
          : "No confirmed blocks stored yet.",
    });
    document.getElementById("blocksLegend").innerHTML = window.BlockFullness.legendHtml();
    renderPager();
    document.getElementById("updated").textContent = "Updated " + new Date().toLocaleTimeString();
  }

  async function load() {
    try {
      const response = await fetch(apiUrl(), { cache: "no-store" });
      if (!response.ok) throw new Error("bad status");
      const payload = await response.json();
      state.blocks = payload.blocks || [];
      state.bounds = payload.bounds || null;
      state.limits = payload.execution_cost_limits || null;
      state.source = payload.source || null;
      // "Newer" pages that reach the head fall back to the latest view so the
      // page keeps auto-refreshing once the user is back at the top.
      if (state.after !== null && state.bounds && isNum(state.bounds.max_height) &&
          state.blocks.length && Number(state.blocks[0].block_height) >= Number(state.bounds.max_height)) {
        state.after = null;
        writeUrl();
      }
      render();
    } catch (_err) {
      document.getElementById("updated").textContent = "Disconnected";
    }
    scheduleRefresh();
  }

  function scheduleRefresh() {
    if (refreshTimer) clearTimeout(refreshTimer);
    if (!isLatestView()) return;
    refreshTimer = setTimeout(load, 10000);
  }

  function go(next) {
    state.height = next.height !== undefined ? next.height : null;
    state.burnHeight = next.burnHeight !== undefined ? next.burnHeight : null;
    state.before = next.before !== undefined ? next.before : null;
    state.after = next.after !== undefined ? next.after : null;
    writeUrl();
    load();
  }

  function bindControls() {
    const stxInput = document.getElementById("stxHeightInput");
    const btcInput = document.getElementById("btcHeightInput");
    const lookupStx = () => {
      const value = stxInput.value.trim();
      if (!isNum(value)) return;
      btcInput.value = "";
      go({ height: Number(value) });
    };
    const lookupBtc = () => {
      const value = btcInput.value.trim();
      if (!isNum(value)) return;
      stxInput.value = "";
      go({ burnHeight: Number(value) });
    };
    document.getElementById("stxHeightGo").addEventListener("click", lookupStx);
    document.getElementById("btcHeightGo").addEventListener("click", lookupBtc);
    stxInput.addEventListener("keydown", (event) => { if (event.key === "Enter") lookupStx(); });
    btcInput.addEventListener("keydown", (event) => { if (event.key === "Enter") lookupBtc(); });
    document.getElementById("latestBtn").addEventListener("click", () => {
      stxInput.value = "";
      btcInput.value = "";
      go({});
    });
    // Height links inside the table navigate through the same state instead
    // of a full page load.
    document.getElementById("blocksTable").addEventListener("click", (event) => {
      const link = event.target.closest("a[href^='/blocks?']");
      if (!link) return;
      const params = new URLSearchParams(link.getAttribute("href").split("?")[1] || "");
      if (params.has("height")) {
        event.preventDefault();
        stxInput.value = params.get("height");
        btcInput.value = "";
        go({ height: Number(params.get("height")) });
      } else if (params.has("burn_height")) {
        event.preventDefault();
        btcInput.value = params.get("burn_height");
        stxInput.value = "";
        go({ burnHeight: Number(params.get("burn_height")) });
      }
    });
  }

  readUrl();
  if (state.height !== null) document.getElementById("stxHeightInput").value = String(state.height);
  if (state.burnHeight !== null) document.getElementById("btcHeightInput").value = String(state.burnHeight);
  bindControls();
  load();
})();
