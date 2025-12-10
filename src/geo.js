import { state } from "./state.js";
import { GEOSITE_URL, GEOIP_URL } from "./constants.js";
import { t, applyTwemoji } from "./i18n.js";
import { setStatus } from "./ui-core.js";
import { debounce, highlightMatch, escapeHtml, isoToFlag } from "./utils.js";
import { makeRuleRow, rebuildRuleOrderFromState } from "./rules.js"; // Circular dep handled by imports

const geositeListEl = document.getElementById("geositeList");
const geoipListEl = document.getElementById("geoipList");
const geositeCountEl = document.getElementById("geositeCount");
const geoipCountEl = document.getElementById("geoipCount");
const geositeShowMoreBtn = document.getElementById("geositeShowMore");
const geoipShowMoreBtn = document.getElementById("geoipShowMore");
const geositeStatusEl = document.getElementById("geositeStatus");
const geoipStatusEl = document.getElementById("geoipStatus");

const INITIAL_LIST_LIMIT = 200;
const LIST_LIMIT_STEP = 200;

let geositeVisibleLimit = INITIAL_LIST_LIMIT;
let geoipVisibleLimit = INITIAL_LIST_LIMIT;
let geositeFilterRaw = "";
let geoipFilterRaw = "";

function updateGeoStatus(statusEl, received, total, count) {
  const parts = [];
  if (total) {
    const pct = Math.min(100, Math.round((received / total) * 100));
    if (Number.isFinite(pct)) parts.push(`${pct}%`);
  } else if (received) {
    parts.push(`${Math.round(received / 1024)} ${t("kb")}`);
  }
  if (typeof count === "number") parts.push(`${count}`);
  statusEl.textContent = parts.length
    ? t("loadingLong", { details: parts.join(" • ") })
    : t("loadingShort");
}

export function loadGeo(kind) {
  const isGeosite = kind === "geosite";
  const url = isGeosite ? GEOSITE_URL : GEOIP_URL;
  const statusEl = isGeosite ? geositeStatusEl : geoipStatusEl;
  const stateArr = isGeosite ? state.geosite : state.geoip;
  const renderFn = isGeosite ? renderGeositeList : renderGeoipList;
  const label = isGeosite ? "GEOSITE" : "GEOIP";

  stateArr.length = 0;
  statusEl.textContent = t("loadingShort");

  const worker = new Worker(new URL("./geo-worker.js", import.meta.url))

  worker.onmessage = ({ data }) => {
    if (data.type === "chunk") {
      stateArr.push(...data.lines);
      updateGeoStatus(statusEl, data.received, data.total, stateArr.length);
      return;
    }
    if (data.type === "done") {
      statusEl.textContent = `OK: ${stateArr.length}`;
      setStatus("ok", t("geoLoaded", { label, count: stateArr.length }));
      renderFn("");
      worker.terminate();
      return;
    }
    if (data.type === "error") {
      statusEl.textContent = t("statusError");
      setStatus("err", data.message || t("geoLoadError"));
      worker.terminate();
    }
  };

  worker.onerror = (e) => {
    statusEl.textContent = t("statusError");
    setStatus("err", e.message || String(e));
    worker.terminate();
  };

  worker.postMessage({ type: "start", url, chunkSize: 6000 });
}

export function renderGeositeList(filter = "") {
  if (!geositeListEl) return;
  const trimmed = filter.trim();

  const filterChanged = trimmed !== geositeFilterRaw;
  geositeFilterRaw = trimmed;

  if (filterChanged) {
    geositeVisibleLimit = INITIAL_LIST_LIMIT;
    geositeListEl.scrollTop = 0;
  }

  geositeListEl.innerHTML = "";

  if (!state.geosite.length) {
    if (geositeCountEl) geositeCountEl.textContent = "0";
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.innerHTML = t("fileNotLoaded");
    geositeListEl.appendChild(empty);
    if (geositeShowMoreBtn) geositeShowMoreBtn.style.display = "none";
    return;
  }

  const f = geositeFilterRaw.toLowerCase();
  const items = state.geosite.filter((x) => !f || x.toLowerCase().includes(f));
  if (geositeCountEl) geositeCountEl.textContent = items.length;

  if (!items.length) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = t("noMatches", { query: geositeFilterRaw || "" });
    geositeListEl.appendChild(empty);
    if (geositeShowMoreBtn) geositeShowMoreBtn.style.display = "none";
    return;
  }

  const limit = Math.min(geositeVisibleLimit, items.length);
  const visibleItems = items.slice(0, limit);

  const frag = document.createDocumentFragment();
  for (const name of visibleItems) {
    frag.appendChild(makeRuleRow("geosite", name, name, geositeFilterRaw));
  }
  geositeListEl.appendChild(frag);

  if (geositeShowMoreBtn) {
    if (items.length > limit) {
      geositeShowMoreBtn.style.display = "inline-flex";
      const remaining = items.length - limit;
      geositeShowMoreBtn.textContent =
        t("showMoreCount", { count: remaining }) || t("showMore");
    } else {
      geositeShowMoreBtn.style.display = "none";
    }
  }
}

export function renderGeoipList(filter = "") {
  if (!geoipListEl) return;
  const trimmed = filter.trim();

  const filterChanged = trimmed !== geoipFilterRaw;
  geoipFilterRaw = trimmed;

  if (filterChanged) {
    geoipVisibleLimit = INITIAL_LIST_LIMIT;
    geoipListEl.scrollTop = 0;
  }

  geoipListEl.innerHTML = "";

  if (!state.geoip.length) {
    if (geoipCountEl) geoipCountEl.textContent = "0";
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.innerHTML = t("fileNotLoaded");
    geoipListEl.appendChild(empty);
    if (geoipShowMoreBtn) geoipShowMoreBtn.style.display = "none";
    return;
  }

  const f = geoipFilterRaw.toLowerCase();
  const items = state.geoip.filter((x) => !f || x.toLowerCase().includes(f));
  if (geoipCountEl) geoipCountEl.textContent = items.length;

  if (!items.length) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = t("noMatches", { query: geoipFilterRaw || "" });
    geoipListEl.appendChild(empty);
    if (geoipShowMoreBtn) geoipShowMoreBtn.style.display = "none";
    return;
  }

  const limit = Math.min(geoipVisibleLimit, items.length);
  const visibleItems = items.slice(0, limit);

  const frag = document.createDocumentFragment();
  for (const code of visibleItems) {
    const flag = isoToFlag(code);
    const pretty = flag ? `${flag}\u00A0${code}` : code;
    frag.appendChild(makeRuleRow("geoip", code, pretty, geoipFilterRaw));
  }
  geoipListEl.appendChild(frag);

  if (geoipShowMoreBtn) {
    if (items.length > limit) {
      geoipShowMoreBtn.style.display = "inline-flex";
      const remaining = items.length - limit;
      geoipShowMoreBtn.textContent =
        t("showMoreCount", { count: remaining }) || t("showMore");
    } else {
      geoipShowMoreBtn.style.display = "none";
    }
  }

  applyTwemoji(geoipListEl);
}
export function setupGeoListeners(renderRulesTargetsCb) {
  if (geositeShowMoreBtn) {
    geositeShowMoreBtn.addEventListener("click", () => {
      geositeVisibleLimit += LIST_LIMIT_STEP;
      renderGeositeList(geositeFilterRaw);
    });
  }

  if (geoipShowMoreBtn) {
    geoipShowMoreBtn.addEventListener("click", () => {
      geoipVisibleLimit += LIST_LIMIT_STEP;
      renderGeoipList(geoipFilterRaw);
    });
  }

  const renderGeositeListDebounced = debounce(
    (value) => renderGeositeList(value),
    250
  );
  const renderGeoipListDebounced = debounce(
    (value) => renderGeoipList(value),
    250
  );

  document.getElementById("geositeReset")?.addEventListener("click", () => {
    state.rulesGeosite.clear();
    renderRulesTargetsCb();
  });

  document.getElementById("geoipReset")?.addEventListener("click", () => {
    state.rulesGeoip.clear();
    renderRulesTargetsCb();
  });

  document
    .getElementById("geositeSearch")
    ?.addEventListener("input", (e) =>
      renderGeositeListDebounced(e.target.value)
    );

  document
    .getElementById("geoipSearch")
    ?.addEventListener("input", (e) =>
      renderGeoipListDebounced(e.target.value)
    );

  document
    .getElementById("loadGeositeBtn")
    ?.addEventListener("click", () => loadGeo("geosite"));

  document
    .getElementById("loadGeoipBtn")
    ?.addEventListener("click", () => loadGeo("geoip"));
}
