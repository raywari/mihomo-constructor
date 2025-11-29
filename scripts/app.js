function resolveParser() {
  try {
    if (typeof window !== "undefined" && window.parser) return window.parser;
    if (typeof parser !== "undefined") return parser;
  } catch {}
  return null;
}
function yamlQuote(s) {
  if (s == null) return null;
  s = String(s)
    .replace(/[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F]/g, "")
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"');
  return `"${s}"`;
}

function emitLine(lines, text = "", indent = 0) {
  lines.push(" ".repeat(indent) + text);
}
function emitKv(lines, key, value, indent = 0, quote = true) {
  if (value == null || (value === "" && key !== "password")) return;

  if (typeof value === "boolean") {
    emitLine(lines, `${key}: ${value ? "true" : "false"}`, indent);
    return;
  }

  let v = value;
  if (quote && typeof v !== "number") v = yamlQuote(v);
  emitLine(lines, `${key}: ${v}`, indent);
}

function emitBool(lines, key, flag, indent = 0) {
  if (flag == null) return;
  emitLine(lines, `${key}: ${flag ? "true" : "false"}`, indent);
}
function emitList(lines, key, items, indent = 0) {
  if (!items || !items.length) return;
  emitLine(lines, `${key}:`, indent);
  for (const it of items) emitLine(lines, `- ${yamlQuote(it)}`, indent + 2);
}

function emitProxiesYaml(proxies) {
  const lines = [];
  emitLine(lines, "proxies:");
  proxies.forEach((p, i) => {
    emitLine(lines, "- name: " + yamlQuote(p.name || "proxy"), 2);
    emitKv(lines, "type", p.type, 4);
    emitKv(lines, "server", p.server, 4, false);
    if (p.port != null) emitKv(lines, "port", p.port, 4, false);

    for (const k of [
      "uuid",
      "password",
      "cipher",
      "alterId",
      "network",
      "flow",
      "servername",
      "client-fingerprint",
      "sni",
      "auth_str",
      "auth",
      "token",
      "protocol",
      "obfs",
      "protocol-param",
      "obfs-param",
      "encryption",
    ])
      if (k in p) emitKv(lines, k, p[k], 4);

    if ("tls" in p) emitBool(lines, "tls", !!p.tls, 4);
    if ("udp" in p) emitBool(lines, "udp", !!p.udp, 4);
    if ("insecure" in p) emitBool(lines, "insecure", !!p.insecure, 4);
    if ("skip-cert-verify" in p)
      emitBool(lines, "skip-cert-verify", !!p["skip-cert-verify"], 4);

    if (p["up-mbps"]) emitKv(lines, "up-mbps", p["up-mbps"], 4, false);
    if (p["down-mbps"]) emitKv(lines, "down-mbps", p["down-mbps"], 4, false);
    if (p.alpn) emitList(lines, "alpn", p.alpn, 4);
    if (p.seed) emitKv(lines, "seed", p.seed, 4);
    if (p.header) emitKv(lines, "header", p.header, 4);
    if (p.plugin) emitKv(lines, "plugin", p.plugin, 4);
    if (p["plugin-opts"]) {
      emitLine(lines, "plugin-opts:", 4);
      for (const [pk, pv] of Object.entries(p["plugin-opts"]))
        emitKv(lines, pk, pv, 6);
    }

    if (p["ws-opts"]) {
      emitLine(lines, "ws-opts:", 4);
      emitKv(lines, "path", p["ws-opts"].path, 6);
      if (p["ws-opts"].headers) {
        emitLine(lines, "headers:", 6);
        for (const [hk, hv] of Object.entries(p["ws-opts"].headers))
          emitKv(lines, hk, hv, 8);
      }
    }
    if (p["reality-opts"]) {
      emitLine(lines, "reality-opts:", 4);
      for (const [rk, rv] of Object.entries(p["reality-opts"]))
        if (rv) emitKv(lines, rk, rv, 6);
    }
    if (p["grpc-opts"]) {
      emitLine(lines, "grpc-opts:", 4);
      for (const [gk, gv] of Object.entries(p["grpc-opts"]))
        emitKv(lines, gk, gv, 6);
    }
    if (p["h2-opts"]) {
      emitLine(lines, "h2-opts:", 4);
      emitKv(lines, "path", p["h2-opts"].path, 6);
      if (p["h2-opts"].host) {
        if (Array.isArray(p["h2-opts"].host))
          emitList(lines, "host", p["h2-opts"].host, 6);
        else emitKv(lines, "host", p["h2-opts"].host, 6);
      }
    }
    if (p["http-opts"]) {
      emitLine(lines, "http-opts:", 4);
      const rawPath = p["http-opts"].path;
      if (rawPath != null && rawPath !== "") {
        const paths = Array.isArray(rawPath) ? rawPath : [rawPath];
        emitList(lines, "path", paths, 6);
      }
      if (p["http-opts"].headers) {
        emitLine(lines, "headers:", 6);
        for (const [hk, hv] of Object.entries(p["http-opts"].headers)) {
          if (hv == null || hv === "") continue;
          const vals = Array.isArray(hv) ? hv : [hv];
          emitList(lines, hk, vals, 8);
        }
      }
    }
    if (p["kcp-opts"]) {
      emitLine(lines, "kcp-opts:", 4);
      if (p["kcp-opts"].seed) emitKv(lines, "seed", p["kcp-opts"].seed, 6);
      if (p["kcp-opts"].header) {
        emitLine(lines, "header:", 6);
        emitKv(lines, "type", p["kcp-opts"].header.type, 8);
      }
    }
    if (p["tcp-opts"]) {
      emitLine(lines, "tcp-opts:", 4);
      if (p["tcp-opts"].header) {
        emitLine(lines, "header:", 6);
        emitKv(lines, "type", p["tcp-opts"].header.type, 8);
      }
    }

    if (i !== proxies.length - 1) emitLine(lines, "");
  });
  return lines.join("\n") + "\n";
}

/* =========================================================
   App state
========================================================= */
const state = {
  proxies: [],
  groups: [],
  geosite: [],
  geoip: [],
  rulesGeosite: new Map(),
  rulesGeoip: new Map(),
  ruleDrafts: {
    geosite: new Map(),
    geoip: new Map(),
  },
  subs: [],
  match: { mode: "auto", value: "" },
};

const GEOSITE_URL = "geo/geosite.txt";
const GEOIP_URL = "geo/geoip.txt";
const MATCH_AUTO_VALUE = "__auto__";
const MATCH_POLICIES = [
  { value: "DIRECT", labelKey: "matchPolicyDirect" },
  { value: "REJECT", labelKey: "matchPolicyReject" },
];

const translations = window.translations || {};
const languageOptions = window.languageOptions || [];

let currentLang = localStorage.getItem("lang") || "en";
if (!translations[currentLang]) currentLang = "en";

function t(key, params = {}) {
  const dict = translations?.[currentLang] || translations?.en || {};

  const template = dict[key] || translations?.en?.[key] || key;

  return template.replace(/\{(\w+)\}/g, (_, k) => params[k] ?? "");
}

function setStatus(kind, text) {
  setStatus.lastKind = kind;
  setStatus.lastText = text;
  const el = document.getElementById("status");
  el.classList.remove("ok", "err");
  if (kind) el.classList.add(kind);
  el.querySelector(".pill").textContent =
    kind === "ok"
      ? t("statusReady")
      : kind === "err"
      ? t("statusError")
      : t("statusIdle");
  document.getElementById("statusText").textContent = text;
}

/* =========================================================
   Helpers
========================================================= */
function isoToFlag(iso) {
  iso = iso.toUpperCase();
  if (!/^[A-Z]{2}$/.test(iso)) return "";
  const A = 0x1f1e6,
    base = "A".codePointAt(0);
  return String.fromCodePoint(
    A + (iso.codePointAt(0) - base),
    A + (iso.codePointAt(1) - base)
  );
}
function uniq(arr) {
  return [...new Set(arr)];
}
function escapeHtml(str) {
  return String(str).replace(
    /[&<>"']/g,
    (s) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[
        s
      ])
  );
}
function highlightMatch(text, query) {
  const q = query?.trim();
  if (!q) return escapeHtml(text);
  const lower = text.toLowerCase();
  const idx = lower.indexOf(q.toLowerCase());
  if (idx === -1) return escapeHtml(text);

  const beforeRaw = text.slice(0, idx);
  const matchRaw = text.slice(idx, idx + q.length);
  const afterRaw = text.slice(idx + q.length);

  const maxBefore = 60;
  const maxAfter = 120;

  const trimmedBefore =
    beforeRaw.length > maxBefore ? beforeRaw.slice(-maxBefore) : beforeRaw;
  const trimmedAfter =
    afterRaw.length > maxAfter ? afterRaw.slice(0, maxAfter) : afterRaw;

  const prefix = beforeRaw.length > maxBefore ? "…" : "";
  const suffix = afterRaw.length > maxAfter ? "…" : "";

  const before = escapeHtml(trimmedBefore);
  const match = escapeHtml(matchRaw);
  const after = escapeHtml(trimmedAfter);

  return `${prefix}${before}<mark>${match}</mark>${after}${suffix}`;
}

function debounce(fn, delay = 250) {
  let timer;
  return function (...args) {
    const ctx = this;
    clearTimeout(timer);
    timer = setTimeout(() => fn.apply(ctx, args), delay);
  };
}

function applyTranslations() {
  document.documentElement.lang = currentLang;
  document.documentElement.dir = currentLang === "fa" ? "rtl" : "ltr";
  document.body.classList.toggle("rtl", currentLang === "fa");

  document.querySelectorAll("[data-i18n]").forEach((el) => {
    const key = el.dataset.i18n;
    const attr = el.dataset.i18nAttr;
    if (attr) {
      el.setAttribute(attr, t(key));
    } else {
      el.textContent = t(key);
    }
  });

  document.querySelectorAll("[data-i18n-aria]").forEach((el) => {
    const key = el.dataset.i18nAria;
    el.setAttribute("aria-label", t(key));
  });

  syncDynamicTexts();
}

function syncDynamicTexts() {
  const output = document.getElementById("output");
  if (!output.textContent.trim() || output.dataset.placeholder === "true") {
    output.textContent = t("outputPlaceholder");
    output.dataset.placeholder = "true";
  }

  if (!state.geosite.length)
    document.getElementById("geositeStatus").textContent = t("notLoaded");
  if (!state.geoip.length)
    document.getElementById("geoipStatus").textContent = t("notLoaded");

  if (typeof setStatus.lastKind !== "undefined") {
    setStatus(setStatus.lastKind, setStatus.lastText || "");
  } else {
    const current = document.getElementById("statusText")?.textContent || "";
    setStatus(null, current);
  }
}

function setupLanguageSelector() {
  const btn = document.getElementById("langButton");
  const menu = document.getElementById("langMenu");
  if (!btn || !menu) return;

  const renderButton = () => {
    const opt =
      languageOptions.find((o) => o.value === currentLang) ||
      languageOptions[0];
    const flag = opt?.flag || isoToFlag(opt?.value?.slice(0, 2)) || "🌐";
    const flagEl =
      btn.querySelector(".lang-current-flag") ||
      btn.querySelector(".lang-flag");
    if (flagEl) flagEl.textContent = flag;
    btn.setAttribute(
      "aria-label",
      `${t("languageLabel")}: ${opt?.label || opt?.value || ""}`.trim()
    );
  };

  const renderMenu = () => {
    menu.innerHTML = languageOptions
      .map(
        (opt) => `
          <button class="lang-option" role="option" data-value="${opt.value}">
            <span class="lang-flag" aria-hidden="true">${
              opt.flag || isoToFlag(opt.value.slice(0, 2)) || "🌐"
            }</span>
            <span class="lang-name">${opt.label}</span>
          </button>
        `
      )
      .join("");
  };

  const closeMenu = () => {
    menu.classList.remove("open");
    btn.setAttribute("aria-expanded", "false");
  };

  const openMenu = () => {
    menu.classList.add("open");
    btn.setAttribute("aria-expanded", "true");
  };

  btn.addEventListener("click", () => {
    if (menu.classList.contains("open")) closeMenu();
    else openMenu();
  });

  menu.addEventListener("click", (e) => {
    const optBtn = e.target.closest(".lang-option");
    if (!optBtn) return;
    const lang = optBtn.dataset.value;
    if (!translations[lang]) return;
    currentLang = lang;
    localStorage.setItem("lang", lang);
    applyTranslations();
    renderGroups();
    renderMatchSelect();
    renderRulesTargets();
    renderSubs();
    setStatus(setStatus.lastKind || null, setStatus.lastText || "");
    renderButton();
    closeMenu();
  });

  document.addEventListener("click", (e) => {
    if (e.target.closest(".lang-control")) return;
    closeMenu();
  });

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeMenu();
  });

  renderMenu();
  renderButton();
}

/* =========================================================
   UI: Proxy Groups
========================================================= */
const groupsContainer = document.getElementById("groupsContainer");
function renderGroups() {
  groupsContainer.innerHTML = "";
  const proxyNames = state.proxies.map((p) => p.name);

  state.groups.forEach((g, idx) => {
    const card = document.createElement("div");
    card.className = "group-card";

    card.innerHTML = `
      <div class="row">
        <input type="text" placeholder="${t("groupNamePlaceholder")}" value="${
      g.name
    }">
        <select>
          ${["select", "url-test", "fallback", "load-balance"]
            .map(
              (t) => `<option ${g.type === t ? "selected" : ""}>${t}</option>`
            )
            .join("")}
        </select>
      </div>
      <div class="two-col">
        <div class="row">
          <label class="hint">${t("iconLabel")}</label>
          <input type="text" placeholder="https://..." value="${g.icon || ""}">
        </div>
        <div class="row">
          <label class="hint">${t("manualLabel")}</label>
          <input type="text" placeholder='${t("manualPlaceholder")}' value="${(
      g.manual || []
    ).join(", ")}">
        </div>
      </div>
      <div class="hint">${t("groupProxiesHint")}</div>
      <div class="listbox" style="max-height:180px">
        ${proxyNames
          .map((n) => {
            const checked = g.proxies.includes(n) ? "checked" : "";
            return `<div class="item"><label><input type="checkbox" data-proxy="${n}" ${checked}> <span>${n}</span></label></div>`;
          })
          .join("")}
      </div>
      <div class="row" style="justify-content:space-between">
        <div class="hint">${t("updateProxyHint")}</div>
        <button class="danger" data-del>🗑 ${t("deleteGroup")}</button>
      </div>
    `;

    const [nameInp, typeSel, iconInp, manualInp] =
      card.querySelectorAll("input, select");
    nameInp.addEventListener("input", (e) => {
      g.name = e.target.value.trim() || "GROUP";
      renderRulesTargets();
      renderMatchSelect();
    });
    typeSel.addEventListener("change", (e) => {
      g.type = e.target.value;
    });
    iconInp.addEventListener("input", (e) => {
      g.icon = e.target.value.trim();
    });
    manualInp.addEventListener("input", (e) => {
      g.manual = e.target.value
        .split(",")
        .map((x) => x.trim())
        .filter(Boolean);
    });

    card.querySelectorAll("input[type=checkbox]").forEach((cb) => {
      cb.addEventListener("change", () => {
        const n = cb.dataset.proxy;
        if (cb.checked && !g.proxies.includes(n)) g.proxies.push(n);
        if (!cb.checked) g.proxies = g.proxies.filter((x) => x !== n);
      });
    });

    card.querySelector("[data-del]").addEventListener("click", () => {
      state.groups.splice(idx, 1);
      renderGroups();
      renderRulesTargets();
      renderMatchSelect();
    });

    groupsContainer.appendChild(card);
  });

  if (!state.groups.length) {
    const empty = document.createElement("div");
    empty.className = "hint";
    empty.textContent = t("emptyGroups");
    groupsContainer.appendChild(empty);
  }
  renderMatchSelect();
}

document.getElementById("addGroupBtn").addEventListener("click", () => {
  state.groups.push({
    name: "PROXY",
    type: "select",
    icon: "",
    proxies: [],
    manual: [],
  });
  renderGroups();
  renderRulesTargets();
  renderMatchSelect();
});

/* =========================================================
   UI: GEOSITE / GEOIP lists + rules
========================================================= */
const geositeListEl = document.getElementById("geositeList");
const geoipListEl = document.getElementById("geoipList");
const geositeCountEl = document.getElementById("geositeCount");
const geoipCountEl = document.getElementById("geoipCount");

const VIRTUAL_BATCH = 200;

function createVirtualList(container, renderItem) {
  const spacerTop = document.createElement("div");
  const spacerBottom = document.createElement("div");
  const host = document.createElement("div");
  host.style.display = "flex";
  host.style.flexDirection = "column";
  host.style.gap = "10px";

  container.innerHTML = "";
  container.style.position = "relative";
  container.style.display = "block";
  container.style.overflowY = "auto";
  container.append(spacerTop, host, spacerBottom);

  const state = {
    items: [],
    limit: VIRTUAL_BATCH,
    batchSize: VIRTUAL_BATCH,
    total: 0,
    itemHeight: 64,
    measured: false,
    hasMessage: false,
  };

  function measureRow() {
    if (state.measured) return;
    const first = host.firstChild;
    if (!first) return;
    const gap = parseFloat(getComputedStyle(host).rowGap || "0") || 0;
    state.itemHeight = first.getBoundingClientRect().height + gap;
    state.measured = true;
  }

  function renderVisible() {
    if (state.hasMessage) return;
    const total = state.total;
    if (!total) {
      host.innerHTML = "";
      spacerTop.style.height = spacerBottom.style.height = "0px";
      return;
    }

    const viewH = container.clientHeight || 400;
    const rowH = Math.max(1, state.itemHeight);
    const start = Math.max(0, Math.floor(container.scrollTop / rowH) - 2);
    const visible = Math.max(1, Math.ceil(viewH / rowH) + 4);
    const end = Math.min(total, start + visible);

    spacerTop.style.height = `${start * rowH}px`;
    spacerBottom.style.height = `${Math.max(0, (total - end) * rowH)}px`;

    const frag = document.createDocumentFragment();
    for (let i = start; i < end; i++)
      frag.appendChild(renderItem(state.items[i]));
    host.innerHTML = "";
    host.appendChild(frag);

    if (!state.measured) {
      measureRow();
      if (state.measured) renderVisible();
    }
  }

  function setItems(list) {
    state.items = list;
    state.limit = state.batchSize;
    state.total = Math.min(list.length, state.limit);
    state.measured = false;
    state.hasMessage = false;
    renderVisible();
  }

  function showMore() {
    if (state.limit >= state.items.length) return;
    state.limit = Math.min(state.limit + state.batchSize, state.items.length);
    state.total = Math.min(state.items.length, state.limit);
    renderVisible();
  }

  function showMessage(node) {
    state.items = [];
    state.total = 0;
    state.hasMessage = true;
    spacerTop.style.height = spacerBottom.style.height = "0px";
    host.innerHTML = "";
    host.appendChild(node);
  }

  function resetLimit() {
    state.limit = state.batchSize;
    state.total = Math.min(state.items.length, state.limit);
  }

  container.addEventListener("scroll", renderVisible);
  window.addEventListener("resize", renderVisible);

  return {
    setItems,
    showMore,
    showMessage,
    resetLimit,
    render: renderVisible,
    getVisibleCount: () => state.total,
    getTotalItems: () => state.items.length,
    hasMore: () => state.items.length > state.total,
    getBatchSize: () => state.batchSize,
  };
}

let geositeFilterRaw = "";
let geoipFilterRaw = "";

const geositeVirtual = createVirtualList(geositeListEl, (name) =>
  makeRuleRow("geosite", name, name, geositeFilterRaw)
);
const geoipVirtual = createVirtualList(geoipListEl, (code) => {
  const flag = isoToFlag(code);
  const pretty = flag ? `${flag} ${code}` : code;
  return makeRuleRow("geoip", code, pretty, geoipFilterRaw);
});

function makeMoreBtn(container, onClick) {
  const btn = document.createElement("button");
  btn.className = "ghost";
  btn.style.width = "100%";
  btn.style.marginTop = "8px";
  btn.textContent = t("showMore");
  btn.addEventListener("click", onClick);
  container.insertAdjacentElement("afterend", btn);
  return btn;
}

const geositeMoreBtn = makeMoreBtn(geositeListEl, () => {
  geositeVirtual.showMore();
  updateMoreButton(geositeVirtual, geositeMoreBtn);
});
const geoipMoreBtn = makeMoreBtn(geoipListEl, () => {
  geoipVirtual.showMore();
  updateMoreButton(geoipVirtual, geoipMoreBtn);
});

function updateMoreButton(virtual, btn) {
  const hasMore = virtual.hasMore();
  btn.style.display = hasMore ? "inline-flex" : "none";
  if (hasMore) {
    btn.textContent = t("showMoreCount", { count: virtual.getBatchSize() });
  }
}

const renderGeositeListDebounced = debounce(
  (value) => renderGeositeList(value),
  250
);
const renderGeoipListDebounced = debounce(
  (value) => renderGeoipList(value),
  250
);

document.getElementById("geositeReset").addEventListener("click", () => {
  state.rulesGeosite.clear();
  renderRulesTargets();
});

document.getElementById("geoipReset").addEventListener("click", () => {
  state.rulesGeoip.clear();
  renderRulesTargets();
});

document
  .getElementById("geositeSearch")
  .addEventListener("input", (e) => renderGeositeListDebounced(e.target.value));

document
  .getElementById("geoipSearch")
  .addEventListener("input", (e) => renderGeoipListDebounced(e.target.value));

const matchSelectEl = document.getElementById("matchPolicy");

function normalizeMatchSelection() {
  if (state.match.mode === "builtin") {
    const exists = MATCH_POLICIES.some((p) => p.value === state.match.value);
    if (!exists) state.match = { mode: "auto", value: "" };
  }
  if (state.match.mode === "group") {
    const hasGroup = state.groups.some((g) => g.name === state.match.value);
    if (!hasGroup) state.match = { mode: "auto", value: "" };
  }
}

function renderMatchSelect() {
  normalizeMatchSelection();

  const options = [];
  options.push(
    `<option value="${MATCH_AUTO_VALUE}">${t("matchAuto")}</option>`
  );
  options.push(
    `<optgroup label="${t("matchSpecialPolicies")}">${MATCH_POLICIES.map(
      (p) => `<option value="${p.value}">${t(p.labelKey)}</option>`
    ).join("")}</optgroup>`
  );
  const groupOptions = state.groups
    .map((g) => g.name)
    .filter(Boolean)
    .map((n) => `<option value="group:${n}">${n}</option>`)
    .join("");
  options.push(
    `<optgroup label="${t("groupsTitle")}">${
      groupOptions || `<option value="" disabled>${t("noGroups")}</option>`
    }</optgroup>`
  );

  matchSelectEl.innerHTML = options.join("");

  const currentValue =
    state.match.mode === "group"
      ? `group:${state.match.value}`
      : state.match.mode === "builtin"
      ? state.match.value
      : MATCH_AUTO_VALUE;

  const allowedValues = Array.from(matchSelectEl.options).map((o) => o.value);
  matchSelectEl.value = allowedValues.includes(currentValue)
    ? currentValue
    : MATCH_AUTO_VALUE;
}

matchSelectEl.addEventListener("change", () => {
  const v = matchSelectEl.value;
  if (v === MATCH_AUTO_VALUE) {
    state.match = { mode: "auto", value: "" };
  } else if (v.startsWith("group:")) {
    state.match = { mode: "group", value: v.slice(6) };
  } else {
    state.match = { mode: "builtin", value: v };
  }
});

function getMatchPolicyTarget() {
  normalizeMatchSelection();

  if (state.match.mode === "builtin" && state.match.value)
    return state.match.value;
  if (state.match.mode === "group" && state.match.value) {
    const hasGroup = state.groups.some((g) => g.name === state.match.value);
    if (hasGroup) return state.match.value;
  }

  const proxyGroup = state.groups.find((g) => g.name === "PROXY");
  if (proxyGroup?.name) return proxyGroup.name;
  if (state.groups.length) return state.groups[0].name;
  return "DIRECT";
}

function renderRulesTargets() {
  renderGeositeList(document.getElementById("geositeSearch").value);
  renderGeoipList(document.getElementById("geoipSearch").value);
}

function makeRuleRow(kind, name, pretty, query = "") {
  const map = kind === "geosite" ? state.rulesGeosite : state.rulesGeoip;
  const drafts = state.ruleDrafts[kind];
  const current = map.get(name) || { action: "", target: "" };
  const draft = drafts.get(name) || current;
  const displayName = highlightMatch(pretty, query);

  const row = document.createElement("div");
  row.className = "item rule-item";
  if (map.has(name)) row.classList.add("is-active");
  row.innerHTML = `
    <div class="rule-main">
      <span class="pill rule-kind">${kind.toUpperCase()}</span>
      <span class="rule-name" title="${escapeHtml(
        pretty
      )}" data-full="${escapeHtml(pretty)}">${displayName}</span>
    </div>
    <div class="rule-actions">
      <select data-action>
        <option value="">${t("ruleActionPlaceholder")}</option>
        <option value="DIRECT">DIRECT</option>
        <option value="PROXY">${t("ruleActionProxy")}</option>
        <option value="BLOCK">BLOCK</option>
      </select>
      <select data-target class="target-select is-hidden"></select>
      <button class="icon-btn" data-clear title="${t(
        "ruleClearTitle"
      )}">✕</button>
    </div>
  `;

  const actionSel = row.querySelector("[data-action]");
  const targetSel = row.querySelector("[data-target]");

  function syncTargets(selectedTarget) {
    const targets = state.groups.map((g) => g.name).filter(Boolean);
    if (!targets.length) {
      targetSel.innerHTML = `<option value="" disabled selected>${t(
        "noGroups"
      )}</option>`;
      targetSel.value = "";
      return;
    }
    targetSel.innerHTML = targets
      .map((t) => `<option value="${t}">${t}</option>`)
      .join("");
    if (selectedTarget && targets.includes(selectedTarget)) {
      targetSel.value = selectedTarget;
    } else if (targets.includes(targetSel.value)) {
    } else {
      targetSel.value = targets[0];
    }
  }

  function setTargetVisibility(isProxy) {
    targetSel.classList.toggle("is-hidden", !isProxy);
  }

  function persistDraft(action) {
    const draftVal = {
      action,
      target: action === "PROXY" ? targetSel.value : "",
    };
    if (!action) {
      drafts.delete(name);
    } else drafts.set(name, draftVal);
  }

  function applyToActive() {
    if (!map.has(name)) return;
    const action = actionSel.value;
    if (!action) {
      map.delete(name);
      renderRulesTargets();
      return;
    }
    if (action === "DIRECT") {
      map.set(name, { action, target: "DIRECT" });
      renderRulesTargets();
      return;
    }
    if (action === "BLOCK") {
      map.set(name, { action, target: "REJECT" });
      renderRulesTargets();
      return;
    }
    syncTargets(targetSel.value);
    const tgt = targetSel.value;
    if (!tgt) {
      setStatus("err", t("selectProxyGroup"));
      actionSel.value = "";
      map.delete(name);
      renderRulesTargets();
      return;
    }
    map.set(name, { action, target: tgt });
    row.classList.add("is-active");
  }

  function getPreparedAction() {
    const action = actionSel.value;
    if (!action) return { action: "", target: "" };
    if (action === "PROXY") {
      syncTargets(targetSel.value);
      return { action, target: targetSel.value };
    }
    return { action, target: action === "DIRECT" ? "DIRECT" : "REJECT" };
  }

  function toggleActivation() {
    if (map.has(name)) {
      map.delete(name);
      row.classList.remove("is-active");
      return;
    }

    const prepared = getPreparedAction();
    if (!prepared.action) {
      setStatus("err", t("selectRuleAction"));
      return;
    }
    if (prepared.action === "PROXY" && !prepared.target) {
      setStatus("err", t("selectProxyGroup"));
      return;
    }

    map.set(name, prepared);
    drafts.set(name, { action: prepared.action, target: prepared.target });
    row.classList.add("is-active");
  }

  syncTargets(draft?.target);
  actionSel.value = draft?.action || "";
  setTargetVisibility(actionSel.value === "PROXY");

  actionSel.addEventListener("change", () => {
    const v = actionSel.value;
    setTargetVisibility(v === "PROXY");
    persistDraft(v);
    applyToActive();
  });
  targetSel.addEventListener("change", () => {
    persistDraft(actionSel.value);
    applyToActive();
  });
  row.addEventListener("click", (e) => {
    if (
      e.target.tagName === "SELECT" ||
      e.target.closest("select") ||
      e.target.closest("button")
    )
      return;

    toggleActivation();
  });
  row.querySelector("[data-clear]").addEventListener("click", (e) => {
    e.stopPropagation();
    map.delete(name);
    drafts.delete(name);
    renderRulesTargets();
  });

  return row;
}

function renderGeositeList(filter = "") {
  const trimmed = filter.trim();

  const filterChanged = trimmed !== geositeFilterRaw;
  geositeFilterRaw = trimmed;

  if (filterChanged) {
    geositeListEl.scrollTop = 0;
  }

  if (!state.geosite.length) {
    geositeCountEl.textContent = "0";
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.innerHTML = t("fileNotLoaded");
    geositeVirtual.showMessage(empty);
    updateMoreButton(geositeVirtual, geositeMoreBtn);
    return;
  }

  const f = geositeFilterRaw.toLowerCase();
  const items = state.geosite.filter((x) => !f || x.toLowerCase().includes(f));
  geositeCountEl.textContent = items.length;

  if (!items.length) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = t("noMatches", { query: geositeFilterRaw || "" });
    geositeVirtual.showMessage(empty);
    updateMoreButton(geositeVirtual, geositeMoreBtn);
    return;
  }

  geositeVirtual.setItems(items);
  geositeVirtual.render();
  updateMoreButton(geositeVirtual, geositeMoreBtn);
}

function renderGeoipList(filter = "") {
  const trimmed = filter.trim();

  const filterChanged = trimmed !== geoipFilterRaw;
  geoipFilterRaw = trimmed;

  if (filterChanged) {
    geoipListEl.scrollTop = 0;
  }

  if (!state.geoip.length) {
    geoipCountEl.textContent = "0";
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.innerHTML = t("fileNotLoaded");
    geoipVirtual.showMessage(empty);
    updateMoreButton(geoipVirtual, geoipMoreBtn);
    return;
  }

  const f = geoipFilterRaw.toLowerCase();
  const items = state.geoip.filter((x) => !f || x.toLowerCase().includes(f));
  geoipCountEl.textContent = items.length;

  if (!items.length) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = t("noMatches", { query: geoipFilterRaw || "" });
    geoipVirtual.showMessage(empty);
    updateMoreButton(geoipVirtual, geoipMoreBtn);
    return;
  }

  geoipVirtual.setItems(items);
  geoipVirtual.render();
  updateMoreButton(geoipVirtual, geoipMoreBtn);
}

const geositeStatusEl = document.getElementById("geositeStatus");
const geoipStatusEl = document.getElementById("geoipStatus");

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

function loadGeo(kind) {
  const isGeosite = kind === "geosite";
  const url = isGeosite ? GEOSITE_URL : GEOIP_URL;
  const statusEl = isGeosite ? geositeStatusEl : geoipStatusEl;
  const stateArr = isGeosite ? state.geosite : state.geoip;
  const renderFn = isGeosite ? renderGeositeList : renderGeoipList;
  const label = isGeosite ? "GEOSITE" : "GEOIP";

  stateArr.length = 0;
  statusEl.textContent = t("loadingShort");

  const worker = new Worker("geo-worker.js");

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

document
  .getElementById("loadGeositeBtn")
  .addEventListener("click", () => loadGeo("geosite"));

document
  .getElementById("loadGeoipBtn")
  .addEventListener("click", () => loadGeo("geoip"));

document.getElementById("autoRulesBtn").addEventListener("click", () => {
  const autoRules = [
    "GEOIP,private,DIRECT,no-resolve",
    "IP-CIDR,45.121.184.0/22,DIRECT,no-resolve",
    "IP-CIDR,103.10.124.0/23,DIRECT,no-resolve",
    "IP-CIDR,103.28.54.0/23,DIRECT,no-resolve",
    "IP-CIDR,146.66.152.0/21,DIRECT,no-resolve",
    "IP-CIDR,155.133.224.0/19,DIRECT,no-resolve",
    "IP-CIDR,162.254.192.0/21,DIRECT,no-resolve",
    "IP-CIDR,185.25.180.0/22,DIRECT,no-resolve",
    "IP-CIDR,192.69.96.0/22,DIRECT,no-resolve",
    "IP-CIDR,205.196.6.0/24,DIRECT,no-resolve",
    "IP-CIDR,208.64.200.0/22,DIRECT,no-resolve",
    "IP-CIDR,208.78.164.0/22,DIRECT,no-resolve",
    "GEOSITE,reddit,DIRECT",
    "GEOSITE,steam,DIRECT",
    "GEOSITE,whatsapp,PROXY",
    "GEOSITE,telegram,PROXY",
    "GEOSITE,discord,PROXY",
    "GEOSITE,youtube,PROXY",
    "DOMAIN-KEYWORD,habr,PROXY",
    "GEOSITE,category-media-ru,PROXY",
    "GEOSITE,category-ru,DIRECT",
    "DOMAIN-SUFFIX,ru,DIRECT",
    "DOMAIN-SUFFIX,by,DIRECT",
    "DOMAIN-SUFFIX,xn--p1ai,DIRECT",
    "GEOSITE,category-gov-ru,DIRECT",
    "GEOIP,RU,DIRECT,no-resolve",
    `MATCH,${getMatchPolicyTarget()}`,
  ];
  const yaml = "rules:\n  - " + autoRules.join("\n  - ");
  const toggle = document.getElementById("rulesAdvancedToggle");
  const area = document.getElementById("rulesAdvancedText");
  area.value = yaml;
  if (!toggle.checked) {
    toggle.checked = true;
    toggle.dispatchEvent(new Event("change"));
  }
  setStatus("ok", t("autoRulesInserted"));
});

/* =========================================================
   UI: Subscriptions
========================================================= */
const subsListEl = document.getElementById("subsList");
function renderSubs() {
  subsListEl.innerHTML = "";
  state.subs.forEach((s, idx) => {
    const row = document.createElement("div");
    row.className = "item";
    row.innerHTML = `
      <div style="display:grid;gap:4px;width:100%">
        <div><b>${s.name}</b></div>
        <small>${s.url}</small>
      </div>
      <button class="danger" data-del style="flex:0 0 auto">${t(
        "delete"
      )}</button>
    `;
    row.querySelector("[data-del]").addEventListener("click", () => {
      state.subs.splice(idx, 1);
      renderSubs();
      rebuildInternalStateDebounced();
    });
    subsListEl.appendChild(row);
  });
  if (!state.subs.length) {
    const empty = document.createElement("div");
    empty.className = "hint";
    empty.textContent = t("noSubs");
    subsListEl.appendChild(empty);
  }
}

document.getElementById("addSubBtn").addEventListener("click", () => {
  const url = document.getElementById("subsUrl").value.trim();
  if (!url) return;
  const name = "sub-" + (state.subs.length + 1);
  state.subs.push({ name, url, interval: 3600 });
  document.getElementById("subsUrl").value = "";
  renderSubs();
  rebuildInternalStateDebounced();
});

/* =========================================================
   Advanced toggles
========================================================= */
function bindAdvanced(toggleId, areaId) {
  const t = document.getElementById(toggleId);
  const a = document.getElementById(areaId);
  function sync() {
    a.style.display = t.checked ? "block" : "none";
  }
  t.addEventListener("change", sync);
  sync();
}
bindAdvanced("groupsAdvancedToggle", "groupsAdvancedText");
bindAdvanced("rulesAdvancedToggle", "rulesAdvancedText");
bindAdvanced("subsAdvancedToggle", "subsAdvancedText");

renderSubs();
renderGroups();
renderRulesTargets();

/* =========================================================
   YAML for groups / rules / subs
========================================================= */
function ensureAutoProxyGroup() {
  if (!state.proxies.length && !state.subs.length) return;

  let g = state.groups.find((g) => g.name === "PROXY");

  if (!g) {
    g = {
      name: "PROXY",
      type: "select",
      icon: "",
      proxies: [],
      manual: [],
      useSubs: [],
    };
    state.groups.unshift(g);
  }

  const allProxyNames = state.proxies.map((p) => p.name);
  const prevProxies = (g.proxies || []).filter((n) =>
    allProxyNames.includes(n)
  );
  g.proxies = uniq([...prevProxies, ...allProxyNames]);

  if (state.subs && state.subs.length) {
    const allSubsNames = state.subs.map((s) => s.name);
    const prevUse = (g.useSubs || []).filter((n) => allSubsNames.includes(n));
    g.useSubs = uniq([...prevUse, ...allSubsNames]);
  } else {
    g.useSubs = [];
  }
}

function emitGroupsYaml() {
  if (document.getElementById("groupsAdvancedToggle").checked) {
    return document.getElementById("groupsAdvancedText").value.trim() + "\n";
  }

  if (!state.groups.length && (state.proxies.length || state.subs.length)) {
    ensureAutoProxyGroup();
  }

  if (!state.groups.length) return "";

  const lines = [];
  emitLine(lines, "proxy-groups:");

  state.groups.forEach((g, gi) => {
    emitLine(lines, "- name: " + (g.name || "GROUP"), 2);
    emitLine(lines, "    type: " + g.type, 0);
    if (g.icon) emitLine(lines, "  icon: " + g.icon, 0);

    const list = uniq([...(g.proxies || []), ...(g.manual || [])]);
    if (list.length) {
      emitLine(lines, "    proxies:", 0);
      list.forEach((pn) => emitLine(lines, "    - " + yamlQuote(pn), 0));
    }

    if (g.useSubs && g.useSubs.length) {
      emitLine(lines, "    use:", 0);
      g.useSubs.forEach((sn) => emitLine(lines, "    - " + yamlQuote(sn), 0));
    }

    if (gi !== state.groups.length - 1) emitLine(lines, "");
  });

  return lines.join("\n") + "\n";
}

function emitRulesYaml() {
  if (document.getElementById("rulesAdvancedToggle").checked) {
    return document.getElementById("rulesAdvancedText").value.trim() + "\n";
  }
  const lines = [];
  emitLine(lines, "rules:");
  for (const [name, r] of state.rulesGeosite.entries()) {
    emitLine(lines, `- GEOSITE,${name},${r.target}`, 2);
  }
  for (const [code, r] of state.rulesGeoip.entries()) {
    emitLine(lines, `- GEOIP,${code},${r.target},no-resolve`, 2);
  }
  emitLine(lines, `- MATCH,${getMatchPolicyTarget()}`, 2);

  return lines.join("\n") + "\n";
}

function emitSubsYaml() {
  if (document.getElementById("subsAdvancedToggle").checked) {
    return document.getElementById("subsAdvancedText").value.trim() + "\n";
  }
  if (!state.subs.length) return "";
  const lines = [];
  emitLine(lines, "proxy-providers:");
  state.subs.forEach((s, i) => {
    emitLine(lines, `${s.name}:`, 2);
    emitLine(lines, `type: http`, 4);
    emitLine(lines, `url: ${yamlQuote(s.url)}`, 4);
    emitLine(lines, `interval: ${s.interval}`, 4, false);
    emitLine(lines, `path: ./providers/${s.name}.yaml`, 4, false);
    emitLine(lines, `health-check:`, 4);
    emitLine(lines, `enable: true`, 6);
    emitLine(lines, `url: http://www.gstatic.com/generate_204`, 6, false);
    emitLine(lines, `interval: 600`, 6, false);
    if (i !== state.subs.length - 1) emitLine(lines, "");
  });
  return lines.join("\n") + "\n";
}

/* =========================================================
   Build action
========================================================= */
const rebuildInternalStateDebounced = debounce(rebuildInternalState, 400);

function rebuildInternalState() {
  const { proxies } = parser.parseMany(document.getElementById("input").value);
  state.proxies = proxies || [];

  ensureAutoProxyGroup();
  renderGroups();
  renderRulesTargets();
}

function resolveProxyNameConflicts(proxies, groups) {
  if (!Array.isArray(proxies) || !proxies.length) return;

  const usedNames = new Set();
  const baseCounters = {};
  const baseToNewNames = {};
  proxies.forEach((p) => {
    if (!p) return;
    let base = p.name != null ? String(p.name).trim() : "";
    if (!base) base = "proxy";
    let newName = base;
    if (usedNames.has(newName)) {
      let idx = baseCounters[base] || 1;
      while (usedNames.has(base + "_" + idx)) idx++;
      newName = base + "_" + idx;
      baseCounters[base] = idx + 1;
    } else {
      baseCounters[base] = baseCounters[base] || 1;
    }

    usedNames.add(newName);
    if (!baseToNewNames[base]) baseToNewNames[base] = [];
    baseToNewNames[base].push(newName);

    p.name = newName;
  });
  if (!Array.isArray(groups) || !groups.length) return;
  const remapList = (list) => {
    if (!Array.isArray(list)) return list;
    const usagePerBase = {};
    return list.map((n) => {
      const base = n != null ? String(n).trim() : "";
      const variants = baseToNewNames[base];
      if (!variants || !variants.length) return n;

      const used = usagePerBase[base] || 0;
      const idx = used < variants.length ? used : variants.length - 1;
      usagePerBase[base] = used + 1;
      return variants[idx];
    });
  };

  groups.forEach((g) => {
    if (!g) return;
    if (g.proxies) g.proxies = remapList(g.proxies);
    if (g.manual) g.manual = remapList(g.manual);
  });
}

function buildConfig() {
  const { proxies = [], errors = [] } = parser.parseMany(
    document.getElementById("input").value,
    { collectErrors: true }
  );
  resolveProxyNameConflicts(proxies, state.groups);
  state.proxies = proxies;

  ensureAutoProxyGroup();

  renderGroups();
  renderRulesTargets();

  let yaml = "";

  if (proxies.length) {
    yaml += emitProxiesYaml(proxies);
  }

  const groupsYaml = emitGroupsYaml();
  const subsYaml = emitSubsYaml();
  const rulesYaml = emitRulesYaml();

  if (groupsYaml) yaml += (yaml ? "\n" : "") + groupsYaml.trim() + "\n";
  if (subsYaml) yaml += (yaml ? "\n" : "") + subsYaml.trim() + "\n";
  if (rulesYaml) yaml += (yaml ? "\n" : "") + rulesYaml.trim() + "\n";

  if (!yaml.trim()) {
    if (errors.length) {
      setStatus("err", errors[0].err || t("emptyStatus"));
      return;
    }
    document.getElementById("output").textContent = t("nothingToBuild");
    setStatus("err", t("emptyStatus"));
    return;
  }

  const outputEl = document.getElementById("output");
  outputEl.textContent = yaml;
  delete outputEl.dataset.placeholder;

  if (errors.length) {
    setStatus(
      "err",
      t("errorSummary", { proxies: proxies.length, errors: errors.length })
    );
  } else {
    const parts = [
      proxies.length ? t("countProxies", { count: proxies.length }) : null,
      state.subs.length ? t("countSubs", { count: state.subs.length }) : null,
      state.groups.length
        ? t("countGroups", { count: state.groups.length })
        : null,
      state.rulesGeosite.size + state.rulesGeoip.size
        ? t("countRules", {
            count: state.rulesGeosite.size + state.rulesGeoip.size,
          })
        : null,
    ]
      .filter(Boolean)
      .join(", ");
    setStatus("ok", t("buildSummary", { parts: parts || t("advancedOnly") }));
  }
}

document.getElementById("convertBtn").addEventListener("click", buildConfig);

/* =========================================================
   Demo + misc buttons
========================================================= */
document.getElementById("pasteDemoBtn").addEventListener("click", () => {
  document.getElementById("input").value = [
    "vless://11111111-2222-3333-4444-555555555555@host.example.com:443?type=ws&security=tls&path=%2Fwebsocket#VLESS_WS_TLS",
    "trojan://password@trojan.example.com:443?sni=example.com#TROJAN_TLS",
    "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@ss.example.com:8388#SHADOWSOCKS",
  ].join("\n");
  setStatus(null, t("demoStatus"));
});

document.getElementById("clearBtn").addEventListener("click", () => {
  document.getElementById("input").value = "";
  document.getElementById("output").textContent = "";
  setStatus(null, t("clearedStatus"));
});

document.getElementById("copyBtn").addEventListener("click", async () => {
  const text = document.getElementById("output").textContent.trim();
  if (!text) {
    setStatus("err", t("nothingToCopy"));
    return;
  }
  try {
    await navigator.clipboard.writeText(text);
    setStatus("ok", t("copied"));
  } catch {
    const ta = document.createElement("textarea");
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    document.body.removeChild(ta);
    setStatus("ok", t("copiedFallback"));
  }
});
document.getElementById("downloadBtn").addEventListener("click", () => {
  const text = document.getElementById("output").textContent.trim();
  if (!text) {
    setStatus("err", t("nothingToDownload"));
    return;
  }
  const blob = new Blob([text], { type: "text/yaml;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "config.yaml";
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  setStatus("ok", t("downloaded"));
});

document.getElementById("input").addEventListener("keydown", (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === "Enter") buildConfig();
});
document.getElementById("input").addEventListener("input", () => {
  rebuildInternalStateDebounced();
});

/* =========================================================
   Initial render + language init
========================================================= */

function initApp() {
  setupLanguageSelector();
  applyTranslations();
  renderSubs();
  renderGroups();
  renderRulesTargets();
  syncDynamicTexts();
}
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initApp);
} else {
  initApp();
}
