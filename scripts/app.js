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
  ruleProviders: [],
  manualRules: [],
  ruleOrder: [],
};

let ruleOrderListEl;

const RULE_BLOCKS = [
  { id: "GEOSITE", label: "GEOSITE — domain lists (geosite)" },
  { id: "GEOIP", label: "GEOIP — countries & IP ranges" },
  { id: "RULE-SET", label: "RULE-SET — rule-providers" },
  { id: "MANUAL", label: "MANUAL — ручные DOMAIN / IP / PROCESS" },
  { id: "MATCH", label: "MATCH — правило по умолчанию" },
];

const GEOSITE_URL = "/geo/geosite.txt";
const GEOIP_URL = "/geo/geoip.txt";
const MATCH_AUTO_VALUE = "__auto__";
const MATCH_POLICIES = [
  { value: "DIRECT", labelKey: "matchPolicyDirect" },
  { value: "REJECT", labelKey: "matchPolicyReject" },
];
const AUTO_GROUP_NAME = "auto";

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

function fillActionSelect(selectEl, { includeReject = true } = {}) {
  if (!selectEl) return;
  const current = selectEl.value;
  selectEl.innerHTML = "";

  const ph = document.createElement("option");
  ph.value = "";
  ph.textContent = t("ruleActionPlaceholder") || "ACTION";
  selectEl.appendChild(ph);

  selectEl.appendChild(new Option("DIRECT", "DIRECT"));
  if (includeReject) selectEl.appendChild(new Option("REJECT", "REJECT"));

  (state.groups || []).forEach((g) => {
    const name = g?.name?.trim();
    if (!name) return;
    selectEl.appendChild(new Option(name, name));
  });

  if ([...selectEl.options].some((o) => o.value === current)) {
    selectEl.value = current;
  } else {
    selectEl.value = "";
  }
}

function applyTranslations() {
  document.documentElement.setAttribute("data-lang", currentLang);

  document.documentElement.dir = currentLang === "fa" ? "rtl" : "ltr";
  document.body.classList.toggle("rtl", currentLang === "fa");

  document.querySelectorAll("[data-i18n]").forEach((el) => {
    const key = el.dataset.i18n;
    const attr = el.dataset.i18nAttr;
    const value = t(key);

    if (attr) {
      el.setAttribute(attr, value);
    } else {
      el.textContent = value;
    }

    if (currentLang === "zh") {
      el.setAttribute("lang", "zh");
    } else if (currentLang === "fa") {
      el.setAttribute("lang", "fa");
    } else if (currentLang === "ru") {
      el.setAttribute("lang", "ru");
    } else {
      el.setAttribute("lang", "en");
    }
  });

  document.querySelectorAll("[data-i18n-aria]").forEach((el) => {
    const key = el.dataset.i18nAria;
    el.setAttribute("aria-label", t(key));
  });
  syncDynamicTexts();
  applyTwemoji(document.body);
}

function syncDynamicTexts() {
  const output = document.getElementById("output");
  if (!output) return;

  const isEmpty = !output.textContent.trim();
  const isPlaceholder = output.getAttribute("data-placeholder") === "true";

  if (isEmpty || isPlaceholder) {
    output.textContent = t("outputPlaceholder");
    output.dataset.placeholder = "true";
  }

  if (!isEmpty && !isPlaceholder) {
    output.removeAttribute("data-placeholder");
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

function applyTwemojiToLang() {
  const scope = document.querySelector(".lang-control");
  if (!scope) return;
  applyTwemoji(scope);
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
    applyTwemojiToLang();
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
    applyTwemojiToLang();
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
        <button class="danger" data-del>\u{1F5D1}\uFE0F ${t(
          "deleteGroup"
        )}</button>
      </div>
    `;

    const [nameInp, typeSel, iconInp, manualInp] =
      card.querySelectorAll("input, select");
    nameInp.addEventListener("change", (e) => {
      g.name = e.target.value.trim() || "GROUP";
      renderMatchSelect();
      rebuildRuleOrderFromState();
      renderRuleProvidersPolicySelect();
      renderSubs();
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
  const manualAction = document.getElementById("manualRuleAction");
  if (manualAction) fillActionSelect(manualAction);
}

document.getElementById("addGroupBtn").addEventListener("click", () => {
  const BASE = "NAME_";

  let maxIndex = 0;
  for (const g of state.groups) {
    if (!g || typeof g.name !== "string") continue;
    const m = g.name.match(/^NAME_(\d+)$/);
    if (m) {
      const num = Number(m[1]);
      if (Number.isFinite(num) && num > maxIndex) {
        maxIndex = num;
      }
    }
  }

  const nextName = `${BASE}${maxIndex + 1}`;

  state.groups.push({
    name: nextName,
    type: "select",
    icon: "",
    proxies: [],
    manual: [],
  });

  renderGroups();
  renderRulesTargets();
  renderMatchSelect();
});

const geositeListEl = document.getElementById("geositeList");
const geoipListEl = document.getElementById("geoipList");
const geositeCountEl = document.getElementById("geositeCount");
const geoipCountEl = document.getElementById("geoipCount");
const geositeShowMoreBtn = document.getElementById("geositeShowMore");
const geoipShowMoreBtn = document.getElementById("geoipShowMore");

const MAX_LIST_ITEMS = 200;

const INITIAL_LIST_LIMIT = 200;
const LIST_LIMIT_STEP = 200;

let geositeVisibleLimit = INITIAL_LIST_LIMIT;
let geoipVisibleLimit = INITIAL_LIST_LIMIT;

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

let geositeFilterRaw = "";
let geoipFilterRaw = "";

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

  fillActionSelect(matchSelectEl);

  let current = "";
  if (state.match.mode === "builtin") {
    current = state.match.value || "";
  } else if (state.match.mode === "group") {
    current = state.match.value || "";
  }

  if (current && [...matchSelectEl.options].some((o) => o.value === current)) {
    matchSelectEl.value = current;
  } else {
    matchSelectEl.value = "";
  }
}

matchSelectEl.addEventListener("change", () => {
  const v = matchSelectEl.value;

  if (!v) {
    state.match = { mode: "auto", value: "" };
  } else if (v === "DIRECT" || v === "REJECT") {
    state.match = { mode: "builtin", value: v };
  } else {
    state.match = { mode: "group", value: v };
  }
  renderRuleOrder();
});

function getMatchPolicyTarget() {
  normalizeMatchSelection();

  if (state.match.mode === "builtin" && state.match.value)
    return state.match.value;
  if (state.match.mode === "group" && state.match.value) {
    const hasGroup = state.groups.some((g) => g.name === state.match.value);
    if (hasGroup) return state.match.value;
  }

  const autoGroup = state.groups.find((g) => g.name === AUTO_GROUP_NAME);
  if (autoGroup?.name) return autoGroup.name;
  if (state.groups.length) return state.groups[0].name;
  return "DIRECT";
}

function renderRulesTargets() {
  renderGeositeList(document.getElementById("geositeSearch").value);
  renderGeoipList(document.getElementById("geoipSearch").value);
  renderRuleProvidersPolicySelect();
  renderRuleProviders();
  rebuildRuleOrderFromState();
}

function renderRuleProvidersPolicySelect() {
  const sel = document.getElementById("ruleProviderPolicy");
  if (!sel) return;

  const groups = state.groups.map((g) => g.name).filter(Boolean);

  const options = [
    `<option value="">${t("ruleActionPlaceholder")}</option>`,
    `<option value="DIRECT">DIRECT</option>`,
    `<option value="REJECT">REJECT</option>`,
    ...groups.map((name) => `<option value="${name}">${name}</option>`),
  ];

  sel.innerHTML = options.join("");
}

function makeRuleRow(kind, name, pretty, query = "") {
  const map = kind === "geosite" ? state.rulesGeosite : state.rulesGeoip;
  const current = map.get(name);
  const displayName = highlightMatch(pretty, query);

  const row = document.createElement("div");
  row.className = "item rule-item";
  if (current) row.classList.add("is-active");

  row.dataset.kind = kind;
  row.dataset.name = name;

  row.innerHTML = `
    <div class="rule-main">
      <span class="pill rule-kind">${kind.toUpperCase()}</span>
      <span class="rule-name"
            title="${escapeHtml(pretty)}"
            data-full="${escapeHtml(pretty)}">${displayName}</span>
      <button class="icon-btn"
              data-role="rule-clear"
              title="${t("ruleClearTitle")}">✕</button>
    </div>
    <div class="rule-actions">
      <select data-role="rule-action"></select>
    </div>
  `;

  const actionSel = row.querySelector('[data-role="rule-action"]');
  fillActionSelect(actionSel);

  if (current) {
    let val = "";
    if (current.action === "PROXY") val = current.target || "";
    else if (current.action === "DIRECT") val = "DIRECT";
    else if (current.action === "BLOCK" || current.target === "REJECT")
      val = "REJECT";
    actionSel.value = val;
  }

  return row;
}

function renderGeositeList(filter = "") {
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

function renderGeoipList(filter = "") {
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

function applyRuleSelection(kind, name, value, row) {
  const map = kind === "geosite" ? state.rulesGeosite : state.rulesGeoip;

  if (!value) {
    map.delete(name);
    row.classList.remove("is-active");
    return;
  }

  if (value === "DIRECT") {
    map.set(name, { action: "DIRECT", target: "DIRECT" });
  } else if (value === "REJECT") {
    map.set(name, { action: "BLOCK", target: "REJECT" });
  } else {
    map.set(name, { action: "PROXY", target: value });
  }

  row.classList.add("is-active");
}

function handleRuleListChange(e) {
  const sel = e.target.closest('select[data-role="rule-action"]');
  if (!sel) return;

  const row = sel.closest(".rule-item");
  if (!row) return;

  const kind = row.dataset.kind;
  const name = row.dataset.name;
  const value = sel.value;

  applyRuleSelection(kind, name, value, row);
  rebuildRuleOrderFromState();
}

function handleRuleListClick(e) {
  const clearBtn = e.target.closest('[data-role="rule-clear"]');
  if (clearBtn) {
    const row = clearBtn.closest(".rule-item");
    if (!row) return;
    const kind = row.dataset.kind;
    const name = row.dataset.name;
    const map = kind === "geosite" ? state.rulesGeosite : state.rulesGeoip;
    map.delete(name);
    row.classList.remove("is-active");
    rebuildRuleOrderFromState();
    return;
  }

  const row = e.target.closest(".rule-item");
  if (!row || e.target.closest("select")) return;

  const kind = row.dataset.kind;
  const name = row.dataset.name;
  const map = kind === "geosite" ? state.rulesGeosite : state.rulesGeoip;
  const sel = row.querySelector('select[data-role="rule-action"]');
  if (!sel) return;

  if (map.has(name)) {
    map.delete(name);
    row.classList.remove("is-active");
  } else {
    const value = sel.value;
    if (!value) {
      setStatus("err", t("selectRuleAction"));
      return;
    }
    applyRuleSelection(kind, name, value, row);
  }

  rebuildRuleOrderFromState();
}

function initRuleListsDelegation() {
  [geositeListEl, geoipListEl].forEach((list) => {
    if (!list) return;
    list.addEventListener("change", handleRuleListChange);
    list.addEventListener("click", handleRuleListClick);
  });
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

  const worker = new Worker("scripts/geo-worker.js");

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
    "GEOIP,private,DIRECT",
    "IP-CIDR,45.121.184.0/22,DIRECT",
    "IP-CIDR,103.10.124.0/23,DIRECT",
    "IP-CIDR,103.28.54.0/23,DIRECT",
    "IP-CIDR,146.66.152.0/21,DIRECT",
    "IP-CIDR,155.133.224.0/19,DIRECT",
    "IP-CIDR,162.254.192.0/21,DIRECT",
    "IP-CIDR,185.25.180.0/22,DIRECT",
    "IP-CIDR,192.69.96.0/22,DIRECT",
    "IP-CIDR,205.196.6.0/24,DIRECT",
    "IP-CIDR,208.64.200.0/22,DIRECT",
    "IP-CIDR,208.78.164.0/22,DIRECT",
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
    "GEOIP,RU,DIRECT",
    `MATCH,${getMatchPolicyTarget()}`,
  ];
  const yaml = "rules:\n  - " + autoRules.join("\n  - ");
  const toggle = document.getElementById("rulesAdvancedToggle");
  const area = document.getElementById("rulesAdvancedText");
  area.value = yaml;
  if (!toggle.checked) {
    toggle.click();
  }
  const subsToggle = document.getElementById("subsAdvancedToggle");
  if (!subsToggle.checked) {
    subsToggle.click();
  }
  setStatus("ok", t("autoRulesInserted"));
});

const ruleProvidersListEl = document.getElementById("ruleProvidersList");

function renderRuleProviders() {
  if (!ruleProvidersListEl) return;

  ruleProvidersListEl.innerHTML = "";

  if (!state.ruleProviders.length) {
    const empty = document.createElement("div");
    empty.className = "hint";
    empty.textContent = t("noRuleProviders") || "Нет провайдеров правил";
    ruleProvidersListEl.appendChild(empty);
    return;
  }

  state.ruleProviders.forEach((rp, idx) => {
    const row = document.createElement("div");
    row.className = "item";

    row.innerHTML = `
      <div style="display:grid;gap:4px;width:100%">
        <div>
          <b>${rp.name}</b>
          <span class="pill">RULE-SET → ${rp.policy || "?"}</span>
        </div>
        <small>${rp.url}</small>
        <small>
          behavior: ${rp.behavior || "classical"}
          · format: ${rp.format || "yaml"}
        </small>
      </div>
      <button class="danger" data-del style="flex:0 0 auto">${t(
        "delete"
      )}</button>
    `;

    row.querySelector("[data-del]").addEventListener("click", () => {
      state.ruleProviders.splice(idx, 1);
      renderRuleProviders();
      rebuildInternalStateDebounced();
    });

    ruleProvidersListEl.appendChild(row);
  });
  rebuildRuleOrderFromState();
}

const subsListEl = document.getElementById("subsList");
function renderSubs() {
  const list = document.getElementById("subsList");
  if (!list) return;
  list.innerHTML = "";

  if (!state.subs.length) return;

  const groupNames = [
    "GLOBAL",
    ...(state.groups || []).map((g) => g.name).filter(Boolean),
  ];

  state.subs.forEach((sub, i) => {
    const item = document.createElement("div");
    item.className = "item";

    item.innerHTML = `
      <label style="gap:10px; align-items:center;">
        <div style="flex:1; min-width:0;">
          <div><b>${sub.name}</b></div>
          <small style="opacity:.8; word-break:break-all;">${sub.url}</small>
        </div>

<select data-sub-proxy-mode="${i}">
          <option value="DIRECT" ${
            sub.fetchMode === "DIRECT" ? "selected" : ""
          }>DIRECT</option>
          <option value="PROXY" ${
            sub.fetchMode === "PROXY" ? "selected" : ""
          }>via Proxy</option>
        </select>

<select data-sub-proxy-name="${i}"
                style="max-width:140px; ${
                  sub.fetchMode === "PROXY" ? "" : "display:none;"
                }">
          ${groupNames
            .map(
              (n) =>
                `<option value="${n}" ${
                  sub.fetchProxy === n ? "selected" : ""
                }>${n}</option>`
            )
            .join("")}
        </select>
      <button class="danger" data-sub-del style="flex:0 0 auto">${t(
        "delete"
      )}</button>
      </label>
    `;

    list.appendChild(item);
  });

  list.querySelectorAll("[data-sub-proxy-mode]").forEach((sel) => {
    sel.addEventListener("change", (e) => {
      const idx = +e.target.dataset.subProxyMode;
      state.subs[idx].fetchMode = e.target.value;

      renderSubs();
      rebuildInternalStateDebounced();
    });
  });

  list.querySelectorAll("[data-sub-proxy-name]").forEach((sel) => {
    sel.addEventListener("change", (e) => {
      const idx = +e.target.dataset.subProxyName;
      state.subs[idx].fetchProxy = e.target.value;
      rebuildInternalStateDebounced();
    });
  });

  list.querySelectorAll("[data-sub-del]").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      const idx = +e.target.dataset.subDel;
      state.subs.splice(idx, 1);
      renderSubs();
      rebuildInternalStateDebounced();
    });
  });
}

document.getElementById("addSubBtn").addEventListener("click", () => {
  const urlInput = document.getElementById("subsUrl");
  const url = urlInput.value.trim();
  if (!url) return;

  const fetchMode = document.getElementById("subsFetchMode")?.value || "DIRECT";
  const skipCertVerify = !!document.getElementById("subsSkipCert")?.checked;

  const name = "sub-" + (state.subs.length + 1);

  state.subs.push({
    name,
    url,
    interval: 3600,
    fetchMode,
    fetchProxy: "GLOBAL",
    skipCertVerify,
  });

  urlInput.value = "";
  renderSubs();
  rebuildInternalStateDebounced();
});

document.getElementById("addRuleProviderBtn").addEventListener("click", () => {
  const nameInput = document.getElementById("ruleProviderName");
  const urlInput = document.getElementById("ruleProviderUrl");
  const behaviorSel = document.getElementById("ruleProviderBehavior");
  const policySel = document.getElementById("ruleProviderPolicy");

  const name = nameInput.value.trim();
  const url = urlInput.value.trim();
  const behavior = behaviorSel.value || "classical";
  const policy = policySel.value;

  if (!name || !url) {
    setStatus("err", t("ruleProvidersNameUrlRequired") || "Нужно имя и URL");
    return;
  }
  if (!policy) {
    setStatus("err", t("selectProxyGroup"));
    return;
  }

  if (state.ruleProviders.some((rp) => rp.name === name)) {
    setStatus("err", t("ruleProvidersNameExists") || "Такое имя уже есть");
    return;
  }

  state.ruleProviders.push({
    name,
    url,
    behavior,
    policy,
    type: "http",
    format: "yaml",
    path: `./rules/${name}.yaml`,
    interval: 600,
  });

  nameInput.value = "";
  urlInput.value = "";

  renderRuleProviders();
  rebuildInternalStateDebounced();
});

function bindAdvanced(toggleId, areaId) {
  const t = document.getElementById(toggleId);
  const a = document.getElementById(areaId);
  const track = t.nextElementSibling;

  function sync() {
    const on = t.checked;
    a.style.display = on ? "block" : "none";
    if (track) {
      track.classList.toggle("is-on", on);
      if (track) {
        track.classList.toggle("is-on", on);
        track.offsetWidth;
      }
      track.offsetWidth;
    }
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

function ensureAutoProxyGroup() {
  if (!state.proxies.length && !state.subs.length) return;

  let g = state.groups.find((g) => g.name === AUTO_GROUP_NAME);

  if (!g) {
    g = {
      name: AUTO_GROUP_NAME,
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

  const entries =
    Array.isArray(state.ruleOrder) && state.ruleOrder.length
      ? state.ruleOrder
      : buildRuleEntriesArray();

  entries.forEach((e) => {
    switch (e.kind) {
      case "GEOSITE":
        emitLine(lines, `- GEOSITE,${e.key},${e.policy}`, 2);
        break;
      case "GEOIP":
        emitLine(lines, `- GEOIP,${e.key},${e.policy}`, 2);
        break;
      case "RULE-SET":
        emitLine(lines, `- RULE-SET,${e.key},${e.policy}`, 2);
        break;
      case "MANUAL":
        emitLine(lines, `- ${e.key},${e.policy}`, 2);
        break;
      case "MATCH":
        emitLine(lines, `- MATCH,${getMatchPolicyTarget()}`, 2);
        break;
    }
  });

  return lines.join("\n") + "\n";
}

function getOrderedRuleEntries() {
  const raw = buildRuleEntriesArray();
  const byId = new Map(raw.map((e) => [e.id, e]));

  const order = Array.isArray(state.ruleOrder) ? state.ruleOrder : [];
  const result = [];

  for (const id of order) {
    const e = byId.get(id);
    if (!e) continue;
    result.push(e);
    byId.delete(id);
  }

  for (const e of byId.values()) {
    result.push(e);
  }

  return result;
}

function emitSubsYaml() {
  const advToggle = document.getElementById("subsAdvancedToggle");
  const advText = document.getElementById("subsAdvancedText");

  if (advToggle?.checked) {
    return advText?.value?.trim() || "";
  }

  if (!state.subs.length) return "";

  let out = "proxy-providers:\n";

  state.subs.forEach((sub) => {
    out += `  ${sub.name}:\n`;
    out += `    type: http\n`;
    out += `    url: "${sub.url}"\n`;
    out += `    interval: ${sub.interval || 3600}\n`;
    out += `    path: ./providers/${sub.name}.yaml\n`;

    if (sub.fetchMode === "PROXY" && sub.fetchProxy) {
      out += `    proxy: ${sub.fetchProxy}\n`;
    }

    out += `    health-check:\n`;
    out += `      enable: true\n`;
    out += `      url: http://www.gstatic.com/generate_204\n`;
    out += `      interval: 600\n`;
  });

  return out.trim();
}

function emitRuleProvidersYaml() {
  if (!state.ruleProviders || !state.ruleProviders.length) return "";

  const lines = [];
  emitLine(lines, "rule-providers:");

  state.ruleProviders.forEach((rp, i) => {
    emitLine(lines, `${rp.name}:`, 2);
    emitLine(lines, `type: ${rp.type || "http"}`, 4);
    if (rp.path) {
      emitLine(lines, `path: ${yamlQuote(rp.path)}`, 4);
    }
    emitLine(lines, `url: ${yamlQuote(rp.url)}`, 4);
    if (rp.interval != null) {
      emitLine(lines, `interval: ${rp.interval}`, 4, false);
    }
    if (rp.proxy) {
      emitLine(lines, `proxy: ${rp.proxy}`, 4);
    }
    if (rp.behavior) {
      emitLine(lines, `behavior: ${rp.behavior}`, 4);
    }
    if (rp.format) {
      emitLine(lines, `format: ${rp.format}`, 4, false);
    }
    if (i !== state.ruleProviders.length - 1) emitLine(lines, "");
  });

  return lines.join("\n") + "\n";
}

const rebuildInternalStateDebounced = debounce(rebuildInternalState, 700);

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
  const ruleProvidersYaml = emitRuleProvidersYaml();
  const rulesYaml = emitRulesYaml();

  if (subsYaml) yaml += (yaml ? "\n" : "") + subsYaml.trim() + "\n";
  if (groupsYaml) yaml += (yaml ? "\n" : "") + groupsYaml.trim() + "\n";
  if (ruleProvidersYaml)
    yaml += (yaml ? "\n" : "") + ruleProvidersYaml.trim() + "\n";
  if (rulesYaml) yaml += (yaml ? "\n" : "") + rulesYaml.trim() + "\n";

  if (!yaml.trim()) {
    const outputEl = document.getElementById("output");
    outputEl.textContent = t("outputPlaceholder");
    outputEl.dataset.placeholder = "true";

    if (errors.length) {
      setStatus("err", errors[0].err || t("emptyStatus"));
    } else {
      setStatus("err", t("emptyStatus"));
    }
    return;
  }

  const outputEl = document.getElementById("output");
  outputEl.textContent = yaml;
  delete outputEl.dataset.placeholder;
  outputEl.removeAttribute("data-placeholder");

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
  const out = document.getElementById("output");
  out.textContent = t("outputPlaceholder");
  out.dataset.placeholder = "true";
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

const twemojiOptions = {
  base: "https://raw.githubusercontent.com/twitter/twemoji/v14.0.2/assets/",
  folder: "svg",
  ext: ".svg",
  className: "emoji",
};

function applyTwemoji(scope) {
  if (!scope || typeof twemoji === "undefined") return;
  try {
    twemoji.parse(scope, twemojiOptions);
  } catch (e) {
    console.warn("twemoji.parse failed", e);
  }
}
function debounce(fn, delay = 120) {
  let t;
  return (...args) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...args), delay);
  };
}

function initManualRules() {
  const typeEl = document.getElementById("manualRuleType");
  const valueEl = document.getElementById("manualRuleValue");
  const actionEl = document.getElementById("manualRuleAction");
  const addBtn = document.getElementById("addManualRuleBtn");

  if (!typeEl || !valueEl || !actionEl || !addBtn) return;

  fillActionSelect(actionEl);

  addBtn.addEventListener("click", () => {
    const type = typeEl.value.trim();
    const rawValue = valueEl.value.trim();
    const actionValue = actionEl.value.trim();

    if (!type || !rawValue || !actionValue) {
      alert(t("manualRulesFillAll"));
      return;
    }

    const normalized = normalizeManualRule(type, rawValue);
    if (!normalized.ok) {
      alert(normalized.error);
      return;
    }

    let action = "";
    let target = "";

    if (actionValue === "DIRECT") {
      action = "DIRECT";
      target = "";
    } else if (actionValue === "REJECT") {
      action = "BLOCK";
      target = "REJECT";
    } else {
      action = "PROXY";
      target = actionValue;
    }

    state.manualRules.push({
      id: Date.now() + Math.random().toString(16).slice(2),
      type,
      value: normalized.value,
      action,
      target,
    });

    valueEl.value = "";
    actionEl.value = "";

    renderManualRules();
  });

  renderManualRules();
  rebuildRuleOrderFromState();
}

function renderManualRules() {
  const listEl = document.getElementById("manualRulesList");
  if (!listEl) return;

  listEl.innerHTML = "";

  const rules = state.manualRules || [];

  if (!rules.length) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = t("manualRulesEmpty");
    listEl.appendChild(empty);
    return;
  }

  rules.forEach((rule) => {
    const item = document.createElement("div");
    item.className = "rule-item";

    const main = document.createElement("div");
    main.className = "rule-main";

    const kind = document.createElement("span");
    kind.className = "pill rule-kind";
    kind.textContent = rule.type;

    let policy = "";
    if (rule.action === "DIRECT") policy = "DIRECT";
    else if (rule.action === "BLOCK" || rule.target === "REJECT")
      policy = "REJECT";
    else if (rule.action === "PROXY") policy = rule.target || "PROXY";

    const name = document.createElement("div");
    name.className = "rule-name";
    const payload = `${rule.type},${rule.value},${policy}`;
    name.textContent = payload;
    name.setAttribute("data-full", payload);

    main.appendChild(kind);
    main.appendChild(name);

    const actions = document.createElement("div");
    actions.className = "rule-actions";

    const removeBtn = document.createElement("button");
    removeBtn.className = "icon-btn";
    removeBtn.type = "button";
    removeBtn.textContent = "✕";
    removeBtn.title = t("manualRulesDelete");

    removeBtn.addEventListener("click", () => {
      const idx = state.manualRules.findIndex((r) => r.id === rule.id);
      if (idx !== -1) {
        state.manualRules.splice(idx, 1);
        renderManualRules();
        rebuildRuleOrderFromState();
      }
    });

    actions.appendChild(removeBtn);

    item.appendChild(main);
    item.appendChild(actions);

    listEl.appendChild(item);
  });
}

function getManualRulesYaml() {
  return state.manualRules.map((r) => {
    let policy = "";
    if (r.action === "DIRECT") policy = "DIRECT";
    else if (r.action === "BLOCK" || r.target === "REJECT") policy = "REJECT";
    else if (r.action === "PROXY") policy = r.target;

    return `${r.type},${r.value},${policy}`;
  });
}

function stripSchemeAndPath(s) {
  return s
    .replace(/^\s*https?:\/\//i, "")
    .replace(/^\s*ws?:\/\//i, "")
    .split(/[\/\?#]/)[0]
    .trim();
}

function isValidDomain(d) {
  if (!d || d.length > 253) return false;
  const parts = d.split(".");
  if (parts.length < 2) return false;
  for (const p of parts) {
    if (!p || p.length > 63) return false;
    if (!/^[a-z0-9-]+$/i.test(p)) return false;
    if (/^-|-$/.test(p)) return false;
  }
  return true;
}

function normalizeDomain(type, raw) {
  let v = stripSchemeAndPath(raw).toLowerCase();
  v = v.replace(/\s+/g, "");

  if (v.startsWith("*.")) v = v.slice(2);

  if (!isValidDomain(v)) {
    return {
      ok: false,
      error: t("manualErrorInvalidDomain", { value: raw }),
    };
  }

  v = v.replace(/\.$/, "");
  return { ok: true, value: v };
}

function normalizeKeyword(raw) {
  let v = stripSchemeAndPath(raw).toLowerCase().trim();
  v = v.replace(/\s+/g, "");
  if (!v) {
    return { ok: false, error: t("manualErrorEmptyKeyword") };
  }
  if (/[\/\\]/.test(v)) {
    return {
      ok: false,
      error: t("manualErrorKeywordSlash"),
    };
  }
  return { ok: true, value: v };
}

function isValidIPv4(ip) {
  const m = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  for (let i = 1; i <= 4; i++) {
    const n = +m[i];
    if (n < 0 || n > 255) return false;
  }
  return true;
}

function normalizeCidr(raw) {
  let v = raw.trim();

  if (isValidIPv4(v)) {
    return { ok: true, value: `${v}/32` };
  }

  const m = v.match(/^(.+?)\/(\d{1,2})$/);
  if (!m) {
    return {
      ok: false,
      error: t("manualErrorInvalidCidrIp", { value: raw }),
    };
  }
  const ip = m[1].trim();
  const mask = +m[2];
  if (!isValidIPv4(ip)) {
    return {
      ok: false,
      error: t("manualErrorInvalidIPv4", { value: ip }),
    };
  }
  if (!Number.isInteger(mask) || mask < 0 || mask > 32) {
    return {
      ok: false,
      error: t("manualErrorMaskRange", { value: raw }),
    };
  }
  return { ok: true, value: `${ip}/${mask}` };
}

function normalizeAsn(raw) {
  const v = raw.trim();
  if (!/^\d+$/.test(v)) {
    return {
      ok: false,
      error: t("manualErrorAsnNotNumber", { value: raw }),
    };
  }
}

function normalizeProcessName(raw) {
  let v = raw.trim().replace(/^"+|"+$/g, "");
  if (!v) {
    return { ok: false, error: t("manualErrorProcessNameEmpty") };
  }
  if (/[\/\\:]/.test(v)) {
    return {
      ok: false,
      error: t("manualErrorProcessNamePath"),
    };
  }
  return { ok: true, value: v };
}

function normalizeProcessPath(raw) {
  let v = raw.trim().replace(/^"+|"+$/g, "");
  if (!v) {
    return { ok: false, error: t("manualErrorProcessPathEmpty") };
  }
  const looksWindows = /^[a-zA-Z]:\\/.test(v) || v.startsWith("\\\\");
  const looksUnix = v.startsWith("/");
  if (!looksWindows && !looksUnix) {
    return {
      ok: false,
      error: t("manualErrorProcessPathFull"),
    };
  }
}

function normalizeManualRule(type, rawValue) {
  switch (type) {
    case "DOMAIN-SUFFIX":
      return normalizeDomain(type, rawValue);
    case "DOMAIN-KEYWORD":
      return normalizeKeyword(rawValue);
    case "IP-CIDR":
      return normalizeCidr(rawValue);
    case "IP-ASN":
      return normalizeAsn(rawValue);
    case "PROCESS-NAME":
      return normalizeProcessName(rawValue);
    case "PROCESS-PATH":
      return normalizeProcessPath(rawValue);
    default:
      return { ok: true, value: rawValue.trim() };
  }
}

function buildRuleEntriesArray() {
  const entries = [];

  for (const [name, r] of state.rulesGeosite.entries()) {
    entries.push({
      id: `GEOSITE:${name}`,
      kind: "GEOSITE",
      key: name,
      policy: r.target,
    });
  }

  for (const [code, r] of state.rulesGeoip.entries()) {
    entries.push({
      id: `GEOIP:${code}`,
      kind: "GEOIP",
      key: code,
      policy: r.target,
    });
  }

  if (state.ruleProviders && state.ruleProviders.length) {
    state.ruleProviders.forEach((rp) => {
      if (!rp.policy) return;
      entries.push({
        id: `RULE-SET:${rp.name}`,
        kind: "RULE-SET",
        key: rp.name,
        policy: rp.policy,
      });
    });
  }

  (state.manualRules || []).forEach((r) => {
    let policy = "";
    if (r.action === "DIRECT") policy = "DIRECT";
    else if (r.action === "BLOCK" || r.target === "REJECT") policy = "REJECT";
    else if (r.action === "PROXY") policy = r.target || "PROXY";

    entries.push({
      id: `MANUAL:${r.id}`,
      kind: "MANUAL",
      key: `${r.type},${r.value}`,
      policy,
    });
  });

  entries.push({
    id: "MATCH:__default__",
    kind: "MATCH",
    key: "MATCH",
    policy: getMatchPolicyTarget(),
  });

  return entries;
}

function rebuildRuleOrderFromState() {
  const raw = buildRuleEntriesArray();

  if (!raw.length) {
    state.ruleOrder = [];
    renderRuleOrder();
    return;
  }

  const matchEntry = raw.find((e) => e.kind === "MATCH") || null;
  const nonMatchRaw = raw.filter((e) => e.kind !== "MATCH");

  const byId = new Map(nonMatchRaw.map((e) => [e.id, e]));

  const prev = Array.isArray(state.ruleOrder) ? state.ruleOrder : [];
  const next = [];

  for (const old of prev) {
    if (old.kind === "MATCH") continue;
    const fresh = byId.get(old.id);
    if (fresh) {
      next.push(fresh);
      byId.delete(old.id);
    }
  }

  for (const e of byId.values()) {
    next.push(e);
  }

  if (matchEntry) {
    next.push(matchEntry);
  }

  state.ruleOrder = next;
  renderRuleOrder();
}

function renderRuleOrder() {
  if (!ruleOrderListEl) return;

  ruleOrderListEl.innerHTML = "";

  const items =
    Array.isArray(state.ruleOrder) && state.ruleOrder.length
      ? state.ruleOrder
      : buildRuleEntriesArray();

  if (!items.length) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = t("ruleOrderEmpty");
    ruleOrderListEl.appendChild(empty);
    return;
  }

  const matchKind = "MATCH";

  items.forEach((entry, index) => {
    const row = document.createElement("div");
    row.className = "rule-order-item";
    if (entry.kind === matchKind) {
      row.classList.add("rule-order-match");
    }

    let kindLabel = "";
    switch (entry.kind) {
      case "GEOSITE":
        kindLabel = t("ruleOrderKindGeosite");
        break;
      case "GEOIP":
        kindLabel = t("ruleOrderKindGeoip");
        break;
      case "RULE-SET":
        kindLabel = t("ruleOrderKindRuleSet");
        break;
      case "MANUAL":
        kindLabel = t("ruleOrderKindManual");
        break;
      case "MATCH":
        kindLabel = t("ruleOrderKindMatch");
        break;
    }

    let label = "";
    if (entry.kind !== matchKind) {
      if (entry.kind === "GEOIP") {
        const code = String(entry.key ?? "");
        const flag = isoToFlag(code);
        const pretty = flag ? `${flag}\u00A0${code}` : code;
        label = escapeHtml(pretty);
      } else {
        label = escapeHtml(String(entry.key ?? ""));
      }
    }

    row.innerHTML = `
      <div class="rule-order-main">
        <span class="pill">${kindLabel}</span>
        ${label ? `<span class="rule-order-label">${label}</span>` : ""}
      </div>
      <div class="rule-order-actions"></div>
    `;

    const actions = row.querySelector(".rule-order-actions");

    if (entry.kind !== matchKind) {
      const downBtn = document.createElement("button");
      downBtn.type = "button";
      downBtn.className = "icon-btn move-down";
      downBtn.title = t("ruleOrderMoveDown");
      downBtn.textContent = "↓";
      downBtn.addEventListener("click", () => moveRuleOrder(index, +1));

      const upBtn = document.createElement("button");
      upBtn.type = "button";
      upBtn.className = "icon-btn move-up";
      upBtn.title = t("ruleOrderMoveUp");
      upBtn.textContent = "↑";
      upBtn.addEventListener("click", () => moveRuleOrder(index, -1));

      const bottomBtn = document.createElement("button");
      bottomBtn.type = "button";
      bottomBtn.className = "icon-btn move-bottom";
      bottomBtn.title = t("ruleOrderMoveBottom") || "Move to bottom";
      bottomBtn.textContent = "⇣";
      bottomBtn.addEventListener("click", () =>
        moveRuleOrderToEdge(index, "bottom")
      );

      const topBtn = document.createElement("button");
      topBtn.type = "button";
      topBtn.className = "icon-btn move-top";
      topBtn.title = t("ruleOrderMoveTop") || "Move to top";
      topBtn.textContent = "⇡";
      topBtn.addEventListener("click", () => moveRuleOrderToEdge(index, "top"));

      actions.appendChild(downBtn);
      actions.appendChild(bottomBtn);
      actions.appendChild(topBtn);
      actions.appendChild(upBtn);
    }

    ruleOrderListEl.appendChild(row);
  });

  applyTwemoji(ruleOrderListEl);
}

function moveRuleOrder(index, delta) {
  const items =
    Array.isArray(state.ruleOrder) && state.ruleOrder.length
      ? state.ruleOrder
      : (state.ruleOrder = buildRuleEntriesArray());

  const item = items[index];
  if (!item) return;

  if (item.kind === "MATCH") return;

  const movableCount = items.filter((e) => e.kind !== "MATCH").length;

  let to = index + delta;
  if (to < 0 || to >= movableCount) return;

  items.splice(index, 1);
  items.splice(to, 0, item);

  renderRuleOrder();
}

function moveRuleOrderToEdge(index, direction) {
  const items =
    Array.isArray(state.ruleOrder) && state.ruleOrder.length
      ? state.ruleOrder
      : (state.ruleOrder = buildRuleEntriesArray());

  const item = items[index];
  if (!item) return;

  if (item.kind === "MATCH") return;

  const movable = items.filter((e) => e.kind !== "MATCH");
  const movableCount = movable.length;
  if (!movableCount) return;

  const target = direction === "top" ? 0 : movableCount - 1;
  if (index === target) return;

  items.splice(index, 1);
  items.splice(target, 0, item);

  renderRuleOrder();
}

function initApp() {
  ruleOrderListEl = document.getElementById("rulesOrderList");
  setupLanguageSelector();
  applyTranslations();
  renderSubs();
  renderGroups();
  renderRulesTargets();
  syncDynamicTexts();
  applyTwemoji(document.body);
  initManualRules();
  rebuildRuleOrderFromState();
  initRuleListsDelegation();
}
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initApp);
} else {
  initApp();
}
