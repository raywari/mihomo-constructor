import {
  state,
  getMatchPolicyTarget,
  normalizeMatchSelection,
} from "./state.js";
import { t, applyTwemoji } from "./i18n.js";
import { fillActionSelect, setStatus } from "./ui-core.js";
import { renderGeositeList, renderGeoipList } from "./geo.js";
import { escapeHtml, isoToFlag, highlightMatch } from "./utils.js";
import { normalizeManualRule } from "./validators.js";

const ruleOrderListEl = document.getElementById("rulesOrderList");
const matchSelectEl = document.getElementById("matchPolicy");
const ruleProvidersListEl = document.getElementById("ruleProvidersList");

let _rebuildCallback = () => {};
export function setRulesRebuildCallback(fn) {
  _rebuildCallback = fn;
}

export function renderRuleProviders() {
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
      _rebuildCallback();
    });

    ruleProvidersListEl.appendChild(row);
  });
  rebuildRuleOrderFromState();
}

export function renderRuleProvidersPolicySelect() {
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
export function initManualRules() {
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
    rebuildRuleOrderFromState();
  });

  renderManualRules();
}

export function renderManualRules() {
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

export function buildRuleEntriesArray() {
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

export function rebuildRuleOrderFromState() {
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

export function renderRuleOrder() {
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

export function renderRulesTargets() {
  renderGeositeList(document.getElementById("geositeSearch").value);
  renderGeoipList(document.getElementById("geoipSearch").value);
  renderRuleProvidersPolicySelect();
  renderRuleProviders();
  rebuildRuleOrderFromState();
}
export function renderMatchSelect() {
  if (!matchSelectEl) return;
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

if (matchSelectEl) {
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
}
export function makeRuleRow(kind, name, pretty, query = "") {
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

export function initRuleListsDelegation() {
  const geositeListEl = document.getElementById("geositeList");
  const geoipListEl = document.getElementById("geoipList");
  [geositeListEl, geoipListEl].forEach((list) => {
    if (!list) return;
    list.addEventListener("change", handleRuleListChange);
    list.addEventListener("click", handleRuleListClick);
  });
}
