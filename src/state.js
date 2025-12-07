import { MATCH_POLICIES, AUTO_GROUP_NAME } from "./constants.js";
import { uniq } from "./utils.js";

export const state = {
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
export function normalizeMatchSelection() {
  if (state.match.mode === "builtin") {
    const exists = MATCH_POLICIES.some((p) => p.value === state.match.value);
    if (!exists) state.match = { mode: "auto", value: "" };
  }
  if (state.match.mode === "group") {
    const hasGroup = state.groups.some((g) => g.name === state.match.value);
    if (!hasGroup) state.match = { mode: "auto", value: "" };
  }
}

export function getMatchPolicyTarget() {
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

export function ensureAutoProxyGroup() {
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

export function resolveProxyNameConflicts(proxies, groups) {
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
