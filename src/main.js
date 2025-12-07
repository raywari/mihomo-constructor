import {
  state,
  ensureAutoProxyGroup,
  resolveProxyNameConflicts,
  getMatchPolicyTarget,
} from "./state.js";
import {
  t,
  applyTranslations,
  setupLanguageSelector,
  syncDynamicTexts,
  applyTwemoji,
} from "./i18n.js";
import { setStatus } from "./ui-core.js";
import { renderGroups } from "./groups.js";
import {
  renderRulesTargets,
  renderMatchSelect,
  initManualRules,
  rebuildRuleOrderFromState,
  initRuleListsDelegation,
  renderRuleProviders,
  setRulesRebuildCallback,
} from "./rules.js";
import { renderSubs, setSubsRebuildCallback } from "./subs.js";
import { setupGeoListeners } from "./geo.js";
import {
  emitProxiesYaml,
  emitGroupsYaml,
  emitSubsYaml,
  emitRuleProvidersYaml,
  emitRulesYaml,
} from "./yaml-gen.js";
import { debounce } from "./utils.js";
import { parseMany } from "./parser.js";
function rebuildInternalState() {
  const { proxies } = parseMany(document.getElementById("input").value);
  state.proxies = proxies || [];
  state.proxies = proxies || [];

  ensureAutoProxyGroup();
  renderGroups();
  renderRulesTargets();
}

const rebuildInternalStateDebounced = debounce(rebuildInternalState, 700);
setSubsRebuildCallback(rebuildInternalStateDebounced);
setRulesRebuildCallback(rebuildInternalStateDebounced);

function buildConfig() {
  const { proxies = [], errors = [] } = parseMany(
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

function initEventListeners() {
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
  document.getElementById("addGroupBtn").addEventListener("click", () => {
    const BASE = "NAME_";
    let maxIndex = 0;
    for (const g of state.groups) {
      if (!g || typeof g.name !== "string") continue;
      const m = g.name.match(/^NAME_(\d+)$/);
      if (m) {
        const num = Number(m[1]);
        if (Number.isFinite(num) && num > maxIndex) maxIndex = num;
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
  document.getElementById("addSubBtn").addEventListener("click", () => {
    const urlInput = document.getElementById("subsUrl");
    const url = urlInput.value.trim();
    if (!url) return;

    const fetchMode =
      document.getElementById("subsFetchMode")?.value || "DIRECT";
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
  document
    .getElementById("addRuleProviderBtn")
    .addEventListener("click", () => {
      const nameInput = document.getElementById("ruleProviderName");
      const urlInput = document.getElementById("ruleProviderUrl");
      const behaviorSel = document.getElementById("ruleProviderBehavior");
      const policySel = document.getElementById("ruleProviderPolicy");

      const name = nameInput.value.trim();
      const url = urlInput.value.trim();
      const behavior = behaviorSel.value || "classical";
      const policy = policySel.value;

      if (!name || !url) {
        setStatus(
          "err",
          t("ruleProvidersNameUrlRequired") || "Нужно имя и URL"
        );
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
}

function initApp() {
  window.state = state;

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

  bindAdvanced("groupsAdvancedToggle", "groupsAdvancedText");
  bindAdvanced("rulesAdvancedToggle", "rulesAdvancedText");
  bindAdvanced("subsAdvancedToggle", "subsAdvancedText");

  initEventListeners();
  setupGeoListeners(renderRulesTargets); // Pass callback to update rules when GEO resets
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initApp);
} else {
  initApp();
}
