import { state, getMatchPolicyTarget } from "./state.js";
import {
  yamlQuote,
  emitLine,
  emitKv,
  emitBool,
  emitList,
  uniq,
} from "./utils.js";
import { buildRuleEntriesArray } from "./rules.js";

export function emitProxiesYaml(proxies) {
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

export function emitGroupsYaml() {
  if (document.getElementById("groupsAdvancedToggle")?.checked) {
    return document.getElementById("groupsAdvancedText").value.trim() + "\n";
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

export function emitRulesYaml() {
  if (document.getElementById("rulesAdvancedToggle")?.checked) {
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

export function emitSubsYaml() {
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

export function emitRuleProvidersYaml() {
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
