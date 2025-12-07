import { t } from "./i18n.js";
import { stripSchemeAndPath } from "./utils.js";

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
  let v = raw.trim().toUpperCase();
  if (v.startsWith("AS")) v = v.slice(2);
  if (!/^\d+$/.test(v)) {
    return {
      ok: false,
      error: t("manualErrorAsnNotNumber", { value: raw }),
    };
  }
  return { ok: true, value: v };
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
  return { ok: true, value: v };
}

export function normalizeManualRule(type, rawValue) {
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
