export const GEOSITE_URL = new URL("../geo/geosite.txt", import.meta.url).href;
export const GEOIP_URL = new URL("../geo/geoip.txt", import.meta.url).href;
export const MATCH_AUTO_VALUE = "__auto__";
export const AUTO_GROUP_NAME = "auto";

export const MATCH_POLICIES = [
  { value: "DIRECT", labelKey: "matchPolicyDirect" },
  { value: "REJECT", labelKey: "matchPolicyReject" },
];

export const RULE_BLOCKS = [
  { id: "GEOSITE", label: "GEOSITE — domain lists (geosite)" },
  { id: "GEOIP", label: "GEOIP — countries & IP ranges" },
  { id: "RULE-SET", label: "RULE-SET — rule-providers" },
  { id: "MANUAL", label: "MANUAL — ручные DOMAIN / IP / PROCESS" },
  { id: "MATCH", label: "MATCH — правило по умолчанию" },
];
