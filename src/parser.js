const atobCompat =
  typeof atob === "function"
    ? atob
    : (str) => Buffer.from(str, "base64").toString("binary");

export function b64decodeAuto(data) {
  if (!data) return "";
  data = data.replace(/-/g, "+").replace(/_/g, "/");
  const pad = (4 - (data.length % 4)) % 4;
  data += "=".repeat(pad);
  try {
    const bin = atobCompat(data);
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  } catch {
    return "";
  }
}

function stripControlChars(s) {
  if (s == null) return s;
  return String(s).replace(/[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F]/g, "");
}

function sanitizeString(input, fallback = "") {
  if (input == null) return fallback;

  let s = String(input);
  try {
    s = s.normalize("NFKC");
  } catch {}
  s = s.replace(
    /([\uD800-\uDBFF](?![\uDC00-\uDFFF]))|((?<![\uD800-\uDBFF])[\uDC00-\uDFFF])/g,
    ""
  );
  s = s.replace(/[\u0000-\u001F\u007F-\u009F]/g, "");
  s = s.replace(/[\u200E\u200F\u202A-\u202E\u2066-\u2069]/g, "");
  s = s.replace(/[\uFE00-\uFE0F]/g, "");
  s = s.replace(/\s+/g, " ").trim();
  if (s.length > 120) s = s.slice(0, 120);

  return s || fallback;
}

function parsedQs(u) {
  const o = {};
  u.searchParams.forEach((v, k) => (o[k] = v));
  return o;
}

export function normalizeInputLines(raw) {
  if (!raw) return [];
  raw = raw.trim();
  if (!raw) return [];
  if (!raw.includes("://") && /^[A-Za-z0-9+/_-]+=*$/.test(raw)) {
    const dec = b64decodeAuto(raw);
    if (dec.includes("://")) raw = dec;
  }

  const schemes = [
    "vless://",
    "vmess://",
    "ss://",
    "trojan://",
    "ssr://",
    "hysteria://",
    "hy://",
    "hy2://",
    "hysteria2://",
    "tuic://",
  ];

  const result = [];
  const chunks = raw.split(/\s+/g);

  for (const chunk of chunks) {
    const text = chunk.trim();
    if (!text) continue;

    let i = 0;
    let found = false;

    while (i < text.length) {
      let start = -1;
      let schemeUsed = "";
      for (const s of schemes) {
        const idx = text.indexOf(s, i);
        if (idx !== -1 && (start === -1 || idx < start)) {
          start = idx;
          schemeUsed = s;
        }
      }

      if (start === -1) break;
      found = true;
      let end = text.length;
      for (const s of schemes) {
        const idx = text.indexOf(s, start + schemeUsed.length);
        if (idx !== -1 && idx < end) {
          end = idx;
        }
      }

      const candidate = text.slice(start, end).trim();
      if (candidate) result.push(candidate);
      i = end;
    }
    if (!found && text.includes("://")) {
      result.push(text);
    }
  }

  return result;
}

function readBool(q, key) {
  if (!(key in q)) return undefined;
  const v = q[key];
  return v === "1" || v === "true" || v === "True" || v === "yes";
}

function getNameFromFragmentOrHost(u, fb) {
  if (u.hash && u.hash.length > 1) {
    try {
      return sanitizeString(decodeURIComponent(u.hash.slice(1)), fb);
    } catch {
      return sanitizeString(u.hash.slice(1), fb);
    }
  }
  return sanitizeString(u.hostname || fb, fb);
}

function normalizeHostname(h) {
  if (!h) return h;
  const s = String(h);
  if (s.startsWith("[") && s.endsWith("]")) {
    return s.slice(1, -1);
  }
  return s;
}

export function parseVless(u) {
  const q = parsedQs(u);
  const name = getNameFromFragmentOrHost(u, "vless");
  const host = normalizeHostname(u.hostname);
  const p = {
    name: sanitizeString(name, host || "vless"),
    type: "vless",
    server: host,
    port: u.port ? Number(u.port) : null,
    uuid: sanitizeString(u.username || "", ""),
    network: sanitizeString(q.type || q.net || "tcp", "tcp"),
    servername: q.sni ? sanitizeString(q.sni) : undefined,
    udp: true,
  };
  const sec = q.security || "";
  if (sec === "reality") {
    p.tls = true;
    p["reality-opts"] = {
      "public-key": q.pbk || "",
      "short-id": q.sid || "",
      spiderx: q.spx || "",
    };
  } else if (sec === "tls") {
    p.tls = true;
  }
  if (q.flow) p.flow = q.flow;
  if (q.sni) p.servername = q.sni;
  if (q.alpn)
    p.alpn = q.alpn
      .split(",")
      .map((x) => x.trim())
      .filter(Boolean);
  if (q.authority) p.authority = decodeURIComponent(q.authority || "");
  if (q.fp) p["client-fingerprint"] = q.fp;
  let enc = q.encryption || "";
  if (enc) {
    enc = stripControlChars(enc).trim();
    const eqIdx = enc.indexOf("=");
    if (eqIdx !== -1) enc = enc.slice(0, eqIdx);
    if (!enc) enc = "none";
    p.encryption = enc;
  } else {
    p.encryption = "none";
  }

  const net = (q.type || q.net || "tcp").toLowerCase();
  if (net === "ws") {
    const ws = { path: q.path ? decodeURIComponent(q.path) : "" };
    if (q.host) ws.headers = { Host: q.host };
    p["ws-opts"] = ws;
  } else if (net === "grpc") {
    p.network = "grpc";
    const grpc = {};
    const svc =
      q.serviceName ||
      q.servicename ||
      q["service-name"] ||
      q["service_name"] ||
      q.service;
    if (svc) grpc["grpc-service-name"] = decodeURIComponent(svc);
    if (q.mode) grpc.mode = q.mode;
    if (Object.keys(grpc).length) p["grpc-opts"] = grpc;
  } else if (net === "h2") {
    p.network = "h2";
    const h2 = {};
    if (q.path) h2.path = decodeURIComponent(q.path);
    if (q.host) {
      const hosts = decodeURIComponent(q.host)
        .split(",")
        .map((x) => x.trim())
        .filter(Boolean);
      h2.host = hosts.length === 1 ? hosts[0] : hosts;
    }
    if (Object.keys(h2).length) p["h2-opts"] = h2;
  } else if (net === "http" || net === "httpupgrade" || net === "xhttp") {
    p.network = net === "httpupgrade" ? "http" : net;
    const http = { path: q.path ? decodeURIComponent(q.path) : "" };
    if (q.host) http.headers = { Host: q.host };
    p["http-opts"] = http;
  } else if (net === "kcp") {
    p.network = "kcp";
    const kcp = {};
    if (q.seed) kcp.seed = decodeURIComponent(q.seed);
    if (q.headerType) kcp.header = { type: q.headerType };
    if (Object.keys(kcp).length) p["kcp-opts"] = kcp;
  } else if (net === "tcp") {
    if (q.headerType) p["tcp-opts"] = { header: { type: q.headerType } };
    if (q.path) p.path = decodeURIComponent(q.path);
    if (q.host) p.host = q.host;
  }
  return p;
}

export function parseVmess(u) {
  let rest = (u.host || "") + (u.pathname || "");
  if (rest.endsWith("/")) rest = rest.slice(0, -1);
  if (rest.startsWith("/")) rest = rest.slice(1);
  if (!rest.includes("@") && !u.search) {
    const decoded = b64decodeAuto(rest);
    let cfg;
    try {
      cfg = JSON.parse(decoded);
    } catch {
      throw new Error("Invalid vmess base64 JSON");
    }
    const obj = {
      name: sanitizeString(cfg.ps || cfg.add || "vmess", cfg.add || "vmess"),
      type: "vmess",
      server: normalizeHostname(cfg.add),
      port: Number(cfg.port),
      uuid: sanitizeString(cfg.id, ""),
      cipher: sanitizeString(cfg.cipher || cfg.scy || "auto", "auto"),
      alterId: cfg.aid != null ? Number(cfg.aid) : 0,
      network: sanitizeString(cfg.net || cfg.network || "tcp", "tcp"),
      tls: cfg.tls === "tls" || cfg.security === "tls",
      udp: true,
    };
    if (cfg.host) obj.host = cfg.host;
    if (cfg.path) obj.path = cfg.path;
    if (cfg.sni) obj.servername = cfg.sni;
    if (cfg.alpn)
      obj.alpn = Array.isArray(cfg.alpn)
        ? cfg.alpn
        : [cfg.alpn].filter(Boolean);
    if (obj.network === "ws") {
      const ws = { path: cfg.path || "" };
      if (cfg.host) ws.headers = { Host: cfg.host };
      obj["ws-opts"] = ws;
    } else if (obj.network === "grpc") {
      const grpc = {};
      if (cfg.path) grpc["grpc-service-name"] = cfg.path;
      if (cfg.mode) grpc.mode = cfg.mode;
      if (Object.keys(grpc).length) obj["grpc-opts"] = grpc;
    } else if (obj.network === "h2") {
      const h2 = {};
      if (cfg.path) h2.path = cfg.path;
      if (cfg.host)
        h2.host = cfg.host.includes(",")
          ? cfg.host
              .split(",")
              .map((x) => x.trim())
              .filter(Boolean)
          : cfg.host;
      obj["h2-opts"] = h2;
    } else if (obj.network === "http") {
      const http = {};
      if (cfg.path) http.path = cfg.path;
      if (cfg.host) http.headers = { Host: cfg.host };
      if (Object.keys(http).length) obj["http-opts"] = http;
    }
    return obj;
  }
  const q = parsedQs(u);
  const name = getNameFromFragmentOrHost(u, "vmess");
  const host = normalizeHostname(u.hostname);
  const p = {
    name: sanitizeString(name, host || "vmess"),
    type: "vmess",
    server: host,
    port: u.port ? Number(u.port) : null,
    uuid: sanitizeString(u.username || "", ""),
    cipher: sanitizeString(q.cipher || "auto", "auto"),
    alterId: q.aid != null ? Number(q.aid) : 0,
    network: sanitizeString(q.type || q.net || "tcp", "tcp"),
    servername: q.sni ? sanitizeString(q.sni) : undefined,
    udp: true,
  };
  if (q.security === "tls" || q.tls === "tls") p.tls = true;
  if (q.sni) p.servername = q.sni;
  if (q.alpn)
    p.alpn = q.alpn
      .split(",")
      .map((x) => x.trim())
      .filter(Boolean);
  const net = (q.type || q.net || "tcp").toLowerCase();
  if (net === "ws") {
    const ws = { path: q.path ? decodeURIComponent(q.path) : "" };
    if (q.host) ws.headers = { Host: q.host };
    p["ws-opts"] = ws;
  } else if (net === "grpc") {
    p.network = "grpc";
    const grpc = {};
    const svc =
      q.serviceName ||
      q.servicename ||
      q["service-name"] ||
      q["service_name"] ||
      q.service;
    if (svc) grpc["grpc-service-name"] = decodeURIComponent(svc);
    if (q.mode) grpc.mode = q.mode;
    if (Object.keys(grpc).length) p["grpc-opts"] = grpc;
  } else if (net === "h2") {
    p.network = "h2";
    const h2 = {};
    if (q.path) h2.path = decodeURIComponent(q.path);
    if (q.host) {
      const hosts = decodeURIComponent(q.host)
        .split(",")
        .map((x) => x.trim())
        .filter(Boolean);
      h2.host = hosts.length === 1 ? hosts[0] : hosts;
    }
    if (Object.keys(h2).length) p["h2-opts"] = h2;
  } else if (net === "http") {
    p.network = "http";
    const http = { path: q.path ? decodeURIComponent(q.path) : "" };
    if (q.host) http.headers = { Host: q.host };
    p["http-opts"] = http;
  }
  return p;
}

export function parseSs(u) {
  const nameFrag = getNameFromFragmentOrHost(u, "ss");

  let method = null;
  let password = null;
  let host = null;
  let port = null;

  const hostAndPath = (u.host || "") + (u.pathname || "");
  const rest = hostAndPath.replace(/^\/+/, "");

  if (rest && !rest.includes("@") && /^[A-Za-z0-9+/_-]+=*$/.test(rest)) {
    const decoded = b64decodeAuto(rest);
    if (decoded) {
      if (decoded.includes("@")) {
        const [userinfo, hostinfo] = decoded.split("@", 2);
        if (userinfo.includes(":")) {
          [method, password] = userinfo.split(":", 2);
        } else {
          method = userinfo;
          password = "";
        }
        if (hostinfo.includes(":")) {
          [host, port] = hostinfo.split(":", 2);
        } else {
          host = hostinfo;
        }
      } else if (decoded.includes(":")) {
        [method, password] = decoded.split(":", 2);
      } else {
        method = decoded;
        password = "";
      }
    }
  }

  if (!method && u.username) {
    let user = decodeURIComponent(u.username || "");
    if (/^[A-Za-z0-9+/_-]+=*$/.test(user)) {
      const decodedUser = b64decodeAuto(user);
      if (decodedUser && decodedUser.includes(":")) {
        user = decodedUser;
      }
    }
    if (user.includes(":")) {
      [method, password] = user.split(":", 2);
    } else if (user) {
      method = user;
      if (password == null) password = "";
    }
  }

  if (!host && u.hostname) host = normalizeHostname(u.hostname);
  if (port == null && u.port) port = u.port;

  method = stripControlChars(method || "");
  if (!method) {
    method = "aes-256-gcm";
  }

  if (password == null) password = "";
  password = stripControlChars(password);

  const q = parsedQs(u);

  if (q.encryption) {
    let enc = stripControlChars(q.encryption).trim();
    const eqIdx = enc.indexOf("=");
    if (eqIdx !== -1) enc = enc.slice(0, eqIdx);
    if (!enc) enc = "none";
    if (
      (!password || password === "") &&
      method &&
      /^[0-9a-fA-F-]{16,}$/.test(method) &&
      !/gcm|chacha/i.test(method)
    ) {
      password = method;
    }

    method = enc;
  }

  const safeName = sanitizeString(
    nameFrag !== "ss" ? nameFrag : host || "ss",
    host || "ss"
  );
  const hostStr = String(host || "").trim();
  const badHost =
    !hostStr ||
    /["',\s]/.test(hostStr) ||
    hostStr.includes("{") ||
    hostStr.includes("}") ||
    hostStr.includes("\\") ||
    hostStr.length > 255;

  if (badHost) {
    throw new Error("Invalid SS host (garbage)");
  }
  const portNum = Number(port);
  if (!Number.isFinite(portNum) || portNum < 1 || portNum > 65535) {
    throw new Error("Invalid SS port (garbage)");
  }
  const allowedCiphers = new Set([
    "aes-128-gcm",
    "aes-192-gcm",
    "aes-256-gcm",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "chacha20-ietf-poly1305",
    "chacha20-poly1305",
    "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "none",
  ]);

  const methodStr = String(method || "")
    .trim()
    .toLowerCase();
  if (!allowedCiphers.has(methodStr)) {
    throw new Error("Invalid SS cipher (garbage)");
  }
  const pwdStr = String(password || "").trim();
  if (!pwdStr || /[{},"]/.test(pwdStr)) {
    throw new Error("Invalid SS password (garbage)");
  }
  host = hostStr;
  port = portNum;
  method = methodStr;
  password = pwdStr;

  const p = {
    name: safeName,
    type: "ss",
    server: host,
    port: port != null && /^\d+$/.test(String(port)) ? Number(port) : port,
    cipher: sanitizeString(method, "aes-256-gcm"),
    password: sanitizeString(password, ""),
    udp: true,
  };

  if (q.plugin) {
    p.plugin = q.plugin;
    const parts = q.plugin.split(";");
    if (parts.length > 1) {
      const popt = {};
      for (const x of parts.slice(1)) {
        if (!x) continue;
        if (x.includes("=")) {
          const [k, v] = x.split("=", 2);
          popt[k] = v;
        } else {
          popt[x] = "true";
        }
      }
      if (Object.keys(popt).length) p["plugin-opts"] = popt;
    }
  }

  return p;
}

export function parseTrojan(u) {
  const q = parsedQs(u);
  const name = getNameFromFragmentOrHost(u, "trojan");
  const host = normalizeHostname(u.hostname);
  const p = {
    name: sanitizeString(name, host || "trojan"),
    type: "trojan",
    server: host,
    port: u.port ? Number(u.port) : null,
    password: sanitizeString(u.username || "", ""),
    servername: q.sni ? sanitizeString(q.sni) : undefined,
    udp: true,
  };
  if (q.security === "tls" || q.sni || q.security === "reality") p.tls = true;
  if (q.sni) p.servername = q.sni;
  const insecureFlag = readBool(q, "insecure");
  const allowInsecureFlag = readBool(q, "allowInsecure");
  if (insecureFlag !== undefined) p.insecure = insecureFlag;
  if (allowInsecureFlag !== undefined)
    p["skip-cert-verify"] = allowInsecureFlag;
  else if (insecureFlag !== undefined) p["skip-cert-verify"] = insecureFlag;
  if (q.fp) p["client-fingerprint"] = q.fp;
  if (q.alpn)
    p.alpn = q.alpn
      .split(",")
      .map((x) => x.trim())
      .filter(Boolean);
  if (q.security === "reality") {
    p["reality-opts"] = {
      "public-key": q.pbk || "",
      "short-id": q.sid || "",
      spiderx: q.spx || "",
    };
  }
  const net = (q.type || q.net || "tcp").toLowerCase();
  if (net === "ws") {
    p.network = "ws";
    const ws = { path: q.path ? decodeURIComponent(q.path) : "" };
    if (q.host) ws.headers = { Host: q.host };
    p["ws-opts"] = ws;
  } else if (net === "grpc") {
    p.network = "grpc";
    const grpc = {};
    const svc =
      q.serviceName ||
      q.servicename ||
      q["service-name"] ||
      q["service_name"] ||
      q.service;
    if (svc) grpc["grpc-service-name"] = decodeURIComponent(svc);
    if (q.mode) grpc.mode = q.mode;
    if (Object.keys(grpc).length) p["grpc-opts"] = grpc;
  }
  return p;
}

export function parseHy(u, hy2 = false) {
  const q = parsedQs(u);
  const name = getNameFromFragmentOrHost(u, hy2 ? "hysteria2" : "hysteria");
  const host = normalizeHostname(u.hostname);

  const p = {
    name: sanitizeString(name, host || (hy2 ? "hy2" : "hy")),
    type: hy2 ? "hysteria2" : "hysteria",
    server: host,
    port: u.port ? Number(u.port) : null,
    udp: true,
  };

  if (hy2) {
    p.password = sanitizeString(stripControlChars(u.username || ""), "");
    const obfsTypeRaw = q.obfs || q["obfs-type"] || q.obfsType || "";
    const obfsPassRaw =
      q["obfs-password"] || q.obfsPassword || q["obfsPassword"] || "";

    const obfsType = sanitizeString(obfsTypeRaw, "").toLowerCase();
    const obfsPass = sanitizeString(obfsPassRaw, "");

    if (obfsType && obfsType !== "plain") {
      if (obfsPass) {
        p.obfs = "salamander";
        p["obfs-password"] = obfsPass;
      }
    }
    const hasObfsTypeExplicit =
      "obfs" in q || "obfs-type" in q || "obfsType" in q;
    if (!hasObfsTypeExplicit) {
      delete p.obfs;
      delete p["obfs-password"];
    }
    if (p.obfs && !obfsPass) {
      delete p.obfs;
      delete p["obfs-password"];
    }
  } else {
    p.auth = sanitizeString(q.auth || "", "");
    if ("insecure" in q)
      p.insecure =
        q.insecure === "1" || q.insecure === "true" || q.insecure === "True";
    if ("upmbps" in q)
      p["up-mbps"] = /^\d+$/.test(q.upmbps) ? Number(q.upmbps) : q.upmbps;
    if ("downmbps" in q)
      p["down-mbps"] = /^\d+$/.test(q.downmbps)
        ? Number(q.downmbps)
        : q.downmbps;
    const obfsTypeRaw = q.obfs || q["obfs-type"] || q.obfsType || "";
    const obfsPassRaw =
      q["obfs-password"] || q.obfsPassword || q["obfsPassword"] || "";

    const obfsType = sanitizeString(obfsTypeRaw, "").toLowerCase();
    const obfsPass = sanitizeString(obfsPassRaw, "");

    if (obfsType && obfsType !== "plain") {
      if (obfsPass) {
        p.obfs = obfsType;
        p["obfs-password"] = obfsPass;
      }
    }
  }

  if (q.alpn)
    p.alpn = q.alpn
      .split(",")
      .map((x) => sanitizeString(x.trim(), ""))
      .filter(Boolean);

  if (q.sni) p.servername = sanitizeString(q.sni, "");
  p.name = sanitizeString(p.name, p.server || "proxy");
  if (p.password) p.password = sanitizeString(p.password, "");
  if (p.auth) p.auth = sanitizeString(p.auth, "");
  if (p.servername) p.servername = sanitizeString(p.servername, "");

  return p;
}

export function parseTuic(u) {
  const q = parsedQs(u);
  const name = getNameFromFragmentOrHost(u, "tuic");
  let uuid = null,
    passwd = null;

  if (u.username && u.username.includes(":")) {
    [uuid, passwd] = u.username.split(":", 2);
  } else {
    uuid = u.username || "";
  }

  uuid = stripControlChars(uuid || "");
  if (passwd == null) passwd = "";
  passwd = stripControlChars(passwd);
  const host = normalizeHostname(u.hostname);
  const p = {
    name,
    type: "tuic",
    server: u.hostname,
    port: u.port ? Number(u.port) : null,
    uuid,
    password: passwd,
    udp: true,
  };
  p.name = sanitizeString(p.name, p.server || "proxy");
  if (p.password) p.password = sanitizeString(p.password, "");
  if (p.uuid) p.uuid = sanitizeString(p.uuid, "");
  if (p.cipher) p.cipher = sanitizeString(p.cipher, "");
  if (p.servername) p.servername = sanitizeString(p.servername, "");
  if (p.host) p.host = sanitizeString(p.host, "");
  if (p.path) p.path = sanitizeString(p.path, "");
  if (q.token) p.token = q.token;
  if (q.sni) p.sni = q.sni;
  if (q.alpn) p.alpn = q.alpn.split(",").filter(Boolean);
  if (q.congestion_control) p["congestion-controller"] = q.congestion_control;
  else if (q["congestion-controller"])
    p["congestion-controller"] = q["congestion-controller"];
  if (q.udp_relay_mode) p["udp-relay-mode"] = q.udp_relay_mode;
  if (q["disable-sni"])
    p["disable-sni"] = q["disable-sni"] === "true" || q["disable-sni"] === "1";
  return p;
}

function decodeBase64Url(str) {
  try {
    return b64decodeAuto(str.trim());
  } catch {
    return "";
  }
}

export function parseSsr(url) {
  const raw = url.replace(/^ssr:\/\//i, "");
  const decoded = decodeBase64Url(raw);
  if (!decoded || !decoded.includes(":")) throw new Error("Invalid SSR link");

  const [serverRaw, portRaw, protocolRaw, methodRaw, obfsRaw, tail] =
    decoded.split(":", 6);
  if (!tail) throw new Error("Invalid SSR tail");

  const [pwdB64, paramsRaw = ""] = tail.split("/?", 2);

  const server = normalizeHostname(sanitizeString(serverRaw, ""));
  const port = Number(portRaw);

  const password = sanitizeString(decodeBase64Url(pwdB64), "");
  const protocol = sanitizeString(protocolRaw, "origin");
  let obfs = sanitizeString(obfsRaw, "plain");
  const cipher = sanitizeString(methodRaw, "aes-256-cfb");

  const params = new URLSearchParams(paramsRaw);
  let obfsParam = sanitizeString(
    decodeBase64Url(params.get("obfsparam") || ""),
    ""
  );
  const protoParam = sanitizeString(
    decodeBase64Url(params.get("protoparam") || ""),
    ""
  );
  const remarks = sanitizeString(
    decodeBase64Url(params.get("remarks") || ""),
    ""
  );

  const obfsLower = String(obfs || "").toLowerCase();
  const hasObfsParam = obfsParam && String(obfsParam).trim().length > 0;
  if (!hasObfsParam && obfsLower !== "plain") {
    obfs = "plain";
    obfsParam = "";
  }

  return {
    name: sanitizeString(remarks || server, server || "ssr"),
    type: "ssr",
    server,
    port: Number.isFinite(port) ? port : portRaw,
    cipher,
    password,
    protocol,
    obfs,
    "protocol-param": protoParam || undefined,
    "obfs-param": obfsParam || undefined,
    udp: true,
  };
}

export function parseOne(url) {
  const raw = String(url || "").trim();
  if (!raw) throw new Error("Empty url");

  if (/^ssr:\/\//i.test(raw)) {
    return parseSsr(raw);
  }

  let u;
  try {
    u = new URL(raw);
  } catch (e) {
    throw new Error("Invalid URL: " + raw.slice(0, 120));
  }

  const s = (u.protocol || "").replace(":", "").toLowerCase();

  switch (s) {
    case "vless":
      return parseVless(u);

    case "vmess":
      return parseVmess(u);

    case "ss":
      return parseSs(u);

    case "trojan":
      return parseTrojan(u);

    case "hysteria":
    case "hy":
      return parseHy(u, false);

    case "hy2":
      return parseHy(u, true);

    case "tuic":
      return parseTuic(u);

    default:
      throw new Error("Unsupported scheme: " + s);
  }
}

export function parseMany(raw, { collectErrors = false } = {}) {
  const urls = normalizeInputLines(raw || "");
  const proxies = [];
  const errors = [];

  for (const u of urls) {
    try {
      const p = parseOne(u);
      if (p) proxies.push(p);
    } catch (err) {
      if (collectErrors) {
        errors.push({
          u,
          err: err?.message || String(err) || "parse error",
        });
      }
    }
  }

  return { urls, proxies, errors };
}
