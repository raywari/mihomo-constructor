export function debounce(fn, delay = 120) {
  let t;
  return (...args) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...args), delay);
  };
}

export function escapeHtml(str) {
  return String(str).replace(
    /[&<>"']/g,
    (s) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[
        s
      ])
  );
}

export function highlightMatch(text, query) {
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

export function uniq(arr) {
  return [...new Set(arr)];
}

export function isoToFlag(iso) {
  iso = iso.toUpperCase();
  if (!/^[A-Z]{2}$/.test(iso)) return "";
  const A = 0x1f1e6,
    base = "A".codePointAt(0);
  return String.fromCodePoint(
    A + (iso.codePointAt(0) - base),
    A + (iso.codePointAt(1) - base)
  );
}

export function stripSchemeAndPath(s) {
  return s
    .replace(/^\s*https?:\/\//i, "")
    .replace(/^\s*ws?:\/\//i, "")
    .split(/[\/\?#]/)[0]
    .trim();
}
export function yamlQuote(s) {
  if (s == null) return null;
  s = String(s)
    .replace(/[\x00-\x08\x0B-\x0C\x0E-\x1F\x7F]/g, "")
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"');
  return `"${s}"`;
}

export function emitLine(lines, text = "", indent = 0) {
  lines.push(" ".repeat(indent) + text);
}

export function emitKv(lines, key, value, indent = 0, quote = true) {
  if (value == null || (value === "" && key !== "password")) return;

  if (typeof value === "boolean") {
    emitLine(lines, `${key}: ${value ? "true" : "false"}`, indent);
    return;
  }

  let v = value;
  if (quote && typeof v !== "number") v = yamlQuote(v);
  emitLine(lines, `${key}: ${v}`, indent);
}

export function emitBool(lines, key, flag, indent = 0) {
  if (flag == null) return;
  emitLine(lines, `${key}: ${flag ? "true" : "false"}`, indent);
}

export function emitList(lines, key, items, indent = 0) {
  if (!items || !items.length) return;
  emitLine(lines, `${key}:`, indent);
  for (const it of items) emitLine(lines, `- ${yamlQuote(it)}`, indent + 2);
}
