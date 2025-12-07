import { t } from "./i18n.js";
import { state } from "./state.js";

export function setStatus(kind, text) {
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
  const stText = document.getElementById("statusText");
  if (stText) stText.textContent = text;
}

export function fillActionSelect(selectEl, { includeReject = true } = {}) {
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
