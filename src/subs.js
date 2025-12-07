import { state } from "./state.js";
import { t } from "./i18n.js";

let _rebuildCallback = () => {};
export function setSubsRebuildCallback(fn) {
  _rebuildCallback = fn;
}

export function renderSubs() {
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
      _rebuildCallback();
    });
  });

  list.querySelectorAll("[data-sub-proxy-name]").forEach((sel) => {
    sel.addEventListener("change", (e) => {
      const idx = +e.target.dataset.subProxyName;
      state.subs[idx].fetchProxy = e.target.value;
      _rebuildCallback();
    });
  });

  list.querySelectorAll("[data-sub-del]").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      const idx = +e.target.dataset.subDel;
      state.subs.splice(idx, 1);
      renderSubs();
      _rebuildCallback();
    });
  });
}
