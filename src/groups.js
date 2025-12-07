import { state } from "./state.js";
import { t } from "./i18n.js";
import { fillActionSelect } from "./ui-core.js";
import {
  renderMatchSelect,
  rebuildRuleOrderFromState,
  renderRuleProvidersPolicySelect,
  renderRulesTargets,
} from "./rules.js";
import { renderSubs } from "./subs.js";

const groupsContainer = document.getElementById("groupsContainer");

export function renderGroups() {
  if (!groupsContainer) return;
  groupsContainer.innerHTML = "";
  const proxyNames = state.proxies.map((p) => p.name);

  state.groups.forEach((g, idx) => {
    const card = document.createElement("div");
    card.className = "group-card";

    card.innerHTML = `
      <div class="row">
        <input type="text" placeholder="${t("groupNamePlaceholder")}" value="${
      g.name
    }">
        <select>
          ${["select", "url-test", "fallback", "load-balance"]
            .map(
              (t) => `<option ${g.type === t ? "selected" : ""}>${t}</option>`
            )
            .join("")}
        </select>
      </div>
      <div class="two-col">
        <div class="row">
          <label class="hint">${t("iconLabel")}</label>
          <input type="text" placeholder="https://..." value="${g.icon || ""}">
        </div>
        <div class="row">
          <label class="hint">${t("manualLabel")}</label>
          <input type="text" placeholder='${t("manualPlaceholder")}' value="${(
      g.manual || []
    ).join(", ")}">
        </div>
      </div>
      <div class="hint">${t("groupProxiesHint")}</div>
      <div class="listbox" style="max-height:180px">
        ${proxyNames
          .map((n) => {
            const checked = g.proxies.includes(n) ? "checked" : "";
            return `<div class="item"><label><input type="checkbox" data-proxy="${n}" ${checked}> <span>${n}</span></label></div>`;
          })
          .join("")}
      </div>
      <div class="row" style="justify-content:space-between">
        <div class="hint">${t("updateProxyHint")}</div>
        <button class="danger" data-del>\u{1F5D1}\uFE0F ${t(
          "deleteGroup"
        )}</button>
      </div>
    `;

    const [nameInp, typeSel, iconInp, manualInp] =
      card.querySelectorAll("input, select");
    nameInp.addEventListener("change", (e) => {
      g.name = e.target.value.trim() || "GROUP";
      renderMatchSelect();
      rebuildRuleOrderFromState();
      renderRuleProvidersPolicySelect();
      renderSubs();
    });
    typeSel.addEventListener("change", (e) => {
      g.type = e.target.value;
    });
    iconInp.addEventListener("input", (e) => {
      g.icon = e.target.value.trim();
    });
    manualInp.addEventListener("input", (e) => {
      g.manual = e.target.value
        .split(",")
        .map((x) => x.trim())
        .filter(Boolean);
    });

    card.querySelectorAll("input[type=checkbox]").forEach((cb) => {
      cb.addEventListener("change", () => {
        const n = cb.dataset.proxy;
        if (cb.checked && !g.proxies.includes(n)) g.proxies.push(n);
        if (!cb.checked) g.proxies = g.proxies.filter((x) => x !== n);
      });
    });

    card.querySelector("[data-del]").addEventListener("click", () => {
      state.groups.splice(idx, 1);
      renderGroups();
      renderRulesTargets();
      renderMatchSelect();
    });

    groupsContainer.appendChild(card);
  });

  if (!state.groups.length) {
    const empty = document.createElement("div");
    empty.className = "hint";
    empty.textContent = t("emptyGroups");
    groupsContainer.appendChild(empty);
  }
  renderMatchSelect();
  const manualAction = document.getElementById("manualRuleAction");
  if (manualAction) fillActionSelect(manualAction);
}
