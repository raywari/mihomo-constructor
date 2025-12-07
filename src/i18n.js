import { isoToFlag } from "./utils.js";
import { setStatus } from "./ui-core.js";
import { renderGroups } from "./groups.js";
import { renderMatchSelect, renderRulesTargets } from "./rules.js";
import { renderSubs } from "./subs.js";
import { state } from "./state.js";
import en from "./i18n/en.js";
import zh from "./i18n/zh.js";
import fa from "./i18n/fa.js";
import ru from "./i18n/ru.js";
const supportedLanguages = [en, zh, fa, ru];

const translations = {};
const languageOptions = [];

supportedLanguages.forEach((lang) => {
  translations[lang.meta.value] = lang.dict;
  languageOptions.push(lang.meta);
});
export let currentLang = localStorage.getItem("lang") || "en";
if (!translations[currentLang]) currentLang = "en";

export function t(key, params = {}) {
  const dict = translations[currentLang] || translations.en || {};
  const template = dict[key] || translations.en?.[key] || key;
  return template.replace(/\{(\w+)\}/g, (_, k) => params[k] ?? "");
}

const twemojiOptions = {
  base: "https://raw.githubusercontent.com/twitter/twemoji/v14.0.2/assets/",
  folder: "svg",
  ext: ".svg",
  className: "emoji",
};

export function applyTwemoji(scope) {
  if (!scope || typeof twemoji === "undefined") return;
  try {
    twemoji.parse(scope, twemojiOptions);
  } catch (e) {
    console.warn("twemoji.parse failed", e);
  }
}

function applyTwemojiToLang() {
  const scope = document.querySelector(".lang-control");
  if (!scope) return;
  applyTwemoji(scope);
}

export function syncDynamicTexts() {
  const output = document.getElementById("output");
  if (!output) return;

  const isEmpty = !output.textContent.trim();
  const isPlaceholder = output.getAttribute("data-placeholder") === "true";

  if (isEmpty || isPlaceholder) {
    output.textContent = t("outputPlaceholder");
    output.dataset.placeholder = "true";
  }

  if (!isEmpty && !isPlaceholder) {
    output.removeAttribute("data-placeholder");
  }
  if (!state?.geosite?.length) {
    const el = document.getElementById("geositeStatus");
    if (el) el.textContent = t("notLoaded");
  }
  if (!state?.geoip?.length) {
    const el = document.getElementById("geoipStatus");
    if (el) el.textContent = t("notLoaded");
  }

  if (typeof setStatus.lastKind !== "undefined") {
    setStatus(setStatus.lastKind, setStatus.lastText || "");
  } else {
    const current = document.getElementById("statusText")?.textContent || "";
    setStatus(null, current);
  }
}

export function applyTranslations() {
  document.documentElement.setAttribute("data-lang", currentLang);

  document.documentElement.dir = currentLang === "fa" ? "rtl" : "ltr";
  document.body.classList.toggle("rtl", currentLang === "fa");

  document.querySelectorAll("[data-i18n]").forEach((el) => {
    const key = el.dataset.i18n;
    const attr = el.dataset.i18nAttr;
    const value = t(key);

    if (attr) {
      el.setAttribute(attr, value);
    } else {
      el.textContent = value;
    }
    if (["zh", "fa", "ru"].includes(currentLang)) {
      el.setAttribute("lang", currentLang);
    } else {
      el.setAttribute("lang", "en");
    }
  });

  document.querySelectorAll("[data-i18n-aria]").forEach((el) => {
    const key = el.dataset.i18nAria;
    el.setAttribute("aria-label", t(key));
  });
  syncDynamicTexts();
  applyTwemoji(document.body);
}

export function setupLanguageSelector() {
  const btn = document.getElementById("langButton");
  const menu = document.getElementById("langMenu");
  if (!btn || !menu) return;

  const renderButton = () => {
    const opt =
      languageOptions.find((o) => o.value === currentLang) ||
      languageOptions[0];
    const flag = opt?.flag || isoToFlag(opt?.value?.slice(0, 2)) || "🌐";

    const flagEl =
      btn.querySelector(".lang-current-flag") ||
      btn.querySelector(".lang-flag");
    if (flagEl) flagEl.textContent = flag;
    btn.setAttribute(
      "aria-label",
      `${t("languageLabel")}: ${opt?.label || opt?.value || ""}`.trim()
    );
    applyTwemojiToLang();
  };

  const renderMenu = () => {
    menu.innerHTML = languageOptions
      .map(
        (opt) => `
          <button class="lang-option" role="option" data-value="${opt.value}">
            <span class="lang-flag" aria-hidden="true">${
              opt.flag || isoToFlag(opt.value.slice(0, 2)) || "🌐"
            }</span>
            <span class="lang-name">${opt.label}</span>
          </button>
        `
      )
      .join("");
    applyTwemojiToLang();
  };

  const closeMenu = () => {
    menu.classList.remove("open");
    btn.setAttribute("aria-expanded", "false");
  };

  const openMenu = () => {
    menu.classList.add("open");
    btn.setAttribute("aria-expanded", "true");
  };

  btn.addEventListener("click", () => {
    if (menu.classList.contains("open")) closeMenu();
    else openMenu();
  });

  menu.addEventListener("click", (e) => {
    const optBtn = e.target.closest(".lang-option");
    if (!optBtn) return;
    const lang = optBtn.dataset.value;
    if (!translations[lang]) return;

    currentLang = lang;
    localStorage.setItem("lang", lang);
    applyTranslations();
    renderGroups();
    renderMatchSelect();
    renderRulesTargets();
    renderSubs();

    setStatus(setStatus.lastKind || null, setStatus.lastText || "");
    renderButton();
    closeMenu();
  });

  document.addEventListener("click", (e) => {
    if (e.target.closest(".lang-control")) return;
    closeMenu();
  });

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeMenu();
  });

  renderMenu();
  renderButton();
}
