[🌐 Open Mihomo Constructor](https://raywari.github.io/mihomo-constructor/)

**README languages:**

- **English** — [https://github.com/raywari/mihomo-constructor/blob/main/README.md](https://github.com/raywari/mihomo-constructor/blob/main/README.md)
- **Русский** — [https://github.com/raywari/mihomo-constructor/blob/main/README_RU.md](https://github.com/raywari/mihomo-constructor/blob/main/README_RU.md)
- **中文 (Chinese)** — [https://github.com/raywari/mihomo-constructor/blob/main/README_ZH.md](https://github.com/raywari/mihomo-constructor/blob/main/README_ZH.md)
- **فارسی (Persian / Iranian)** — [https://github.com/raywari/mihomo-constructor/blob/main/README_FA.md](https://github.com/raywari/mihomo-constructor/blob/main/README_FA.md)

# Mihomo Constructor

A frontend-only config builder for Clash/Mihomo that focuses on a visual UI and clean YAML output, so you don't have to copy and paste fragments by hand.

Ideal if you have messy proxy links and subscriptions from different providers and want a single, consistent Clash/Mihomo config without editing YAML manually.

> ⚠️ The project is not an official product of the Clash/Mihomo teams and is not affiliated with MetaCubeX or other client authors. It simply works with their config formats and rule sets.

## What the tool does

**Mihomo Constructor** builds a complete `config.yaml` for Clash/Mihomo by combining:

- proxy links in popular formats (`vless://`, `vmess://`, `ss://`, `trojan://`, `ssr://`, `hysteria://`, `hy://`, `hy2://`, `hysteria2://`, `tuic://`),
- subscriptions (proxy-providers) with selectable fetch mode,
- proxy groups with icons, manual entries, and auto-generated proxies,
- rules built from GEOSITE / GEOIP lists, rule-providers, or manual rules (DOMAIN/IP/PROCESS),
- optional raw YAML blocks for subscriptions, groups, and rules when you need full control.

The app is a static HTML page with ES module scripts and no backend: open it, paste your inputs, adjust settings, and copy or download the ready YAML.

---

## Feature overview

### Parsing inputs

- The parser normalizes base64 or plain text input and extracts multiple links in one paste.
- Supported schemes include VLESS, VMess, Shadowsocks, Trojan, ShadowsocksR, Hysteria (v1/v2), `hy://`, and TUIC, so heterogeneous lists work out of the box.

### Subscriptions (proxy-providers)

- Add multiple subscription URLs at once; each becomes a provider automatically.
- Choose how to fetch each subscription (DIRECT or via Proxy) and toggle an advanced YAML area to replace provider definitions manually.

### Proxy groups

- Create groups from the UI with type selection (`select`, `url-test`, `fallback`, `load-balance`), icons, and manual proxy lists.
- All parsed proxies are listed with checkboxes for quick assignment, and deleting or renaming groups updates dependent rules.
- An auto-generated **`auto`** group aggregates every detected proxy and subscription to keep MATCH rules working even with empty manual groups.

### Rules and rule order

- Load GEOSITE/GEOIP categories from bundled text files and search within them; add rule-providers or manual DOMAIN / IP / PROCESS rules.
- Auto-group rules with a single button, pick a default MATCH target (DIRECT/REJECT/group), and reorder priorities in the **Rule order** list.
- Advanced YAML blocks are available for rule-providers and rules when you need to paste existing configurations.

### Output and status

- Build merges `proxies + groups + providers + rules` into one YAML snippet, shows a status summary, and lets you copy to clipboard or download `config.yaml` immediately.

### Localization

- The interface ships with English, Chinese, Persian, and Russian dictionaries, and language preference is stored locally.
- Emojis are rendered via Twemoji for consistent icons across platforms.

---

## How to use the UI

1. **Paste links** into the “Input links” box or press **Demo** to insert sample nodes, then click **Build config**.
2. **Add subscriptions** in the **Subscriptions (proxy-providers)** block, set fetch mode, and open **Advanced Subscriptions (YAML)** if you want to supply raw provider YAML.
3. **Configure proxy groups** via **➕ Add group**; pick the type, icon, manual proxies, and which parsed proxies should join via checkboxes. Advanced mode accepts direct YAML.
4. **Load rule data** with **📄 Load** (GEOSITE) and **🌍 Load** (GEOIP), search categories, add rule-providers, or enter manual rules. **⚙️ Auto rules group** can scaffold defaults, and the **Rule order** box lets you tweak priorities.
5. **Set default MATCH behavior** (DIRECT/REJECT/a group) and fine-tune advanced rule YAML if needed.
6. **Build and export**: the **Ready YAML** pane shows the merged config, with buttons to **Copy** or **Download config.yaml**. Status pills report counts or parsing errors.

---

## Repository layout

- `index.html` — single-page UI wired with vanilla JS modules; includes all controls for input, subscriptions, groups, rules, status, and YAML output.
- `styles/` — fonts and styles for the interface.
- `src/main.js` — entry point that parses inputs, rebuilds state, and generates YAML output.
- `src/parser.js` — robust proxy-link parser handling multiple schemes and base64 inputs.
- `src/groups.js` — logic and UI bindings for managing proxy groups.
- `src/subs.js` — logic and UI bindings for subscriptions (proxy-providers).
- `src/rules.js` — rule management, rule-providers, rule order, and MATCH behavior.
- `src/geo.js` — loading and searching GEOSITE/GEOIP categories from bundled files.
- `src/yaml-gen.js` — assembles the final YAML from application state.
- `src/i18n.js` & `src/i18n/` — language selector, translation dictionaries, and Twemoji integration.
- `geo/` — generated `geosite.txt` / `geoip.txt` lists bundled for offline GEOSITE/GEOIP browsing.
- `geo-update.py` — helper script to refresh GEO lists from `meta-rules-dat`.

---

## Running locally

The app is static: clone the repo and serve the folder with any static server so ES modules load correctly, for example:

```bash
python -m http.server 8000
```

Then open `http://localhost:8000/` in your browser. No build step or backend services are required.

---

## Updating GEO files

`geo/geosite.txt` and `geo/geoip.txt` come from [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat) and are regenerated via `geo-update.py`:

```bash
python geo-update.py
```

The script clones the upstream repository, extracts category names (with extensions stripped), moves the text files into `geo/`, and removes the temporary clone.

---

## Limitations

- **No backend:** the app runs entirely in the browser; subscriptions are fetched directly from the client.
- **Browser-only:** there is no CLI wrapper; this tool is focused on an interactive web UI.
- **Client compatibility:** output is optimized for Mihomo/Clash.Meta-style configs. Some forks or heavily customized clients may still require manual tweaks.
- **No built-in node testing:** the app does not ping or benchmark proxies; it only generates config YAML.

---

## Localization and contributions

- Add or adjust translations in `src/i18n/*.js` and register new locales in `src/i18n.js`.
- Feel free to open issues or PRs for parser tweaks, new presets, or UI improvements.
- Please keep README translations in their respective files; this English version is the canonical source.

---

## Credits

Mihomo Constructor is an independent helper built on top of the Clash/Mihomo formats and rule sets. All mentioned product names belong to their authors.
