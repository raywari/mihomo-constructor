[🌐 Open Mihomo Constructor](https://raywari.github.io/mihomo-constructor/)

**README languages:**  
- **English (current)**  
- **Русский** — https://github.com/raywari/mihomo-constructor/blob/main/README_RU.md  
- **中文 (Chinese)** — https://github.com/raywari/mihomo-constructor/blob/main/README_ZH.md  
- **فارسی (Persian / Iranian)** — https://github.com/raywari/mihomo-constructor/blob/main/README_FA.md  

# Mihomo Constructor

A convenient config builder for Clash/Mihomo with a focus on a visual UI and YAML generation without manual copy-paste.

> ⚠️ This project is not an official product of the Clash/Mihomo teams.  
> It does not use their trademarks for commercial purposes and does not try to “take over” the name.  
> It’s simply a separate handy tool that works with their config formats.

---

## What it is

**Mihomo Constructor** is a web tool that helps you assemble a Clash/Mihomo config from:

- proxy links (`vless://`, `vmess://`, `ss://`, etc.),
- subscriptions (proxy-providers),
- proxy groups,
- rules (GEOSITE/GEOIP, rule-providers),
- optionally — manual YAML.

The project is fully frontend: open the page, paste your data, tweak settings — and get a ready-to-use `config.yaml`.

---

## Features

- **Link input**
  - Paste a bunch of links at once — the app parses them and adds them into `proxies`.

- **Subscriptions (proxy-providers)**
  - Supports multiple subscription URLs.
  - *Advanced Subscriptions (YAML)* mode — you can replace/extend YAML manually.

- **Proxy Groups**
  - Add groups via the “➕ Add group” button.
  - *Advanced Groups (YAML)* mode — full control through raw text.

- **GEOSITE / GEOIP**
  - Load domain and IP lists.
  - Search by category / country.
  - Auto-generate rules via the “⚙️ Rules auto-group” button.

- **Advanced Rules + Rule-Providers**
  - If standard controls aren’t enough — enable advanced mode and edit a YAML block directly.

- **Final YAML output**
  - Everything is merged into one config: `proxies + groups + providers + rules`.
  - You can instantly:
    - copy to clipboard,
    - download as `config.yaml`.

---

## Used and related projects

I’m oriented around the Clash/Mihomo ecosystem and use open projects, their config formats, and existing rule sets as a base for a more convenient constructor.

Some related projects:

- **Mihomo (core)**  
  Core repo whose config format this project is compatible with:  
  https://github.com/MetaCubeX/mihomo

- **Mihomo Dashboard (metacubexd)**  
  Official dashboard to manage Mihomo via a web UI:  
  https://github.com/MetaCubeX/metacubexd

- **meta-rules-dat**  
  Rule sets (GEOSITE/GEOIP, etc.) in a convenient format for Mihomo:  
  https://github.com/MetaCubeX/meta-rules-dat

- **Clash / Clash.Meta and clients**  
  A navigator for Clash clients and core, with links to different implementations and GUIs:  
  https://github.com/clash-version/clash-download

Mihomo Constructor complements these projects and is not their fork.  
It’s an independent utility built on top of their formats to help you assemble stable Clash/Mihomo configs faster and more comfortably.

- The names **“Clash”**, **“Mihomo”**, and other mentioned products belong to their respective authors.
- Mihomo Constructor is not affiliated with MetaCubeX, Clash authors, or other client teams.
