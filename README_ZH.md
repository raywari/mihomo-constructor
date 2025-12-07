[🌐 打开 Mihomo Constructor](https://raywari.github.io/mihomo-constructor/)

**README 语言：**

- **English** — [https://github.com/raywari/mihomo-constructor/blob/main/README.md](https://github.com/raywari/mihomo-constructor/blob/main/README.md)
- **Русский** — [https://github.com/raywari/mihomo-constructor/blob/main/README_RU.md](https://github.com/raywari/mihomo-constructor/blob/main/README_RU.md)
- **中文 (Chinese)** — [https://github.com/raywari/mihomo-constructor/blob/main/README_ZH.md](https://github.com/raywari/mihomo-constructor/blob/main/README_ZH.md)
- **فارسی (Persian / Iranian)** — [https://github.com/raywari/mihomo-constructor/blob/main/README_FA.md](https://github.com/raywari/mihomo-constructor/blob/main/README_FA.md)

# Mihomo Constructor

一个纯前端的 Clash/Mihomo 配置构建器，主打可视化界面和干净的 YAML 输出，这样你就不用再手动到处复制粘贴配置片段了。

特别适合那种：手里乱七八糟一堆不同提供商的代理链接和订阅，但又想要一个统一、整洁的 Clash/Mihomo 配置，而且不想自己去改 YAML。

> ⚠️ 这个项目不是 Clash/Mihomo 团队的官方产品，也不隶属于 MetaCubeX 或其他客户端作者。它只是支持它们的配置格式和规则集。

## 工具能做什么

**Mihomo Constructor** 会帮你生成一个完整的 Clash/Mihomo `config.yaml`，组合内容包括：

- 常见格式的代理链接（`vless://`、`vmess://`、`ss://`、`trojan://`、`ssr://`、`hysteria://`、`hy://`、`hy2://`、`hysteria2://`、`tuic://`），
- 支持选择拉取方式的订阅（proxy-providers），
- 带图标、手动条目和自动生成代理的代理组，
- 来自 GEOSITE / GEOIP 列表、规则提供者（rule-providers）或手写规则（DOMAIN/IP/PROCESS）的规则，
- 当你需要完全掌控时，可以插入用于订阅、分组和规则的原始 YAML 块。

整个应用就是一张静态 HTML 页面，使用 ES modules，无任何后端：打开页面、贴上你的东西、调好设置，然后复制或下载生成好的 YAML 就行。

---

## 功能概览

### 解析输入

- 解析器会把 base64 或纯文本输入统一处理，并且能从一次粘贴里拆出多条链接。
- 支持的协议包括 VLESS、VMess、Shadowsocks、Trojan、ShadowsocksR、Hysteria（v1/v2）、`hy://` 和 TUIC，所以混合列表基本开箱即用。

### 订阅

- 可以一次性添加多个订阅 URL，每条都会自动变成一个 provider。
- 可以为每个订阅选择获取方式（DIRECT 直连或经由 Proxy），并打开高级 YAML 区域，手动覆盖 provider 的定义。

### 代理组

- 在界面里创建代理组，选择类型（`select`、`url-test`、`fallback`、`load-balance`）、图标，以及手动添加的代理列表。
- 所有解析出来的代理都会以带复选框的列表列出，方便你分配到各个组中；删除或重命名组时，依赖该组的规则也会自动更新。
- 自动生成的 **`auto`** 组会聚合所有发现的代理和订阅，就算手动组是空的，MATCH 规则也能正常工作。

### 规则和优先级

- 从内置的文本文件中加载 GEOSITE/GEOIP 分类并支持搜索；可以添加规则提供者（rule-providers），也可以写手动 DOMAIN / IP / PROCESS 规则。
- 一键自动分组规则，选择默认的 MATCH 目标（DIRECT/REJECT/某个组），并且可以在 **Rule order** 列表中调整优先级顺序。
- 当你想直接粘贴现成配置时，规则提供者和规则本身都提供高级 YAML 区块。

### 输出与状态

- Build 时会把 `proxies + groups + providers + rules` 合并成一段 YAML，显示状态摘要，并允许你立即复制到剪贴板或下载为 `config.yaml`。

### 本地化

- 界面自带英文、中文、波斯语和俄语词典，语言偏好会保存在本地。
- Emoji 通过 Twemoji 渲染，在不同平台上看起来会更一致。

---

## 如何使用界面

1. 把**链接粘贴**到 “Input links” 输入框里，或者先点一下 **Demo** 填入示例节点，然后点击 **Build config**。
2. 在 **Subscriptions (proxy-providers)** 区块中**添加订阅**，设定拉取模式，如果你希望直接提供 provider 的原始 YAML，可以打开 **Advanced Subscriptions (YAML)**。
3. 通过 **➕ Add group** **配置代理组**：选择类型、图标、手动添加的代理，以及勾选哪些解析出来的代理要加入这个组。高级模式支持直接写 YAML。
4. 使用 **📄 Load**（GEOSITE）和 **🌍 Load**（GEOIP）**加载规则数据**，搜索分类、添加规则提供者，或输入手动规则。**⚙️ Auto rules group** 可以生成一套默认规则骨架，你也可以在 **Rule order** 里微调规则优先级。
5. **设置默认 MATCH 行为**（DIRECT/REJECT/某个组），如果需要，再去高级规则 YAML 里做细调。
6. **构建并导出**：在 **Ready YAML** 面板中可以看到合并后的配置，并通过 **Copy** 或 **Download config.yaml** 按钮导出。状态标签会提示数量统计或解析错误。

---

## 仓库结构

- `index.html` — 单页 UI，使用原生 JS modules，包含所有输入、订阅、分组、规则、状态与 YAML 输出控件。
- `styles/` — 界面所需的字体和样式。
- `src/main.js` — 入口文件，负责解析输入、重建状态并生成 YAML 输出。
- `src/parser.js` — 支持多种协议和 base64 输入的健壮代理链接解析器。
- `src/groups.js` — 管理代理组的逻辑与 UI 绑定。
- `src/subs.js` — 管理订阅（proxy-providers）的逻辑与 UI 绑定。
- `src/rules.js` — 规则管理、规则提供者、规则顺序以及 MATCH 行为。
- `src/geo.js` — 从内置文件加载并搜索 GEOSITE/GEOIP 分类。
- `src/yaml-gen.js` — 根据应用状态组装最终 YAML。
- `src/i18n.js` 和 `src/i18n/` — 语言选择器、翻译词典与 Twemoji 集成。
- `geo/` — 预生成的 `geosite.txt` / `geoip.txt` 列表，用于离线浏览 GEOSITE/GEOIP 分类。
- `geo-update.py` — 用于从 `meta-rules-dat` 更新 GEO 列表的辅助脚本。

---

## 本地运行

应用是静态的：clone 仓库后，用任意静态服务器把这个目录跑起来，让 ES modules 能正常加载，例如：

```bash
python -m http.server 8000
```

然后在浏览器打开 `http://localhost:8000/` 即可。不需要构建步骤，也不需要任何后端服务。

---

## 更新 GEO 文件

`geo/geosite.txt` 和 `geo/geoip.txt` 来自 [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat)，通过 `geo-update.py` 重新生成：

```bash
python geo-update.py
```

脚本会 clone 上游仓库，提取分类名（去掉扩展名），把文本文件移动到 `geo/` 目录中，然后删除临时 clone。

---

## 限制

- **没有后端：** 应用完全在浏览器中运行，订阅由客户端直接拉取。
- **仅限浏览器：** 没有 CLI 封装，这个工具专注于交互式 Web UI。
- **客户端兼容性：** 输出针对 Mihomo/Clash.Meta 风格配置做了优化。某些分支或高度定制的客户端可能仍需手动微调。
- **不内置节点测速：** 应用不会 ping 或 benchmark 代理节点，它只负责生成配置 YAML。

---

## 本地化与贡献

- 可以在 `src/i18n/*.js` 中添加或调整翻译，并在 `src/i18n.js` 中注册新语言。
- 欢迎提交 issue 或 PR 来改进解析器、增加预设或优化 UI。
- 请把各语言的 README 翻译放在各自的文件里；英文版本是主要和权威的来源。

---

## 署名

Mihomo Constructor 是一个基于 Clash/Mihomo 配置格式和规则集构建的独立辅助工具。文中提到的所有产品名称都归其各自作者所有。
