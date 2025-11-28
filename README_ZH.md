[🌐 打开 Mihomo Constructor](https://raywari.github.io/mihomo-constructor/)

**README 语言：**  
- **中文（当前）**  
- **Русский（俄语）** — https://github.com/raywari/mihomo-constructor/blob/main/README_RU.md  
- **English（英语）** — https://github.com/raywari/mihomo-constructor/blob/main/README.md  
- **فارسی（波斯语 / 伊朗语）** — https://github.com/raywari/mihomo-constructor/blob/main/README_FA.md  

# Mihomo Constructor

一个方便的 Clash/Mihomo 配置构建器，主打可视化 UI 与自动生成 YAML，无需手动复制粘贴。

> ⚠️ 本项目并非 Clash/Mihomo 团队的官方产品。  
> 不会将其商标用于商业目的，也不试图“抢占”名称。  
> 它只是一个独立的便捷工具，用于生成与其配置格式兼容的文件。

---

## 这是什么

**Mihomo Constructor** 是一个网页工具，帮助你从以下内容组装 Clash/Mihomo 配置：

- 代理链接（`vless://`、`vmess://`、`ss://` 等），
- 订阅（proxy-providers），
- 代理分组（proxy groups），
- 规则（GEOSITE/GEOIP、rule-providers），
- 如有需要，也支持手写 YAML。

本项目完全前端化：打开网页 → 粘贴数据 → 调整设置 → 直接得到可用的 `config.yaml`。

---

## 功能特性

- **链接输入**
  - 一次性粘贴多条链接 — 应用会自动解析并加入 `proxies`。

- **订阅（proxy-providers）**
  - 支持多个订阅链接。
  - *Advanced Subscriptions (YAML)* 模式 — 可手动替换/补充 YAML。

- **代理分组（Proxy Groups）**
  - 点击“➕ 添加组”按钮即可新增分组。
  - *Advanced Groups (YAML)* 模式 — 通过文本完整控制分组 YAML。

- **GEOSITE / GEOIP**
  - 加载域名与 IP 列表。
  - 按类别/国家搜索。
  - 通过“⚙️ 规则自动分组”按钮自动生成规则。

- **高级规则 + Rule-Providers**
  - 如果内置控件不够用 — 开启高级模式直接编辑 YAML 规则块。

- **输出成品 YAML**
  - 所有内容会合并为一个配置：`proxies + groups + providers + rules`。
  - 可直接：
    - 复制到剪贴板，
    - 下载为 `config.yaml`。

---

## 使用与相关项目

我面向 Clash/Mihomo 生态，基于开源项目、其配置格式与现有规则集开发这个便捷构建器。

部分相关/配套项目：

- **Mihomo（核心）**  
  与本项目配置格式兼容的核心仓库：  
  https://github.com/MetaCubeX/mihomo

- **Mihomo Dashboard（metacubexd）**  
  官方网页面板，用于通过 Web 界面管理 Mihomo：  
  https://github.com/MetaCubeX/metacubexd

- **meta-rules-dat**  
  为 Mihomo 提供的规则集（GEOSITE/GEOIP 等）：  
  https://github.com/MetaCubeX/meta-rules-dat

- **Clash / Clash.Meta 及客户端**  
  Clash 相关核心与客户端导航，包含不同实现与 GUI：  
  https://github.com/clash-version/clash-download

Mihomo Constructor 用于补充这些项目，并非它们的 fork。  
它是一个独立工具，基于其格式之上，帮助你更快、更轻松地组装稳定的 Clash/Mihomo 配置。

- **“Clash”**、**“Mihomo”** 及其他提到的产品名称归其作者所有。
- Mihomo Constructor 与 MetaCubeX 团队、Clash 作者或其他客户端团队无隶属关系。
