<div align="center">

[English](README.en.md) | 中文

```text
  ◆──────────────────────────────────────◆
  ███╗   ███╗ ██████╗    ███████╗ ██████╗
  ████╗ ████║██╔════╝    ██╔════╝██╔════╝
  ██╔████╔██║██║         ███████╗██║
  ██║╚██╔╝██║██║         ╚════██║██║
  ██║ ╚═╝ ██║╚██████╗    ███████║╚██████╗
  ╚═╝     ╚═╝ ╚═════╝    ╚══════╝ ╚═════╝
  ◆──────────────────────────────────────◆
```

# 🛠️ MC Scanner v3.6.5

> 版本号唯一来源是 `config.__version__`：CLI `--version`、Web 面板和启动脚本都从这里取。升级版本只改这一处，不要再手写进文档/脚本。

### Minecraft 服务器扫描 · 探测 · 观察者 · 安全提醒 / Minecraft Server Scanner · Probe · Observer · Security Alert

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![CI](https://github.com/IRmsk/mc-scanner-v3/actions/workflows/test.yml/badge.svg)](https://github.com/IRmsk/mc-scanner-v3/actions)
[![License](https://img.shields.io/badge/License-GPL--3.0-00d992.svg)](LICENSE)
[![Protocol](https://img.shields.io/badge/协议表-41%20版本%20(340%2B)-10b981.svg)](#协议与版本)
[![Tests](https://img.shields.io/badge/测试-215%20通过-00d992.svg)](#测试)
[![Platform](https://img.shields.io/badge/平台-Linux%20%7C%20macOS%20%7C%20Windows%20%7C%20Termux-555555.svg)](#)

**端口扫描 · SLP 探测 · 认证检测 · 观察者 · AI 托管 · 安全扫描 · Web 面板**

</div>

---

## 📑 目录

| | | |
|:---:|:---:|:---:|
| [🧭 简介](#-简介) | [✨ 功能一览](#-功能一览) | [🚦 能力边界](#-能力边界诚实对照) |
| [🚀 快速开始](#-快速开始) | [📖 从零开始教程](#-从零开始教程--beginners-guide) | [🧩 项目结构](#-项目结构) |
| [🧪 测试](#-测试) | [📜 更新日志](#-更新日志) | [⚖️ 法律与伦理](#️-法律与伦理) |
| [📄 许可证](#-许可证) | | |

---

## 🧭 简介

**MC Scanner** 是一个纯 Python 编写的 Minecraft 服务器扫描与探测工具，提供 **Web 控制面板** 和 **命令行** 两种使用方式。

它能做的事：扫描网段端口、通过 SLP 协议获取服务器信息（版本 / MOTD / 玩家数 / 在线玩家）、识别认证模式（离线 / 正版 / 白名单）、以机器人身份登录发消息、用观察者实时监控聊天、以及（实验性的）AI 托管聊天。

> 本项目是一个**功能完整的个人工具**，定位是「授权范围内的服务器巡检与安全提醒」，不是通用 Minecraft 客户端，也不鼓励任何未授权访问。

```text
┌─ 典型工作流 ─────────────────────────────────────────────┐
│  端口扫描  →  SLP 探测  →  认证识别  →  观察者 / 安全提醒  │
│  (找端口)    (取信息)     (离线/正版)    (监控 / 告知)      │
└──────────────────────────────────────────────────────────┘
```

---

## ✨ 功能一览

### 🔍 扫描与探测

| 功能 | 说明 |
|------|------|
| 多线程 / 异步端口扫描 | 支持 CIDR 网段、端口范围、主机名 |
| SLP 协议探测 | 版本、玩家数、MOTD、协议号、玩家列表 |
| 认证模式检测 | 离线 / 正版 / 白名单 / 拒绝 四态 |
| 核心 / 模组识别 | vanilla · paper · spigot · forge · fabric · neoforge 等 |
| masscan 两阶段集成 | 大范围自动 masscan 探活 → SLP 探测 |

### 🤖 机器人与观察者

| 功能 | 说明 |
|------|------|
| 登录发消息 | 登录服务器发送自定义消息 |
| AuthMe 支持 | `auto` / `login_only` / `register_then_login` 三种模式，按服务器反馈分支 |
| 多版本适配 | 协议表由 minecraft-data 自动生成（41 个协议版本） |
| 多机器人并发 | 单台上限可配置（`bot_threads`） |
| 观察者模式 | 实时监控聊天、关键词处理、记录落盘、断线指数退避重连 |
| 正版账号登录 | Microsoft 账号 OAuth 设备码流程，多账户管理 |

### 🧠 AI 托管（实验性）

> 实验性功能，默认不加载，需在配置中显式启用。

| 功能 | 说明 |
|------|------|
| AI 聊天机器人 | 兼容 DeepSeek / OpenAI 等接口 |
| 预设人格 | 多种人格，Web 端可编辑 |
| 多 AI 群聊 | 多个机器人同服互动 |
| 分层记忆 | 短期原文 + 中期摘要 + 长期玩家档案（可随时清除） |
| 安全护栏 | AI 回复以 `/` 开头会被拦截，API 连续失败自动退避 |

> **人格说明**：预设人格均为「助手」主题（热心、高冷、毒舌但靠谱、话痨、摸鱼、温柔引导、技术宅、乐观、直球、讲故事、极简、好奇探索共 12 种），底色为善意和帮助。
> 所有人格**只能用于自己拥有或已获书面授权的服务器**；向陌生人服务器发消息属于[禁止行为](#️-法律与伦理)中的骚扰。
> 现有「安全护栏」只拦 `/` 开头的命令和控制字符，**不是内容审核**。
> 实现层面：所有人格文本最终都汇入 `core/ai_bot.py` 的 `_safe_send_chat` 做统一出站过滤
> （控制字符清理 + `/` 命令前缀拦截 + 单条长度上限 200 字 + 换行拦截 + 单 bot 0.8s 限速），人格注入**不得绕过**该过滤。

### 🛡️ 扫描模式

| 模式 | 并发 | 速率 | 适用场景 |
|------|------|------|---------|
| `safe` | 低 | 自适应降速 | 公网 / 授权测试，低速温和 |
| `balanced` | 中 | 适中 | 默认模式，日常扫描 |
| `aggressive` | 高 | 全速 | **仅内网 / 信任网络** |

- **多任务并发**：可同时运行多个扫描任务（`max_concurrent_scans`，默认 2），超出上限自动排队、跑完自动续启；扫描期间**进服、收藏重查、观察者、AI、健康监控均可并行**，互不阻塞
- **批次冷却**：每批扫完暂停，降低连接风暴
- **自适应速率**：超时率突变自动降速，连接异常时暂停 / 中止
- **断点续扫**：中断后 `--resume` 从上次位置继续（进度文件带版本校验，损坏即拒绝）

### 🌐 Web 面板

- 启动后访问 `http://127.0.0.1:8090`
- **无登录认证**：本工具默认绑定 `127.0.0.1` 本地使用，不设登录；若绑定 `0.0.0.0` 局域网可访问，**任何人都能操作，请确保网络可信**
- 深色界面，**桌面端 / 移动端自适应**
- 扫描任务、观察者、AI 托管、正版账号、数据库、收藏、人数历史一站管理
- 顶部常显当前能力状态徽章；默认绑定 `127.0.0.1`（本地使用）

### 🔒 安全与运维

- **能力分级开关**：扫描（默认开）/ 登录交互 / RCON 命令（默认关）
- **全局只读模式**：一键锁死所有写操作
- **操作审计日志**：写操作记录来源、目标、动作、结果
- API 按模块限流；敏感配置支持 `MC_*` 环境变量覆盖
- SLP 探测缓存，避免重复探测

### 💓 健康监控（收藏）

- 周期探测收藏服务器，记录在线/离线、人数、玩家进出，变化可汇总邮件
- **温和探测速率**（避免被限速/拉黑）：并发 ≤ `health_probe_concurrency`（默认 8）；同一 IP 两次探测间隔 ≥ `health_probe_ip_gap` 秒（默认 1.5）；每轮间隔 `health_interval` 秒（默认 300）——均在 Web 设置页或 `config.json` 可调
- 监控用 fast 模式只试自动版本不遍历所有协议，55个目标十几秒跑完；发现认证缺失时自动补一次认证检测
- 默认还会带上数据库里"有人气"的服务器（最多 20 个）；只想监控收藏时设 `health_monitor_db_extra: false`

---

## 🚦 能力边界（诚实对照）

为了不夸大，这里如实说明当前版本「能做什么、做不到什么」：

| 场景 | 状态 | 说明 |
|------|:----:|------|
| 端口扫描 / SLP 信息探测 | ✅ 可靠 | 主路径，覆盖各版本 |
| 离线（offline）服登录 + 发消息 | ✅ 可靠 | 安全提醒的主要场景 |
| 正版（online）服登录 | ✅ 可用 | 需先完成 Microsoft OAuth |
| 正版服**发送聊天** | ✅ 可用 | 正版登录后自动获取Mojang签发的RSA证书，用 pycryptodome 做 RSA-2048+SHA256 签名；签名失败自动回退无签名模式 |
| Forge / Fabric / NeoForge 模组服 | ⚠️ 部分 | 以原版姿态可通过部分验收；强制模组校验的服无法进入 |
| 1.12.2 等旧版本 | ⚠️ 尽力 | 协议表已覆盖并重点验证，但边缘情况较多 |
| 通用 Minecraft 客户端 | ❌ 非目标 | 不做完整游戏操作 / 模组加载（聊天签名见上一行的正版说明） |
| 未授权全网扫描 | 🚫 禁止 | 见[法律与伦理](#️-法律与伦理) |

---

## 🚀 快速开始

### 安装 / Installation

```bash
git clone https://github.com/IRmsk/mc-scanner-v3.git
cd mc-scanner-v3

# 安装依赖（必需 flask + 正版登录用 pycryptodome）
pip install -r requirements.txt

# 可选：复制配置模板
cp config.example.json config.json
```

> **依赖说明**：本项目不再 vendor 第三方库（`libs/` 目录已删除），全部通过 pip 安装。`flask` 是 Web 面板必需，`pycryptodome` 是正版账号登录必需。`uvloop` / `pysimdjson` 是可选加速，不装自动降级不影响功能。

### 启动 Web 面板

```bash
python3 cli.py web --port 8090 --host 127.0.0.1
# 浏览器打开 http://127.0.0.1:8090
```

### 命令行扫描

```bash
# 单 IP 全端口，安全模式
python3 cli.py scan 1.2.3.4 --port 1-65535 --mode safe

# 网段扫描，平衡模式
python3 cli.py scan 192.168.1.0/24 --mode balanced

# 断点续扫
python3 cli.py scan 1.2.3.4 --port 1-65535 --mode safe --resume

# 只扫端口（不探测 MC 协议）
python3 cli.py portscan 192.168.1.0/24 --port 1-65535

# masscan 大范围端口发现（CLI 的 scan 子命令没有 --use-masscan，该选项只在 Web 面板可用）
python3 cli.py masscan --targets 10.0.0.0/8 --port 25565 --rate 1000 --exclude exclude.conf
```

### 正版账号登录（设备码）

1. Web 面板 → 设置页 → 正版账号 →「获取设备码」
2. 浏览器打开 `microsoft.com/link`，输入设备码并登录
3. 成功后自动保存；观察者 / AI 进服时**手动勾选**「正版验证」即可

### 环境变量（敏感配置）

```bash
MC_AI_API_KEY=your_key
MC_AI_BASE_URL=https://api.deepseek.com
MC_AI_MODEL=deepseek-chat
MC_DISCORD_WEBHOOK=your_webhook
MC_AUTHME_PASSWORD=your_password
```

### 命令行退出码

| 码 | 含义 |
|:---:|------|
| 0 | 成功 |
| 1 | 无结果 / 失败 |
| 2 | 高速模式未确认 |
| 3 | 参数错误（缺参数 / 缺 `--yes`） |
| 4 | 能力开关拒绝 |

---

## 📖 从零开始教程 / Beginner's Guide

### 1. 环境要求 / Requirements

| 项目 | 要求 |
|------|------|
| Python | 3.10+（3.12 推荐） |
| 系统 | Linux / macOS / Windows / Termux(Android) |
| 网络 | 能访问目标服务器和 GitHub |
| 可选 | masscan（大范围高速扫描） |

### 2. 安装 / Installation

```bash
# 克隆仓库
git clone https://github.com/IRmsk/mc-scanner-v3.git
cd mc-scanner-v3

# 安装依赖
pip install -r requirements.txt

# 验证安装
python3 cli.py --help
```

如果 `pip install` 失败（常见于 Termux/手机）：
```bash
pkg install python python-pip openssl
pip install flask pycryptodome
```

### 3. 第一次启动 Web 面板 / First Run

```bash
python3 cli.py web --port 8090 --host 127.0.0.1
```

浏览器打开 `http://127.0.0.1:8090`，你会看到深色面板。底部导航有：扫描、结果、收藏、观察、AI、自动、库、历史。

> **手机 Termux 用户**：在 Termux 里运行上面的命令，然后用手机浏览器打开 `http://127.0.0.1:8090`。面板已适配移动端。

### 4. 扫描你的第一个服务器 / First Scan

在 Web 面板的「扫描」页：
1. 目标输入框填 IP 或域名（如 `1.2.3.4` 或 `mc.example.com`）
2. 端口默认 `25565`，可填范围 `25565-25570`
3. 模式选 `safe`（公网用）或 `balanced`（默认）
4. 点「开始扫描」

扫描分两阶段：
- **阶段1**：端口扫描，找开放端口
- **阶段2**：SLP 探测 + 认证检测，判断离线/正版/白名单

扫完后在「结果」页查看，可按认证模式、版本、关键词筛选。

命令行等效：
```bash
python3 cli.py scan 1.2.3.4 --mode safe
python3 cli.py scan 192.168.1.0/24 --mode balanced
```

### 5. 观察者模式 / Observer

观察者 = 以机器人身份登录服务器，实时看聊天、玩家进出，可发消息。

在「观察」页或「结果」页点某台服务器的「观察」按钮：
- 用户名填你想用的名字（如 `WatchDog`）
- 离线服直接进，正版服需先配置微软账号（见第6节）
- 进服后可在输入框发消息，聊天记录自动保存
- 点「断开」退出，记录可导出 TXT/HTML

命令行等效：
```bash
python3 cli.py bot 1.2.3.4:25565 -u WatchDog -m "你好" --hold 10
```

### 6. 正版账号登录 / Premium Account (Microsoft)

要用正版账号进正版服，需先完成 Microsoft OAuth：

1. Web 面板 → 右上角设置 → 正版账号 →「获取设备码」
2. 终端会显示一串设备码和网址 `microsoft.com/link`
3. 浏览器打开网址，输入设备码，登录你的微软账号
4. 成功后账号自动保存，观察者进服时勾选「正版验证」即可

> 正版登录需要 `pycryptodome`（已在 requirements.txt 中）。聊天签名用 RSA-2048+SHA256，Mojang 签发证书。

### 7. 单服务器登录发消息 / Bot

对指定服务器登录并发送自定义消息：

```bash
# 登录单台服务器发消息
python3 cli.py bot 192.168.1.10:25565 -u SecurityBot \
  -m "你好，我是安全扫描机器人" \
  -m "检测到您的服务器是离线模式，建议启用 online-mode=true"
```

有 AuthMe 的服务器用 `--authme 密码` 自动注册/登录，`--register` 用于新用户注册。

### 8. 收藏与健康监控 / Favorites & Health Monitor

- 在「结果」页点星标收藏服务器
- 「收藏」页管理收藏，支持按认证方式、有人/没人筛选
- 健康监控自动周期探测收藏服务器，记录人数变化，可邮件通知
- 人数趋势图在收藏页，点 📈 查看

### 9. 配置说明 / Configuration

`config.json`（首次运行自动生成）主要字段：

下表与 `config.py` 的 `DEFAULT_CONFIG` 一致（`config.example.json` 也同源）：

| 字段 | 默认 | 说明 |
|------|------|------|
| `username` | `SecurityBot` | 机器人默认用户名 |
| `messages` | `null` | 默认警告消息，为空时用内置提示语 |
| `ports` | `[25565]` | 默认扫描端口 |
| `scan_threads` | `50` | 端口扫描线程数 |
| `scan_timeout` | `3.0` | 单目标超时（秒） |
| `workers` | `16` | SLP 探测线程数 |
| `timeout` | `5.0` | SLP 探测超时（秒） |
| `bot_threads` | `5` | 机器人并发数 |
| `bot_timeout` | `15` | 机器人超时（秒） |
| `message_delay` | `1.2` | 消息发送间隔（秒） |
| `rate` | `30` | 全局速率（每秒请求数） |
| `authme_password` | `""` | AuthMe 自动登录密码 |
| `exclude_file` | `exclude.conf` | 排除列表文件 |
| `db_path` | `mcscanner.db` | SQLite 数据库路径 |
| `web_host` / `web_port` | `127.0.0.1` / `8080` | Web 面板绑定地址 / 端口 |
| `log_level` | `INFO` | 日志级别 |
| `bot_threads` | `5` | 多机器人并发上限 |
| `health_interval` | `300` | 健康监控轮询间隔（秒） |
| `health_probe_concurrency` | `8` | 健康监控同时探测数 |
| `health_probe_ip_gap` | `1.5` | 同 IP 两次探测最小间隔（秒） |

完整默认值以 `config.py` 的 `DEFAULT_CONFIG` 为准。也可用环境变量覆盖敏感配置：`MC_AI_API_KEY`、`MC_DISCORD_WEBHOOK` 等。

### 安全开关

| 开关 | 默认 | 说明 |
|---|---|---|
| `ALLOW_PUBLIC_BIND` | 无（拒绝） | 绑定 `0.0.0.0` 需显式设置环境变量 `ALLOW_PUBLIC_BIND=1`，否则启动时拒绝 |
| `capabilities.scan` | `true` | 基础扫描能力（允许扫自己的服务器） |
| `capabilities.public_scan` | `false` | 公网随机扫描（禁止全网扫，需显式开启） |
| `health_monitor_db_extra` | `false` | 是否额外监控数据库里有人气的服务器（默认关，避免无授权探测第三方） |

### 10. 常见问题 / FAQ

**Q: 提示 `ModuleNotFoundError: No module named 'flask'`**
A: 没装依赖，执行 `pip install -r requirements.txt`

**Q: 正版服进不去，报 `authservers_down`**
A: Mojang 认证服务器临时不可用，等几分钟重试；或检查网络是否能访问 `authserver.mojang.com`

**Q: 发消息被踢 `chat.disabled.missingProfileKey`**
A: 服务器强制安全档案，需用正版账号登录（第6节），离线账号无法在强制签名服发消息

**Q: 发消息被踢 `Packet chat was larger than expected`**
A: 部分服务器版本的聊天包格式兼容问题，正在排查中，可换台服务器测试

**Q: NeoForge/Forge 模组服连不上**
A: 强制模组校验的服要求客户端装对应模组，纯原版客户端无法进入。开了「允许原版客户端」的模组服可以进

**Q: 扫描进度条不动**
A: 小目标（<100台）扫描很快，进度条可能直接跳到100%；大目标用 `--workers` 调大并发

**Q: Termux 上 `pip install` 编译失败**
A: 用 `pkg install python openssl` 后只装纯 Python 包：`pip install flask pycryptodome`，跳过 `cryptography`（用 pycryptodome 兜底）

### 11. 卸载 / Uninstall

```bash
# 停止服务后直接删除目录
rm -rf mc-scanner-v3
# 数据库和配置在目录内，一并删除
```

---

## 🧩 项目结构

```text
mc-scanner-v3/
├── cli.py                  # 命令行入口
├── config.py               # 配置管理
├── core/
│   ├── bot.py              # Minecraft 机器人核心
│   ├── conn.py             # 连接层（加密 / 协议）
│   ├── probe.py            # SLP / 认证探测
│   ├── protocol.py         # 版本映射 / 协议常量
│   ├── packets.py          # 协议表加载与完整性校验
│   ├── packets_auto.py     # 自动生成协议表（41 版本）
│   ├── microsoft_auth.py   # Microsoft OAuth 正版登录
│   ├── ed25519.py          # 纯Python Ed25519签名（零外部依赖）
│   ├── errors.py           # 统一错误码与映射
│   ├── nbt.py / chat.py    # NBT / JSON 文本解析
│   ├── buffer.py           # 字节流工具
│   ├── rcon.py             # RCON 远程控制台
│   ├── command_runner.py   # 命令执行器
│   ├── plugins.py          # 插件 / 反作弊识别
│   ├── fingerprint.py      # 服务器指纹
│   ├── ai_bot.py           # AI 机器人会话
│   ├── ai_memory.py        # AI 分层记忆
│   ├── ai_personas.py      # AI 人格预设
│   └── protocols/          # 各版本协议 handler
├── scanner/
│   ├── safe.py             # 安全扫描配置 / 进度存储
│   ├── async_engine.py     # 异步流水线
│   ├── portscan.py         # 同步端口扫描
│   └── engine.py           # 扫描引擎
├── web/
│   ├── app.py              # Flask 应用
│   ├── index.html          # 前端面板（桌面 / 移动自适应）
│   ├── state.py            # 共享状态
│   └── routes_*.py         # 各模块 API 路由
├── service/                # 扫描 / 警告任务服务
├── storage/                # 收藏等持久化
├── tools/
│   ├── gen_packets.py      # 协议表自动生成
│   ├── get_mc_token.py     # 正版设备码工具
│   └── send_command.py     # 命令发送工具（需授权，谨慎使用）
├── distributed/            # ⚠️ 实验性：分布式分片
├── android_patches/        # ⚠️ 实验性：Android/Kivy 打包补丁（PythonActivity.java）
├── tests/                  # 单元 / 集成测试
├── config.example.json     # 配置模板
├── requirements.txt        # 依赖
├── LICENSE                 # GPL-3.0
└── README.md
```

---

## 🧪 测试

```bash
python3 -m pytest tests/ -q
```

当前 **215 个测试全部通过**，覆盖：协议表完整性、版本映射、认证探测、Login Start分档、Client Settings分档、AuthMe分支、进度存储、AI安全护栏、失败路径、无报告协议回退等。

重新生成协议表：

```bash
python3 tools/gen_packets.py --download
```

---

## 📜 更新日志 / Changelog

<details>
<summary><b>v3.6.5</b>（点击展开 / Click to expand）</summary>

这版是安全审计维修清单的集中修复，8 个提交 101 个文件，测试 193 → 212。/ Security audit maintenance fixes, 8 commits, 101 files, tests 193 → 212.

**协议层 / Protocol**
- **解压炸弹**：`zlib.decompress` 改用 `decompressobj().decompress(data, max_length)`，8MB 上限真正生效（之前检查服务器自报的 data_length，可撒谎）
- **VarInt**：限 5 字节（之前第 6 字节被先收下再判断），加 int32 符号扩展（`0xFFFFFFFF` 正确返回 -1 而非 4294967295）
- **NBT List 计数**：校验 count ≤ 剩余字节数，恶意服发 `count=0x7FFFFFFF` 不再空转十几分钟
- **包 ID 错位**：770-772 手写表范围缩到只 770，771/772 交自动表（之前用 1.21.5 的 ID 覆盖 1.21.6+，导致保活回错包被踢）

**扫描器 / Scanner**
- **safe 模式并发**：不再硬编码 `slp_concurrency=400`，走 profile 默认值（之前 safe 模式实际并发 400，是设计值 20 的 20 倍）
- **端口展开 DoS**：`parse_ports_spec` 先夹到 1-65535，到 max_ports 即停，不再全量物化 range（`1-50000000` 之前吃几 GB 内存）
- **fd 泄漏**：async_probe 超时/异常分支加 finally 关 writer
- **跨 event loop 锁**：`_rate_lock` 按次创建，不再绑定首个 loop 导致第二次 asyncio.run 静默失败
- **畸形 banner 崩溃**：version/players 非 dict 时 isinstance 兜底
- **异步路径排除表**：cli.py 异步入口统一走 `parse_and_filter_targets`，私网/保留段不再被绕过
- **masscan 结果落库**：之前 masscan 分支调 `probe_list()`（注释明写"不存数据库"），现显式 `db.upsert_many`

**Web / 前端**
- **存储型 XSS**：自动扫描日志 `innerHTML` 拼接加 `escapeHtml`（日志含远端可控 MOTD/版本）
- **反射型 XSS**：`/auth-response` 的 error/err_desc/name 统一转义
- **SSRF + 密钥外泄**：AI 请求 base_url 不再可由请求方覆盖，只用配置值
- **services_assistant 死代码**：原来自建线程调不存在的 `ScanEngine(targets=..., run())` + 访问不存在的 `scan_state["stop_event"]`，自然语言扫描链路 100% 崩溃。现改调 `services_scan.start_scan_task`
- **warn KeyError**：异常分支补 `messages_sent: 0`，不再 `sum(r["messages_sent"])` 必 500
- **scan_tasks 内存泄漏**：任务结束后延迟淘汰，不再每任务长期持有全量 results
- **能力开关门禁**：`/api/auto_scan/add`、随机全网扫描补 capability/read_only 校验
- **观察者日志锁**：`_ensure_log_file`/`_append_log`/`_next_seq` 加锁，防并发 fd 泄漏/seq 重复
- **健康监控状态竞态**：`del status[k]` 加锁，状态接口快照遍历

**Bot / AI**
- **AI `/` 拦截绕过**：`send_message`/`send_to_all`/opener 统一走 `_safe_send_chat`，不再绕过斜杠命令拦截
- **SMTP 证书校验**：`ssl._create_stdlib_context()`（CERT_NONE）改 `ssl.create_default_context()`，防 MITM 窃取邮箱凭据
- **幽灵玩家**：AI bot duration/重连上限分支 return 前统一 finally close()
- **auto_scanner 资源上限**：targets/ports 加规模上限，`ai_hijack` 去重 + 留句柄 + 上限

**存储 / Storage**
- **收藏夹丢更新**：`_write_atomic` 用 `mkstemp` + `os.replace`，不再读→改→写跨调用无锁
- **rescan_all 持锁做 I/O**：网络探测移出临界区（之前 `add_favorite` 阻塞 5.68 秒）
- **SQLite 连接泄漏**：连接池上限 + LRU，db_path 固定不再来自请求
- **JSON 截断**：按语义裁剪后保证合法，不再按字符截断 2000 导致非法 JSON
- **分片竞态**：`claim_shard` 读-改-写加文件锁，`job_id` 正则校验防路径穿越

**CLI / 文档**
- **版本号单一来源**：run.bat 从 `config.__version__` 取，不再写死 3.6.3
- **run.bat 依赖检查**：改 `import flask` 判依赖（之前查 `libs\flask\__init__.py`，libs 已删所以永远重装且只装 flask 漏 pycryptodome）
- **config.example.json**：与 DEFAULT_CONFIG 对齐

**还没修好的 / Still broken**
- 部分离线服发消息被踢 "Packet chat was larger than expected"：仍在排查
- 个别协议版本（如 776）自动生成的协议表缺 Configuration 段，回退手写常量
- 强制模组校验的 Forge/NeoForge 服无法连接（纯原版客户端硬限制）
- 鉴权未恢复：`_check_auth` 仍为空函数，工具定位本地 127.0.0.1 使用，绑 0.0.0.0 有风险

</details>

<details>
<summary><b>v3.6.4</b>（点击展开 / Click to expand）</summary>

这版主要是修 bug 和清理，没有新功能。/ Mostly bug fixes and cleanup, no new features.

**修了什么 / What's fixed**

- **NeoForge 识别**：NeoForge 1.20.2+ 不在 SLP 里暴露 forgeData，之前会误判成 vanilla。现在靠登录握手时的 `neoforge:login` 频道修正。注意：只在开了认证检测时有效；强制模组校验的 NeoForge 服依然连不进去（这是硬限制，不是 bug）
- **人数趋势图不显示**：一个低级错误——图表容器是 `<div>` 不是 `<canvas>`，无数据时塞进去的 `<p>` 标签残留导致 Chart.js 初始化失败。现在先清空再建 canvas
- **扫描进度条不动**：自适应限速器初始速率被 profile 默认值覆盖了用户配置，初始批次 200 太大导致小目标一次性提交完才进循环。改了初始速率取 min(用户配置, 上限)，批次改 max_workers*2，进度步长动态化
- **配置路径叠层**：config.json 在子目录时，保存一次路径多一层。已统一以配置文件所在目录为基准
- **不再 vendor 依赖**：删除整个 `libs/` 目录（Flask 及其依赖，约 2.6MB），全部通过 `pip install -r requirements.txt` 安装。之前的 uvloop/simdjson 空壳也一并删了
- **代码卫生**：8 处 raise 补了 from e，补了一个测试断言，测试结束清理 observer_logs，清了 21 个 unused import，PWA 缓存加了版本号

**还没修好的 / Still broken**

- 部分离线服发消息被踢 "Packet chat was larger than expected"：正在排查，已加 payload hex 调试日志，根因还没定位到
- 个别协议版本（如 776）自动生成的协议表缺 Configuration 段，回退手写常量，可能导致新版服务器连接异常
- 强制模组校验的 Forge/NeoForge 服无法连接（需要客户端发模组列表，纯原版客户端做不到）

</details>

<details>
<summary><b>v3.6.3</b>（点击展开）</summary>

**聊天功能修复（核心）**
- 修复 1.21 (proto 767) 观察者收不到聊天消息：`extract_chat_text` 错误跳过 `globalIndex` 字段（该字段 1.21.2/768 才加入），导致解析字节错位、文本为空。消息实际一直在广播，只是观察者解析不出来
- 撤掉针对错误诊断的 workaround：离线账号 `/me` 兜底、自签名 Chat Session（对离线账号有害，服务器收到无法验证的密钥后会静默丢弃后续无签名消息）

**正版签名聊天（RSA-2048+SHA256）**
- Minecraft 1.19+ 聊天签名实际用 **RSA-2048 + SHA256 PKCS#1 v1.5**（非 Ed25519），Mojang `/player/certificates` 返回 RSA 密钥对
- `_build_signed_chat` 用 pycryptodome 做 RSA-SHA256 签名，签名数据 = sender UUID(16) + timestamp(8) + salt(8) + message(UTF-8)
- 766+ (1.20.5+) 签名字段是固定 256 字节 buffer，无 varint 长度前缀
- 离线服不获取证书、不发 Chat Session（离线 UUID 与正版证书 UUID 不匹配，发了会被 invalid_public_key_signature 踢）
- 修复 Chat Session / 签名聊天 base64 解码 `Incorrect padding`：Mojang 返回的密钥可能缺末尾 `=` padding，解码前自动补全

**认证状态机加固**
- `auth_mode` 在 `__init__` 初始化为 `unknown`，Play 成功时仅 unknown 才标 offline（正版账号走过 Encryption 后保留 online，不再被覆盖）
- bot 与 probe 白名单关键词对齐（whitelist / white list / not white-listed / not whitelisted / 白名单 / 不在白名单 / not on the whitelist）
- `join_and_warn` 异常路径改用 `BotError.code`（WHITELIST / ONLINE_MODE_REQUIRED / BANNED / KICKED / INCOMPATIBLE_VERSION），不再扫异常字符串
- neoforge 从 forge pattern 拆出单独分类
- plugin_channels 数据流接上：auth_probe 返回并落库，可辅助 Forge/模组识别
- 无报告协议时跨时代回退（775/767/763/761/754/340），不再只试最新 3 个版本
- `fingerprint_server` 改名为 `fingerprint_by_field_order`，避免和 `core/fingerprint.py` 同名冲突

**安全加固**
- `msa_refresh_token` 等敏感令牌掩码，前缀收窄到 2 位
- 修复两处存储型 XSS（logBox、观察者卡片）

**AI 与观察者**
- AI Bot 10 秒内收到一模一样的内容直接忽略，不再自己跟自己吵架
- 观察者聊天记录按日期分类、可搜索 IP、可手动删除 0 消息记录

**收藏与健康监控**
- 收藏人数显示 `online/max` 格式（如 2/20）并显示玩家名称
- 收藏页筛选增加认证方式（正版/盗版）和有人/没人
- 人数趋势图移到收藏页
- 健康监控发现认证缺失时自动补一次认证检测

**Web 面板**
- 右上角加关闭服务按钮
- 移动端界面优化

</details>

<details>
<summary><b>v3.6.2</b>（点击展开）</summary>

**修复与优化**
- 修复 1.19.3–1.20.4 协议层 bug（Login Start 字节分档、Client Settings 字段分档）
- 健康监控 fast 模式，不再遍历19个协议版本，速度提升10倍
- AI Bot 通过 UUID 真正识别自己发的消息，不再自己跟自己说话
- 正版登录后自动同步服务器实际用户名，支持 Ed25519 签名聊天
- 数据库页加导入/清空/收藏按钮，收藏列表白名单优先排序
- 收藏人数显示 online/max 格式并显示玩家名
- Web 面板加关闭服务按钮
- 移除登录认证（本地工具），README 诚实描述
</details>

<details>
<summary><b>v3.6.1</b>（点击展开）</summary>

**收藏与健康监控**
- 收藏保留上次在线信息（`last_good_info`），离线重查/监控不再覆盖
- 健康监控并发探测、按监控列表清理残留状态、事件改用在线状态判定（空服开机不再漏报）
- 健康监控支持 Web 面板配置轮询间隔、手动"立即检查"、逐台探测实时更新
- 收藏文件原子写 + 并发写加锁，监控写回无变化不重写盘

</details>

<details>
<summary><b>v3.6.0</b>（点击展开）</summary>

**扫描引擎**
- `safe` / `balanced` / `aggressive` 三档模式
- 批次冷却、自适应降速、连接异常检测、断点续扫
- masscan 两阶段集成、扫描任务队列

**协议地基**
- 协议表由 minecraft-data 自动生成（41 版本），发布前完整性校验
- 版本映射校准并以单测锁死
- 配置阶段包 ID 以自动表为准

**AI 功能**
- 分层记忆系统、人格编辑、自动重连
- AI 回复命令拦截、API 失败退避、记忆可清除

**正版登录**
- Microsoft OAuth 设备码流程、多账户管理
- 各进服入口支持正版验证开关（手动勾选）
- ⚠️ 不发送真实聊天签名，强制签名服可能拒收

**安全加固**
- 能力分级开关、全局只读、操作审计、API 限流

</details>

<details>
<summary><b>v3.4.0</b></summary>

- Web 面板模块化拆分（多路由模块 + 服务层）
- Web UI 视觉升级 + 移动端适配
- AI 助手浮窗、健康监控邮件、人数历史曲线

</details>

---

## ⚖️ 法律与伦理

> 本节是使用本工具的**硬性约束**，不是可选项。

### ✅ 合法使用范围

- **安全研究 / 授权测试**：在明确（最好书面）授权下评估目标系统
- **自有资产巡检**：扫描和管理你自己拥有或托管的服务器
- **内网教学**：在隔离的私有网络中学习网络与协议

### 🚫 禁止行为

- 对**未授权**服务器进行端口扫描、探测或漏洞扫描
- 登录未授权服务器（含离线服）或访问其数据
- 在未授权服务器执行 `/op`、`/gamemode`、`/ban`、`/stop` 等任何命令
- 用 RCON 连接未授权服务器
- 进行 DDoS、僵尸网络、垃圾消息等任何形式的拒绝服务 / 骚扰
- 收集、传播第三方服务器的玩家数据、IP 等个人信息
- 规避或突破防火墙、白名单、正版验证等安全保护措施

### 🔐 数据隐私

- 工具不会向任何第三方上传你的扫描数据或配置
- 扫描结果仅存于本地，由你自行管理
- 请勿把含真实 IP / 玩家信息的结果或凭据提交到公开仓库
- `.gitignore` 默认排除 `*.db`、`*.json` 等数据与凭据文件

<details>
<summary><b>📖 相关法律依据（中国大陆）</b></summary>

未经授权扫描、登录或控制计算机信息系统，可能涉及：

- 《中华人民共和国刑法》第 285 条 —— 非法侵入计算机信息系统罪、非法获取计算机信息系统数据罪、**提供侵入 / 非法控制计算机信息系统程序、工具罪**
- 《中华人民共和国刑法》第 286 条 —— 破坏计算机信息系统罪
- 《中华人民共和国刑法》第 287 条之二 —— 帮助信息网络犯罪活动罪
- 《中华人民共和国网络安全法》
- 《中华人民共和国数据安全法》
- 《中华人民共和国个人信息保护法》

在其他国家 / 地区，请遵守当地关于计算机滥用、未授权访问与数据保护的法律（如 CFAA、GDPR 等）。

</details>

<details>
<summary><b>📝 免责声明</b></summary>

- 本工具按「现状」提供，作者不对其适用性、可靠性或安全性作担保
- 使用者需自行承担使用本工具产生的一切法律责任与后果
- 作者不对因使用本工具导致的任何直接或间接损失负责
- 如不同意上述条款，请立即停止使用并删除本工具
- 以上为一般性信息，不构成法律意见；具体案件请咨询执业律师

</details>

---

## 📄 许可证

本项目基于 [GNU GPL v3.0](LICENSE) 发布。使用/修改/分发本项目代码必须保持开源并采用相同协议。

<div align="center">

**请在授权范围内使用。Happy & Safe Scanning. 🟢**

</div>
