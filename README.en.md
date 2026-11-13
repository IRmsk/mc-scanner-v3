<div align="center">

English | [中文](README.md)

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

# 📡 MC Scanner v3.6.5

> The single source of truth for the version is `config.__version__`: CLI `--version`, the Web panel and the launcher scripts all read it. Bump it there only.

### Check your own Minecraft server: offline mode? which ports are public? is RCON exposed?

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![CI](https://github.com/IRmsk/mc-scanner-v3/actions/workflows/test.yml/badge.svg)](https://github.com/IRmsk/mc-scanner-v3/actions)
[![License](https://img.shields.io/badge/License-GPL--3.0-00d992.svg)](LICENSE)
[![Protocol](https://img.shields.io/badge/Protocol-40%20versions%20(340%2B)-10b981.svg)](#protocols)
[![Tests](https://img.shields.io/badge/tests-CI%20gated-00d992.svg)](#tests)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows%20%7C%20Termux-555555.svg)](#)

**Self-check · Inspection · Auth Detection · Observer · Web Panel**

</div>

---

## ⚡ 30-Second Self-Check

```bash
pip install -r requirements.txt
python cli.py scan play.example.com:25565
```

Real output (the CLI prints in Chinese by default; this is a local test server, unedited):

```text
[*] 发现 1 个 Minecraft 服务器:
  127.0.0.1:25599 | 1.21.1(协议767) | 5/100人 | cracked | vanilla
                                                  ^^^^^^^
```

`cracked` means **offline mode**: anyone can join with any username, and impersonate an admin.

| 4th column | Meaning | What to do |
|---|---|---|
| `online` | Mojang auth required | fine |
| `cracked` | **offline mode — anyone can join, anyone can be OP** | set `online-mode=true` in `server.properties` |
| `whitelist` | whitelist on, can't get in | fine (this one is good news) |
| `rejected` | connection refused | check the server log |

### Two more worth confirming

| What | Command | How to read it |
|---|---|---|
| Ports other than 25565 | `python cli.py portscan <YOUR_PUBLIC_IP> --port 1-65535` | every line is reachable from the internet |
| Is RCON exposed | `python cli.py portscan <YOUR_PUBLIC_IP> --port 25575` | any hit = console reachable, set `rcon.password` or disable it |

> All three commands touch only the single address you pass in. **Point them at your own server** — this is a self-check tool, not a way to find other people's servers.

---

## 📑 Table of Contents

| | | |
|:---:|:---:|:---:|
| [⚡ 30-Second Self-Check](#-30-second-self-check) | [🧭 Introduction](#-introduction) | [✨ Features](#-features) |
| [🚀 Quick Start](#-quick-start) | [📖 Beginner's Guide](#-beginners-guide) | [🧩 Project Structure](#-project-structure) |
| [🧪 Tests](#-tests) | [📜 Changelog](#-changelog) | [⚖️ Legal & Ethics](#️-legal--ethics) |

---

## 🧭 Introduction

**MC Scanner** is a pure-Python self-check and inspection tool for Minecraft servers, with both a command line and a **Web panel**. No Java, no game client needed.

It can: scan network ranges for open ports, query server info via SLP (version / MOTD / player count / online players), detect auth mode (offline / online / whitelist), log in as a bot to send messages, monitor chat in real-time with an observer, and (experimental) host AI chat bots.

> Its default posture is **check your own**: point it at an address you are responsible for and see what it exposes.
> Range scanning, the observer and join-and-warn are all still there — but those are what you use *after* you have authorization. See [Capabilities](#-capabilities-honest-assessment).

```text
Self-check (default)
  one address you own  →  SLP probe  →  auth mode  →  is it cracked?
     your server         version/count   offline/online    that's the leak

Inspection (after authorization)
  CIDR range  →  bulk probe  →  observer / join-and-warn  →  Web panel
   find targets   SLP + auth       continuous watch          manage / export
```

---

## ✨ Features

### 🔍 Scanning & Probing

| Feature | Description |
|---------|-------------|
| Multi-threaded / async port scan | CIDR ranges, port ranges, hostnames |
| SLP protocol probe | Version, player count, MOTD, protocol number, player list |
| Auth mode detection | offline / online / whitelist / rejected — four states |
| Core / modded detection | vanilla · paper · spigot · forge · fabric · neoforge, etc. |
| masscan two-stage integration | Large-range masscan discovery → SLP probe |

### 🤖 Bot & Observer

| Feature | Description |
|---------|-------------|
| Login & send messages | Log into servers and send custom messages |
| AuthMe support | `auto` / `login_only` / `register_then_login` modes, branches based on server response |
| Multi-version adaptation | Protocol table auto-generated from minecraft-data (41 protocol versions) |
| Concurrent bots | Per-server limit configurable (`bot_threads`) |
| Observer mode | Real-time chat monitoring, keyword handling, logging to disk, exponential backoff reconnect |
| Premium account login | Microsoft OAuth device code flow, multi-account management |

### 🧠 AI Hosting (Experimental)

> Experimental feature, not loaded by default. Must be explicitly enabled in config.

| Feature | Description |
|---------|-------------|
| AI chat bot | Compatible with DeepSeek / OpenAI APIs |
| Preset personas | Multiple personas, editable in Web panel |
| Multi-AI group chat | Multiple bots interacting on the same server |
| Layered memory | Short-term raw + mid-term summary + long-term player profile (clearable anytime) |
| Safety guardrail | AI replies starting with `/` are blocked; API failures trigger automatic backoff |

> **Persona note**: all preset personas are "assistant"-themed (warm, cool-expert, sarcastic-but-helpful, chatty, lazy, gentle-guide, tech-nerd, optimistic, straight-shooter, storyteller, minimalist, curious-explorer — 12 total), with helpfulness as the baseline.
> They may **only** be used on servers you own or are explicitly authorised to test; messaging strangers' servers is harassment under
> [Prohibited](#-legal--ethics). The existing "guardrail" only blocks `/` commands and control chars — it is **not content moderation**.
> Implementation-wise, all persona text ends up in `core/ai_bot.py::_safe_send_chat`, which applies the
> single outbound filter (control-char stripping + `/` prefix blocking + 200-char length cap + newline blocking + 0.8s per-bot rate limit);
> persona injection **must not bypass** that filter.

### 🛡️ Scan Modes

| Mode | Concurrency | Rate | Use Case |
|------|------------|------|----------|
| `safe` | Low | Adaptive throttle | Public internet / authorized testing, gentle and slow |
| `balanced` | Medium | Moderate | Default mode, daily scanning |
| `aggressive` | High | Full speed | **Internal / trusted networks only** |

- **Multi-task concurrency**: Run multiple scan tasks simultaneously (`max_concurrent_scans`, default 2), excess auto-queued; bot login, favorite re-check, observer, AI, health monitor all run in parallel without blocking
- **Batch cooldown**: Pause between batches to reduce connection storms
- **Adaptive rate**: Auto-throttle on timeout spikes, pause/abort on connection anomalies
- **Resume**: `--resume` continues from last position after interruption (progress file has version check, corrupted files are rejected)

### 🌐 Web Panel

- Access at `http://127.0.0.1:8080` after startup
- **Login required**: first launch uses `admin` / `admin123` and **forces a password change** before you can operate anything; sessions last 7 days and live in browser localStorage
- **The page shell is public, every data endpoint needs a token**: `/api/*` requires `X-API-Token` (session token, or `web_token` from config); scripts may also pass `?token=`
- Before binding `0.0.0.0`, set `web_token` or change the default password — otherwise anyone on your network can log in
- Dark theme, **desktop / mobile responsive**
- One-stop management: scan tasks, observers, AI bots, premium accounts, database, favorites, player history
- Capability status badges always visible at top

### 🔒 Security & Ops

- **Capability toggles**: Scan (on by default) / login interaction / RCON commands (off by default)
- **Global read-only mode**: One-click lock on all write operations
- **Audit log**: Write operations record source, target, action, result
- Per-module API rate limiting; sensitive config supports `MC_*` environment variable override
- SLP probe cache to avoid duplicate probing

### 💓 Health Monitor (Favorites)

- Periodically probes favorited servers, records online/offline, player count, player joins/leaves; changes can be emailed
- **Gentle probe rate** (avoid rate-limiting/ban): concurrency ≤ `health_probe_concurrency` (default 8); same IP gap ≥ `health_probe_ip_gap` seconds (default 1.5); round interval `health_interval` seconds (default 300) — all adjustable in Web settings or `config.json`
- Uses fast mode (auto-version only, no full protocol iteration), 55 targets done in ~10 seconds; auto-complements auth detection when missing
- Also includes "popular" servers from database (max 20); set `health_monitor_db_extra: false` to monitor only favorites

---

## 🚦 Capabilities (Honest Assessment)

To avoid overpromising, here's what this version can and cannot do:

| Scenario | Status | Notes |
|----------|:------:|-------|
| Port scan / SLP info probe | ✅ Reliable | Main path, covers all versions |
| Offline server login + messaging | ✅ Reliable | Primary use case for security alerts |
| Online (premium) server login | ✅ Works | Requires Microsoft OAuth first |
| Premium server **chat** | ✅ Works | Auto-fetches Mojang-issued RSA cert after login, signs with RSA-2048+SHA256 via pycryptodome; falls back to unsigned on signature failure |
| Forge / Fabric / NeoForge modded servers | ⚠️ Partial | Can pass some acceptance tests as vanilla client; forced-mod-validation servers cannot be entered |
| Old versions (1.12.2 etc.) | ⚠️ Best effort | Protocol table covers and is tested, but edge cases remain |
| General Minecraft client | ❌ Not a goal | No full game controls / mod loading (chat signing is covered by the premium row above) |
| Unauthorized internet-wide scanning | 🚫 Forbidden | See [Legal & Ethics](#️-legal--ethics) |

---

## 🚀 Quick Start

### Installation

```bash
git clone https://github.com/IRmsk/mc-scanner-v3.git
cd mc-scanner-v3

# Install dependencies (flask required + pycryptodome for premium login)
pip install -r requirements.txt

# Optional: copy config template
cp config.example.json config.json
```

> **Dependencies**: No third-party libraries are vendored (the `libs/` directory has been removed). Install all via pip. `flask` is required for Web panel, `pycryptodome` for premium account login. `uvloop` / `pysimdjson` are optional speedups — auto-fallback if missing.

### Pre-built Bundles

This source repository ships **no** bundled dependencies — the former `libs/` directory has
been removed — and there is no build script for pre-built archives, so no verified download
link exists. Install from source instead:

```bash
pip install -r requirements.txt
python3 cli.py web --port 8080
```

Windows users can double-click `run.bat`; it installs dependencies from `requirements.txt`.

### Start Web Panel

```bash
python3 cli.py web --port 8080 --host 127.0.0.1
# Open http://127.0.0.1:8080 in browser
```

### Command-line Scan

```bash
# Single IP, all ports, safe mode
python3 cli.py scan 1.2.3.4 --port 1-65535 --mode safe

# Network range, balanced mode
python3 cli.py scan 192.168.1.0/24 --mode balanced

# Resume interrupted scan
python3 cli.py scan 1.2.3.4 --port 1-65535 --mode safe --resume

# Port scan only (no MC protocol probe)
python3 cli.py portscan 192.168.1.0/24 --port 1-65535

# masscan large-range port discovery (the CLI "scan" subcommand has no --use-masscan;
# that option only exists in the Web panel)
python3 cli.py masscan --targets 10.0.0.0/8 --port 25565 --rate 1000 --exclude exclude.conf
```

### Premium Account Login (Device Code)

1. Web panel → Settings → Premium Accounts → "Get Device Code"
2. Open `microsoft.com/link` in browser, enter the code, log in
3. Account auto-saved; manually check "Premium Verification" when using observer/AI

### Environment Variables (Sensitive Config)

```bash
MC_AI_API_KEY=your_key
MC_AI_BASE_URL=https://api.deepseek.com
MC_AI_MODEL=deepseek-chat
MC_DISCORD_WEBHOOK=your_webhook
MC_AUTHME_PASSWORD=your_password
```

### Exit Codes

| Code | Meaning |
|:----:|---------|
| 0 | Success |
| 1 | No results / failure |
| 2 | High-speed mode not confirmed |
| 3 | Parameter error (missing args / missing `--yes`) |
| 4 | Capability toggle denied |

---

## 📖 Beginner's Guide

### 1. Requirements

| Item | Requirement |
|------|-------------|
| Python | 3.10+ (3.12 recommended) |
| OS | Linux / macOS / Windows / Termux(Android) |
| Network | Can reach target servers and GitHub |
| Optional | masscan (large-range high-speed scanning) |

### 2. Installation

```bash
git clone https://github.com/IRmsk/mc-scanner-v3.git
cd mc-scanner-v3
pip install -r requirements.txt
python3 cli.py --help  # verify
```

If `pip install` fails (common on Termux/mobile):
```bash
pkg install python python-pip openssl
pip install flask pycryptodome
```

### 3. First Run

```bash
python3 cli.py web --port 8080 --host 127.0.0.1
```

Open `http://127.0.0.1:8080` — you'll see the dark panel. Bottom nav: Scan, Results, Favorites, Observer, AI, Auto, Library, History.

> **Termux/mobile users**: Run the command in Termux, then open `http://127.0.0.1:8080` in your phone browser. Panel is mobile-optimized.

### 4. Your First Scan

In the Web panel "Scan" tab:
1. Enter an IP or hostname (e.g. `1.2.3.4` or `mc.example.com`)
2. Port defaults to `25565`, can be a range `25565-25570`
3. Choose `safe` (public internet) or `balanced` (default)
4. Click "Start Scan"

Two stages:
- **Stage 1**: Port scan, find open ports
- **Stage 2**: SLP probe + auth detection, determine offline/online/whitelist

View results in "Results" tab, filter by auth mode, version, keyword.

CLI equivalent:
```bash
python3 cli.py scan 1.2.3.4 --mode safe
python3 cli.py scan 192.168.1.0/24 --mode balanced
```

### 5. Observer Mode

Observer = log in as a bot, watch chat and player joins/leaves in real-time, can send messages.

Click "Observe" on any server in Results or Observer tab:
- Enter a username (e.g. `WatchDog`)
- Offline servers connect directly; premium servers need Microsoft account setup (see §6)
- Once in, type messages in the input box; chat auto-saved
- Click "Disconnect" to exit; records exportable as TXT/HTML

CLI equivalent:
```bash
python3 cli.py bot 1.2.3.4:25565 -u WatchDog -m "Hello" --hold 10
```

### 6. Premium Account (Microsoft)

To join premium servers, complete Microsoft OAuth:

1. Web panel → Settings (top-right) → Premium Accounts → "Get Device Code"
2. Terminal shows a device code and URL `microsoft.com/link`
3. Open the URL, enter the code, log in to your Microsoft account
4. Account auto-saved; check "Premium Verification" when joining servers

> Premium login requires `pycryptodome` (in requirements.txt). Chat signing uses RSA-2048+SHA256 with Mojang-issued certificates.

### 7. Single-Server Bot

Log in to a specific server and send custom messages:

```bash
# Log in to a single server and send messages
python3 cli.py bot 192.168.1.10:25565 -u SecurityBot \
  -m "Hello, I'm a friendly security scanner bot" \
  -m "Your server is in offline mode — consider enabling online-mode=true"
```

Servers with AuthMe: use `--authme password` for auto register/login, `--register` for new user registration.

### 8. Favorites & Health Monitor

- Star servers in Results tab to favorite them
- Favorites tab manages them, filter by auth mode / has players
- Health monitor periodically probes favorited servers, records player count changes, can email notifications
- Player trend chart in Favorites tab, click 📈 to view

### 9. Configuration

`config.json` (auto-generated on first run) key fields:

The table below matches `config.py`'s `DEFAULT_CONFIG` (and `config.example.json`):

| Field | Default | Description |
|-------|---------|-------------|
| `username` | `SecurityBot` | Default bot username |
| `messages` | `null` | Default warning messages; built-in text used when empty |
| `ports` | `[25565]` | Default scan ports |
| `scan_threads` | `50` | Port scan threads |
| `scan_timeout` | `3.0` | Per-target timeout (seconds) |
| `workers` | `16` | SLP probe threads |
| `timeout` | `5.0` | SLP probe timeout (seconds) |
| `bot_threads` | `5` | Bot concurrency |
| `bot_timeout` | `15` | Bot timeout (seconds) |
| `message_delay` | `1.2` | Delay between messages (seconds) |
| `rate` | `30` | Global rate (requests per second) |
| `authme_password` | `""` | AuthMe auto-login password |
| `exclude_file` | `exclude.conf` | Exclude list file |
| `db_path` | `mcscanner.db` | SQLite database path |
| `web_host` / `web_port` | `127.0.0.1` / `8080` | Web panel bind address / port |
| `log_level` | `INFO` | Log level |
| `bot_threads` | `5` | Concurrent bot limit |
| `health_interval` | `300` | Health monitor poll interval (seconds) |
| `health_probe_concurrency` | `8` | Health monitor parallel probes |
| `health_probe_ip_gap` | `1.5` | Min gap between probes of the same IP (seconds) |

The full set of defaults lives in `config.py`'s `DEFAULT_CONFIG`. Sensitive config can also be overridden via environment variables: `MC_AI_API_KEY`, `MC_DISCORD_WEBHOOK`, etc.

### 10. FAQ

**Q: `ModuleNotFoundError: No module named 'flask'`**
A: Dependencies not installed. Run `pip install -r requirements.txt`

**Q: Can't join premium server, `authservers_down`**
A: Mojang auth servers temporarily unavailable. Wait a few minutes and retry; check if your network can reach `authserver.mojang.com`

**Q: Kicked for `chat.disabled.missingProfileKey`**
A: Server enforces secure profiles. Must use a premium account (§6). Offline accounts cannot chat on enforce-secure-profile servers.

**Q: Kicked for `Packet chat was larger than expected`**
A: Chat packet format compatibility issue on some server versions. Under investigation — try a different server.

**Q: Can't connect to NeoForge/Forge modded servers**
A: Forced-mod-validation servers require the client to send a mod list. A vanilla client cannot enter. Servers with "allow vanilla clients" enabled can be joined.

**Q: Scan progress bar stuck**
A: Small targets (<100) scan very quickly, bar may jump straight to 100%. For large targets use `--workers` to increase concurrency.

**Q: `pip install` compile failure on Termux**
A: Run `pkg install python openssl`, then install pure-Python packages only: `pip install flask pycryptodome`, skip `cryptography` (pycryptodome covers it).

### 11. Uninstall

```bash
# Stop the service, then delete the directory
rm -rf mc-scanner-v3
# Database and config are inside, deleted together
```

---

## 🧩 Project Structure

```text
mc-scanner-v3/
├── cli.py                  # CLI entry point
├── config.py               # Config management
├── core/
│   ├── bot.py              # Minecraft bot core
│   ├── conn.py             # Connection layer (encryption / protocol)
│   ├── probe.py            # SLP / auth probing
│   ├── protocol.py         # Version mapping / protocol constants
│   ├── packets.py          # Protocol table loading & integrity check
│   ├── packets_auto.json   # Auto-generated protocol table (40 versions, pure data)
│   ├── microsoft_auth.py   # Microsoft OAuth premium login
│   ├── ed25519.py          # Pure-Python Ed25519 signing (zero deps)
│   ├── errors.py           # Unified error codes & mapping
│   ├── nbt.py / chat.py    # NBT / JSON text parsing
│   ├── buffer.py           # Byte stream utilities
│   ├── rcon.py             # RCON remote console
│   ├── command_runner.py   # Command executor
│   ├── plugins.py          # Plugin / anti-cheat detection
│   ├── fingerprint.py      # Server fingerprinting
│   ├── ai_bot.py           # AI bot session
│   ├── ai_memory.py        # AI layered memory
│   ├── ai_personas.py      # AI persona presets
│   └── protocols/          # Per-version protocol handlers
├── scanner/
│   ├── safe.py             # Safe scan config / progress storage
│   ├── async_engine.py     # Async pipeline
│   ├── portscan.py         # Sync port scan
│   └── engine.py           # Scan engine
├── web/
│   ├── app.py              # Flask app
│   ├── index.html          # Frontend panel (desktop / mobile)
│   ├── state.py            # Shared state
│   └── routes_*.py         # Per-module API routes
├── service/                # Scan / warn task services
├── storage/                # Favorites persistence
├── tools/
│   ├── gen_packets.py      # Auto-generate protocol table
│   ├── get_mc_token.py     # Premium device code tool
│   └── send_command.py     # Command sender (authorized, use with care)
├── distributed/            # ⚠️ Experimental: distributed sharding
├── android_patches/        # ⚠️ Experimental: Android/Kivy packaging patch (PythonActivity.java)
├── tests/                  # Unit / integration tests
├── config.example.json     # Config template
├── requirements.txt        # Dependencies
├── LICENSE                 # GPL-3.0
└── README.md
```

---

## 🧪 Tests

```bash
python3 -m pytest tests/ -q
```

The test count is whatever CI reports — no hand-maintained number here. Coverage: protocol table integrity, version mapping, auth probing, Login Start segmentation, Client Settings segmentation, AuthMe branching, progress storage, AI safety guardrails, failure paths, no-reported-protocol fallback, etc.

Regenerate protocol table:

```bash
python3 tools/gen_packets.py --download
```

---

## 📜 Changelog

<details>
<summary><b>v3.6.5</b></summary>

Security audit maintenance fixes — 8 commits, 101 files, tests 193 → 212.

**Protocol**
- **Decompression bomb**: `zlib.decompress` replaced with `decompressobj().decompress(data, max_length)`, 8MB cap now actually enforced (previously checked server-reported `data_length`, which can lie)
- **VarInt**: Limited to 5 bytes (previously 6th byte was accepted before the check), added int32 sign extension (`0xFFFFFFFF` correctly returns -1, not 4294967295)
- **NBT List count**: Validates count ≤ remaining stream bytes, malicious server sending `count=0x7FFFFFFF` no longer spins for minutes
- **Packet ID mismatch**: 770-772 hand-written table narrowed to just 770, 771/772 now use auto table (previously 1.21.5 IDs overwrote 1.21.6+, causing wrong keep-alive replies and kicks)

**Scanner**
- **Safe mode concurrency**: No longer hardcodes `slp_concurrency=400`, uses profile defaults (previously safe mode actually ran at 400 concurrency, 20x the designed value)
- **Port expansion DoS**: `parse_ports_spec` clamps to 1-65535 first, stops at max_ports, no longer materializes full range (`1-50000000` previously consumed GBs of RAM)
- **fd leak**: async_probe timeout/exception branches now close writer in finally
- **Cross-event-loop lock**: `_rate_lock` created per-run, no longer bound to first loop causing silent failure on second `asyncio.run`
- **Malformed banner crash**: version/players non-dict now has isinstance fallback
- **Async path exclude table**: cli.py async entry unified through `parse_and_filter_targets`, private/reserved ranges no longer bypassed
- **masscan results persist**: Previously masscan branch called `probe_list()` (comment explicitly said "don't save to DB"), now explicitly `db.upsert_many`

**Web / Frontend**
- **Stored XSS**: Auto-scan log `innerHTML` concatenation now uses `escapeHtml` (logs contain server-controlled MOTD/version)
- **Reflected XSS**: `/auth-response` error/err_desc/name all escaped
- **SSRF + key leak**: AI request base_url no longer overridable by request, uses config only
- **services_assistant dead code**: Previously created its own thread calling non-existent `ScanEngine(targets=..., run())` + accessing non-existent `scan_state["stop_event"]`, natural-language scan chain crashed 100%. Now calls `services_scan.start_scan_task`
- **warn KeyError**: Exception branches now include `messages_sent: 0`, no more `sum(r["messages_sent"])` 500
- **scan_tasks memory leak**: Tasks evicted after completion, no longer hold full results indefinitely
- **Capability gates**: `/api/auto_scan/add`, random internet-wide scan now check capability/read_only
- **Observer log lock**: `_ensure_log_file`/`_append_log`/`_next_seq` locked, prevents concurrent fd leak/seq duplication
- **Health monitor state race**: `del status[k]` locked, status endpoint uses snapshot

**Bot / AI**
- **AI `/` interception bypass**: `send_message`/`send_to_all`/opener now all go through `_safe_send_chat`, no longer bypass slash-command interception
- **SMTP cert verification**: `ssl._create_stdlib_context()` (CERT_NONE) replaced with `ssl.create_default_context()`, prevents MITM stealing email credentials
- **Ghost players**: AI bot duration/reconnect-limit branches now close() in finally before returning
- **auto_scanner resource caps**: targets/ports have size limits, `ai_hijack` deduplicated + handles retained + capped

**Storage**
- **Favorites lost updates**: `_write_atomic` uses `mkstemp` + `os.replace`, no more read-modify-write race across calls
- **rescan_all lock-held I/O**: Network probing moved out of critical section (previously `add_favorite` blocked for 5.68 seconds)
- **SQLite connection leak**: Connection pool cap + LRU, db_path fixed not from request
- **JSON truncation**: Semantically truncated to guarantee valid JSON, no more character-wise 2000 truncation producing invalid JSON
- **Shard race**: `claim_shard` read-modify-write uses file lock, `job_id` regex validated against path traversal

**CLI / Docs**
- **Single source version**: run.bat reads from `config.__version__`, no longer hardcoded 3.6.3
- **run.bat dependency check**: Changed to `import flask` (previously checked `libs\flask\__init__.py` which never existed after libs deletion, causing always-reinstall and only installing flask, missing pycryptodome)
- **config.example.json**: Aligned with DEFAULT_CONFIG

**Still broken**

- Some offline servers kick with "Packet chat was larger than expected": still under investigation
- Some protocol versions (e.g. 776) auto-generated table lacks Configuration segment, falls back to hand-written constants
- Forced-mod-validation Forge/NeoForge servers can't connect (vanilla client hard limit)
- Auth not restored: `_check_auth` remains a no-op by design — tool is intended for local 127.0.0.1 use; binding to 0.0.0.0 is risky

</details>

<details>
<summary><b>v3.6.4</b></summary>

This release is mostly bug fixes and cleanup, no new features.

**Fixed**

- **NeoForge detection**: NeoForge 1.20.2+ doesn't expose forgeData in SLP, was misidentified as vanilla. Now corrected via `neoforge:login` channel during login handshake. Note: only works when auth detection is enabled; forced-mod-validation NeoForge servers still can't be joined (hard limit, not a bug)
- **Player trend chart not rendering**: Dumb mistake — chart container was `<div>` not `<canvas>`, leftover `<p>` tag from empty-state caused Chart.js init failure. Now clears div before creating canvas
- **Scan progress bar stuck**: Adaptive rate limiter's initial rate was overridden by profile default, initial batch of 200 was too large for small targets. Fixed: initial rate = min(user config, cap), batch = max_workers*2, dynamic progress step
- **Config path stacking**: When config.json is in a subdirectory, saving once added an extra path layer. Unified to config file's own directory as base
- **No more vendored deps**: Deleted entire `libs/` directory (Flask + deps, ~2.6MB), all via `pip install -r requirements.txt`. Previous uvloop/simdjson empty shells also removed
- **Code hygiene**: 8 `raise` statements got `from e`, one test assertion added, test cleanup for observer_logs, 21 unused imports cleared, PWA cache versioned

**Still broken**

- Some offline servers kick with "Packet chat was larger than expected": under investigation, payload hex debug logging added, root cause not yet found
- Some protocol versions (e.g. 776) auto-generated table lacks Configuration segment, falls back to hand-written constants, may cause connection issues on new servers
- Forced-mod-validation Forge/NeoForge servers can't connect (requires client to send mod list, vanilla client can't)

</details>

<details>
<summary><b>v3.6.3</b></summary>

**Chat fixes (core)**
- Fixed observer not receiving chat on 1.21 (proto 767): `extract_chat_text` incorrectly skipped `globalIndex` field (added in 1.21.2/768), causing byte misalignment and empty text. Messages were always broadcast, just not parsed
- Removed workarounds from wrong diagnosis: offline account `/me` fallback, self-signed Chat Session (harmful to offline accounts — server receives unverifyable key and silently drops subsequent unsigned messages)

**Premium signed chat (RSA-2048+SHA256)**
- Minecraft 1.19+ chat signing actually uses **RSA-2048 + SHA256 PKCS#1 v1.5** (not Ed25519), Mojang `/player/certificates` returns RSA keypair
- `_build_signed_chat` uses pycryptodome for RSA-SHA256, signature data = sender UUID(16) + timestamp(8) + salt(8) + message(UTF-8)
- 766+ (1.20.5+) signature field is fixed 256-byte buffer, no varint length prefix
- Offline servers don't fetch certs or send Chat Session (offline UUID doesn't match premium cert UUID, sending gets kicked for invalid_public_key_signature)
- Fixed Chat Session / signed chat base64 decode `Incorrect padding`: Mojang keys may lack trailing `=` padding, auto-completed before decode

**Auth state machine hardening**
- `auth_mode` initialized to `unknown` in `__init__`, Play success only marks offline if unknown (premium accounts that passed Encryption keep online, no longer overwritten)
- Bot and probe whitelist keywords aligned (whitelist / white list / not white-listed / not whitelisted / 白名单 / 不在白名单 / not on the whitelist)
- `join_and_warn` exception path uses `BotError.code` (WHITELIST / ONLINE_MODE_REQUIRED / BANNED / KICKED / INCOMPATIBLE_VERSION), no more string scanning
- neoforge split from forge pattern into separate category
- plugin_channels data flow connected: auth_probe returns and persists, aids Forge/modded detection
- No-reported-protocol cross-era fallback (775/767/763/761/754/340), not just latest 3 versions
- `fingerprint_server` renamed to `fingerprint_by_field_order`, avoids name clash with `core/fingerprint.py`

**Security hardening**
- `msa_refresh_token` and other sensitive tokens masked, prefix narrowed to 2 chars
- Fixed two stored XSS (logBox, observer cards)

**AI & Observer**
- AI Bot ignores identical content within 10 seconds, no more talking to itself
- Observer chat records grouped by date, IP-searchable, zero-message records manually deletable

**Favorites & Health Monitor**
- Favorite player count shows `online/max` format (e.g. 2/20) with player names
- Favorites filter adds auth mode (premium/offline) and has players/no players
- Player trend chart moved to Favorites tab
- Health monitor auto-complements auth detection when missing

**Web Panel**
- Close service button added top-right
- Mobile UI optimization

</details>

<details>
<summary><b>v3.6.2</b></summary>

**Fixes & improvements**
- Fixed 1.19.3–1.20.4 protocol layer bugs (Login Start byte segmentation, Client Settings field segmentation)
- Health monitor fast mode, no longer iterates 19 protocol versions, 10x speedup
- AI Bot truly identifies its own messages via UUID, no more talking to itself
- Premium login auto-syncs actual server username, supports Ed25519 signed chat
- Database page adds import/clear/favorite buttons, favorite list sorted by whitelist priority
- Favorite player count shows online/max with player names
- Web panel close service button
- Removed login auth (local tool), README honestly describes

</details>

<details>
<summary><b>v3.6.1</b></summary>

**Favorites & Health Monitor**
- Favorites retain last online info (`last_good_info`), offline re-check/monitor no longer overwrites
- Health monitor concurrent probing, cleans residual state by monitor list, events judged by online status (empty server boot no longer missed)
- Health monitor supports Web panel poll interval config, manual "check now", per-server probe real-time updates
- Favorite file atomic write + concurrent write lock, monitor write-back skips when unchanged

</details>

<details>
<summary><b>v3.6.0</b></summary>

**Scan engine**
- `safe` / `balanced` / `aggressive` three modes
- Batch cooldown, adaptive throttle, connection anomaly detection, resume

**Protocol foundation**
- Protocol table auto-generated from minecraft-data (40 versions), integrity check before release
- Version mapping calibrated and locked with unit tests
- Configuration phase packet IDs from auto table

**AI features**
- Layered memory system, persona editing, auto-reconnect
- AI reply command interception, API failure backoff, clearable memory

**Premium login**
- Microsoft OAuth device code flow, multi-account management
- All join entry points support premium verification toggle (manual check)
- ⚠️ Does not send real chat signatures, enforce-secure-profile servers may reject

**Security hardening**
- Capability toggles, global read-only, audit log, API rate limiting

</details>

<details>
<summary><b>v3.4.0</b></summary>

- Web panel modular split (multiple route modules + service layer)
- Web UI visual upgrade + mobile adaptation
- AI assistant floating window, health monitor email, player history chart

</details>

---

## ⚖️ Legal & Ethics

> This section is a **hard constraint** for using this tool, not optional.

### ✅ Legal Use

- **Security research / authorized testing**: Assess target systems under explicit (preferably written) authorization
- **Own asset inspection**: Scan and manage servers you own or host
- **Internal education**: Learn networking and protocols on isolated private networks

### 🚫 Prohibited

- Port scanning, probing, or vulnerability scanning of **unauthorized** servers
- Logging into unauthorized servers (including offline servers) or accessing their data
- Executing `/op`, `/gamemode`, `/ban`, `/stop` or any commands on unauthorized servers
- Connecting RCON to unauthorized servers
- DDoS, botnets, spam, or any form of denial-of-service / harassment
- Collecting or disseminating third-party server player data, IPs, or personal information
- Bypassing or breaking firewalls, whitelists, premium verification, or other security measures

### 🔐 Data Privacy

- The tool does not upload your scan data or config to any third party
- Scan results are stored locally, managed by you
- Do not commit results or credentials containing real IPs / player info to public repos
- `.gitignore` excludes `*.db`, `*.json`, and other data/credential files by default

<details>
<summary><b>📖 Relevant legal references (China mainland)</b></summary>

Unauthorized scanning, login, or control of computer information systems may involve:

- Criminal Law of the PRC Article 285 — Illegal intrusion into computer information systems, illegal acquisition of computer information system data, **providing intrusion/illegal control programs or tools**
- Criminal Law Article 286 — Destroying computer information systems
- Criminal Law Article 287(2) — Assisting information network criminal activities
- Cybersecurity Law of the PRC
- Data Security Law of the PRC
- Personal Information Protection Law of the PRC

In other countries/regions, comply with local laws on computer misuse, unauthorized access, and data protection (e.g. CFAA, GDPR).

</details>

<details>
<summary><b>📝 Disclaimer</b></summary>

- This tool is provided "as is," author makes no warranty of fitness, reliability, or safety
- Users bear all legal responsibility and consequences of using this tool
- Author is not liable for any direct or indirect damages from using this tool
- If you disagree with these terms, stop using and delete this tool immediately
- The above is general information, not legal advice; consult a licensed attorney for specific cases

</details>

---

## 📄 License

This project is released under the [GNU GPL v3.0](LICENSE). Any use, modification, or distribution must remain open-source under the same license.

<div align="center">

**Use within authorized scope. Happy & Safe Scanning. 🟢**

</div>
