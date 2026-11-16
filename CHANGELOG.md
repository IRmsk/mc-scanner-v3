# Changelog

Version history for MC Scanner v3, newest first. Entries are the author's release notes, preserved verbatim.

---

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
