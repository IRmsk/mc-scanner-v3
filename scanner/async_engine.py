# -*- coding: utf-8 -*-
"""
异步综合扫描引擎：端口扫描 → SLP 探测 → 认证检测，流水线并行。
端口一开就立刻 SLP 探测，不用等全部端口扫完。
比同步两阶段引擎快 5-10 倍。
"""
import asyncio
import concurrent.futures
import threading
import time
from typing import Optional

import logger
from scanner.async_portscan import _check_port, has_uvloop
from scanner.async_probe import async_auth_probe, async_slp_probe, has_simdjson
from storage import db

# SLP 并发默认值 / safe 模式上限
SLP_CONCURRENCY_DEFAULT = 200
SLP_CONCURRENCY_SAFE = 20
# 批量写库批次大小
SAVE_BATCH_SIZE = 100


class AsyncScanEngine:
    """异步综合扫描引擎"""

    def __init__(self, db_path: str = "mcscanner.db",
                 concurrency: int = None,
                 slp_concurrency: int = None,
                 timeout: float = 4.0,
                 auth_check: bool = True,
                 rate_limit: int = None,
                 stop_event: Optional[threading.Event] = None,
                 fingerprint: bool = False,
                 mode: str = None, shuffle: bool = None,
                 batch_cooldown: float = None,
                 progress_file: str = None,
                 exclude_file: str = None):
        self.db_path = db_path
        # v3.6.0: 并发/速率 None 时按扫描模式取默认
        from scanner.safe import get_profile
        self._profile = get_profile(mode)
        self.concurrency = concurrency if concurrency is not None else self._profile.concurrency
        # SLP 并发：safe 模式必须压低（大量 SLP 请求同样会触发封禁）。
        # 旧实现只在"调用方恰好传 200"时降级，传 400 或其它值都会绕过保护；
        # 现改为按模式封顶，不再依赖默认值恰好相等。
        self.slp_concurrency = self._resolve_slp_concurrency(slp_concurrency)
        self.timeout = timeout
        self.auth_check = auth_check
        self.rate_limit = rate_limit if rate_limit is not None else self._profile.rate
        self.stop_event = stop_event
        self.fingerprint = fingerprint  # 主动协议指纹（异步引擎暂未实现，预留）
        self.mode = mode
        self.shuffle = shuffle
        self.batch_cooldown = batch_cooldown
        self.progress_file = progress_file
        self.exclude_file = exclude_file
        self.results = []
        self.counters = {
            "total": 0, "up": 0, "cracked": 0, "online": 0,
            "whitelist": 0, "rejected": 0, "offline": 0, "error": 0,
        }
        self._lock = threading.Lock()
        self._start_time = None
        self._excluder = None

    def _resolve_slp_concurrency(self, slp_concurrency: Optional[int]) -> int:
        """SLP 并发解析：None 用默认值，safe 模式统一封顶到 SLP_CONCURRENCY_SAFE"""
        if slp_concurrency is None:
            slp_concurrency = SLP_CONCURRENCY_DEFAULT
        if self._profile.mode == "safe" and slp_concurrency > SLP_CONCURRENCY_SAFE:
            print(f"[*] safe 模式：SLP 并发 {slp_concurrency} → {SLP_CONCURRENCY_SAFE}")
            return SLP_CONCURRENCY_SAFE
        return slp_concurrency

    def _get_excluder(self):
        """惰性构建排除表（exclude_file=None 时不启用）"""
        if self._excluder is None and self.exclude_file:
            with self._lock:
                if self._excluder is None:
                    from scanner.exclude import Excluder
                    self._excluder = Excluder(self.exclude_file)
        return self._excluder

    def _filtered_targets(self, targets):
        """按 exclude_file 过滤目标。

        旧实现：cmd_scan 的异步路径完全不做排除表过滤，私网/保留段会被静默扫描，
        这里在引擎侧补齐（排除表为空时 Excluder 会退回默认私有段）。
        """
        excluder = self._get_excluder()
        if excluder is None or not excluder.networks:
            return targets
        return excluder.filter_targets(iter(targets))

    async def _acquire_rate(self, rate_state):
        """全局令牌桶限速：确保全局速率不超过 rate_limit/s。

        lock/last 由每次扫描创建（rate_state 传入）：旧实现把 Lock 缓存在 self 上，
        复用同一引擎实例第二次 asyncio.run 时会报
        "Lock is bound to a different event loop"，异常还会被 gather 静默丢弃。
        """
        if self.rate_limit <= 0:
            return
        min_interval = 1.0 / self.rate_limit
        async with rate_state["lock"]:
            now = time.time()
            wait = rate_state["last"] + min_interval - now
            if wait > 0:
                await asyncio.sleep(wait)
            rate_state["last"] = time.time()

    def _bump(self, key: str, n: int = 1):
        with self._lock:
            if key in self.counters:
                self.counters[key] += n

    def _print_progress(self, done: int):
        with self._lock:
            c = dict(self.counters)
        elapsed = time.time() - self._start_time if self._start_time else 0
        speed = done / elapsed if elapsed > 0 else 0
        print(f"[{done:>7}] {speed:.0f}/s | up={c['up']} cracked={c['cracked']} "
              f"online={c['online']} whitelist={c['whitelist']} "
              f"rejected={c['rejected']} offline={c['offline']} error={c['error']}")

    async def _write_batch(self, batch: list, write_executor):
        """批量写库：固定单线程 executor 串行化，避免多批次并发写同一 SQLite。

        写失败必须留痕：旧实现批量路径有 logger.warning，收尾 flush 却是
        except: pass，最后不足一批的结果会无声丢失。
        """
        loop = asyncio.get_running_loop()
        try:
            await loop.run_in_executor(write_executor, db.upsert_many, self.db_path, batch)
        except Exception as e:
            logger.warning(f"异步写库失败({len(batch)}条): {e}")

    def _collect(self, done_batch):
        """收集 gather 结果：非 dict（异常对象）必须记录，不能静默丢弃。

        旧实现用 isinstance(r, dict) 直接过滤，跨 event loop 等任务异常就这样消失，
        表现为"扫描完成但结果几乎为空、且无任何报错"。
        """
        for r in done_batch:
            if isinstance(r, dict):
                self.results.append(r)
            else:
                logger.warning(f"异步任务异常: {r!r}")
                self._bump("error")

    async def _probe_target(self, ip: str, port: int,
                            port_sem: asyncio.Semaphore,
                            slp_sem: asyncio.Semaphore,
                            save_queue: list,
                            rate_state: dict,
                            write_executor) -> dict:
        """单目标完整探测：端口 → SLP → 认证。"""
        if self.stop_event and self.stop_event.is_set():
            return {"ip": ip, "port": port, "state": "cancelled"}

        # 阶段1：端口扫描（_check_port 内部已用 port_sem 控制并发，外层不再重复获取）
        await self._acquire_rate(rate_state)
        port_result = await _check_port(ip, port, self.timeout, port_sem)

        self._bump("total")

        if not port_result.is_open:
            self._bump("offline")
            return {"ip": ip, "port": port, "state": "offline",
                    "error": port_result.error}

        # 阶段2：SLP 探测（端口一开就立刻探测，流水线）
        async with slp_sem:
            try:
                slp = await async_slp_probe(ip, port, self.timeout)
            except Exception as e:
                self._bump("error")
                return {"ip": ip, "port": port, "state": "error", "error": str(e)[:100]}

        if slp.get("state") != "up":
            self._bump("offline")
            return {"ip": ip, "port": port, "state": "offline",
                    "error": slp.get("error", "")}

        result = {
            "ip": ip, "port": port,
            "version": slp.get("version", ""),
            "proto": slp.get("proto", 0),
            "motd": slp.get("motd", ""),
            "ping_ms": slp.get("ping_ms"),
            "favicon": slp.get("favicon", ""),
            "core_type": slp.get("core_type", "unknown"),
            "mods": slp.get("mods", []),
            "forge_channels": slp.get("forge_channels", []),
            "players_online": slp.get("online", 0),
            "players_max": slp.get("max", 0),
            "player_list": [p.get("name", "") for p in slp.get("sample", [])],
            "state": "up",
        }
        ct = result["core_type"]
        result["is_modded"] = 1 if ct in ("forge", "fabric", "neoforge", "quilt") else 0
        result["is_plugin"] = 1 if ct in ("paper", "spigot", "bukkit", "purpur",
                                          "catserver", "arclight") else 0
        result["server_type"] = ct if ct != "unknown" else (
            "modded" if result["is_modded"] else
            ("plugin" if result["is_plugin"] else "vanilla"))
        self._bump("up")

        # 阶段3：认证检测
        if self.auth_check:
            try:
                auth = await async_auth_probe(ip, port, result.get("proto", 0),
                                              self.timeout)
                result["auth"] = auth["state"]
                result["auth_detail"] = auth.get("detail", "")
                result["plugin_channels"] = auth.get("plugin_channels", [])
                if auth.get("detected_proto"):
                    result["proto"] = auth["detected_proto"]
                # NeoForge/Forge 1.20.2+ 不在SLP暴露forgeData，用登录频道修正core_type
                _ch = result["plugin_channels"]
                if _ch and result.get("core_type") in ("vanilla", "unknown"):
                    for c in _ch:
                        cl = str(c).lower()
                        if "neoforge" in cl:
                            result["core_type"] = "neoforge"
                            result["is_modded"] = 1
                            result["server_type"] = "neoforge"
                            break
                        if "fml" in cl or "forge" in cl:
                            result["core_type"] = "forge"
                            result["is_modded"] = 1
                            result["server_type"] = "forge"
                            break
                self._bump(result["auth"])
            except Exception:
                result["auth"] = "unknown"

        # 存入保存队列
        save_queue.append(result)
        if len(save_queue) >= SAVE_BATCH_SIZE:
            batch = save_queue[:]
            save_queue.clear()
            await self._write_batch(batch, write_executor)

        return result

    async def _scan_async(self, targets) -> list:
        """异步扫描主循环。"""
        db.init_db(self.db_path)
        # 每次扫描重置结果集与计数器：旧实现 self.results 只增不减，
        # 同一引擎实例复用（Web 长时间运行）时内存随扫描次数无界增长，
        # 进度里的统计数字也会把上一轮的算进来
        self.results = []
        with self._lock:
            for k in self.counters:
                self.counters[k] = 0
        self._start_time = time.time()
        port_sem = asyncio.Semaphore(self.concurrency)
        slp_sem = asyncio.Semaphore(self.slp_concurrency)
        save_queue = []
        tasks = []
        done = 0
        # 限速状态与写库线程按次创建：跨 asyncio.run 复用 self 上的 Lock 会抛
        # "bound to a different event loop"（详见 _acquire_rate）
        rate_state = {"lock": asyncio.Lock(), "last": 0.0}
        write_executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="async-db")
        targets = self._filtered_targets(targets)

        try:
            for ip, port in targets:
                if self.stop_event and self.stop_event.is_set():
                    break
                tasks.append(asyncio.create_task(
                    self._probe_target(ip, port, port_sem, slp_sem, save_queue,
                                       rate_state, write_executor)))

                # 控制任务数量，避免百万级目标一次性创建太多协程
                if len(tasks) >= 5000:
                    # return_exceptions: 单个任务异常不拖垮整批
                    done_batch = await asyncio.gather(*tasks, return_exceptions=True)
                    self._collect(done_batch)
                    done += len(done_batch)
                    tasks = []
                    if done % 1000 == 0:
                        self._print_progress(done)

            if tasks:
                done_batch = await asyncio.gather(*tasks, return_exceptions=True)
                self._collect(done_batch)
                done += len(done_batch)

            # 保存剩余（与批量路径同一套错误处理，不再静默吞错）
            if save_queue:
                batch = save_queue[:]
                save_queue.clear()
                await self._write_batch(batch, write_executor)
        finally:
            write_executor.shutdown(wait=True)

        self._print_progress(done)
        elapsed = time.time() - self._start_time
        print(f"[*] 异步扫描完成: {done} 个目标, {elapsed:.1f}s, "
              f"{done/elapsed:.0f}/s")
        return self.results

    def scan(self, targets) -> list:
        """同步入口：启动事件循环执行异步扫描。

        已在事件循环内时返回 coroutine，由调用方 await（与旧行为一致）；
        推荐异步上下文直接 await engine.scan(...)。
        """
        async def _run():
            return await self._scan_async(targets)

        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(_run())
        return _run()

    def scan_with_portscan(self, targets, scan_concurrency: int = None,
                           scan_timeout: float = 2.5, progress_callback=None) -> list:
        """两阶段扫描（端口扫描 + SLP探测），异步版本。"""
        from scanner.async_portscan import get_open_ports_async, scan_ports_async
        print(f"[*] 异步流水线扫描（并发={self.concurrency}, SLP并发={self.slp_concurrency}）")
        print(f"[*] uvloop: {'启用' if has_uvloop() else '未安装'}, "
              f"simdjson: {'启用' if has_simdjson() else '未安装'}")
        # 阶段1: 异步端口扫描（并发 None 时按模式默认，避免硬编码覆盖 safe 并发）
        print("[*] 阶段1: 异步端口扫描...")
        # 异步路径同样要应用排除表：旧实现只给同步路径过滤，私网/保留段会被静默扫描
        targets = self._filtered_targets(targets)
        port_results = scan_ports_async(
            targets,
            concurrency=scan_concurrency if scan_concurrency is not None else self.concurrency,
            timeout=scan_timeout,
            rate_limit=self.rate_limit,
            stop_event=self.stop_event,
            progress_cb=progress_callback,
            mode=self.mode,
            shuffle=self.shuffle,
            batch_cooldown=self.batch_cooldown,
            progress_file=self.progress_file,
        )
        if asyncio.iscoroutine(port_results):
            # 本方法是同步入口，不能在已有事件循环里 await；明确报错而不是泄漏协程
            port_results.close()
            raise RuntimeError(
                "AsyncScanEngine.scan_with_portscan() 是同步入口，"
                "不能在运行中的事件循环里调用；请在独立线程中调用或直接 await engine.scan(...)")
        open_ports = get_open_ports_async(port_results)
        print(f"[*] 发现 {len(open_ports)} 个开放端口")
        if not open_ports or (self.stop_event and self.stop_event.is_set()):
            return []
        # 阶段2: 对开放端口做SLP+认证探测
        print("[*] 阶段2: SLP探测 + 认证检测...")
        return self.scan(iter(open_ports))


def run_async_scan(targets, **kwargs) -> list:
    """便捷函数：创建异步引擎并扫描。"""
    engine = AsyncScanEngine(**kwargs)
    return engine.scan(targets)
