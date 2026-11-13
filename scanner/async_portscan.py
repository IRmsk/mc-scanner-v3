# -*- coding: utf-8 -*-
"""
异步端口扫描：asyncio + Semaphore 控制并发。
比线程池快 3-5 倍，支持万级并发，内存占用更低。
可选 uvloop 加速（Linux）。
"""
import asyncio
import socket
import time
from dataclasses import dataclass, replace

from scanner.safe import AdaptiveRateController, ScanProgressStore, get_profile, iter_shuffled_chunks


async def _open_connection(ip, port, timeout):
    """异步建立TCP连接，支持全局代理（有代理时走线程池+代理连接）。
    本地/私有地址（127/10/172.16/192.168）自动绕过代理直连。"""
    import ipaddress

    from core.conn import get_global_proxy
    proxy = get_global_proxy()
    # 本地/私有地址不走代理（否则会连到代理服务器的本地）
    if proxy is not None:
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback or addr.is_link_local:
                proxy = None
        except ValueError:
            pass
    if proxy is None:
        return await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)

    # 有代理：在线程池里用同步socket建立代理连接，再包装成asyncio
    def _connect_via_proxy():
        from core.conn import _connect_via_http, _connect_via_socks5
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(timeout)
            if proxy.proto == "socks5":
                _connect_via_socks5(sock, proxy.host, proxy.port, ip, port,
                                    proxy.username, proxy.password)
            else:
                _connect_via_http(sock, proxy.host, proxy.port, ip, port,
                                  proxy.username, proxy.password)
        except Exception:
            # 代理握手失败必须关闭 socket：旧实现直接抛错，每个失败连接泄漏一个 fd
            try:
                sock.close()
            except Exception:
                pass
            raise
        return sock

    loop = asyncio.get_running_loop()
    sock = await loop.run_in_executor(None, _connect_via_proxy)
    try:
        reader, writer = await asyncio.open_connection(sock=sock)
    except Exception:
        # open_connection 失败时 socket 还没被 transport 接管，同样要关闭
        try:
            sock.close()
        except Exception:
            pass
        raise
    return reader, writer

try:
    import uvloop
    _HAS_UVLOOP = True
except ImportError:
    _HAS_UVLOOP = False

_uvloop_installed = False


def _install_uvloop():
    """惰性安装 uvloop，只在首次使用异步扫描时设置，避免模块导入时全局副作用"""
    global _uvloop_installed
    if _HAS_UVLOOP and not _uvloop_installed:
        try:
            asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        except Exception:
            pass
        _uvloop_installed = True


@dataclass
class AsyncScanResult:
    ip: str
    port: int
    is_open: bool
    latency_ms: float = 0.0
    error: str = ""


async def _check_port(ip: str, port: int, timeout: float,
                      semaphore: asyncio.Semaphore,
                      per_ip_sems: dict = None,
                      per_ip_lock: asyncio.Lock = None,
                      max_per_ip: int = 10,
                      retries: int = 2) -> AsyncScanResult:
    """异步检查单个端口，带重试和按IP并发限制。"""
    per_ip_sem = None
    if per_ip_sems is not None and per_ip_lock is not None:
        async with per_ip_lock:
            per_ip_sem = per_ip_sems.get(ip)
            if per_ip_sem is None:
                per_ip_sem = asyncio.Semaphore(max_per_ip)
                per_ip_sems[ip] = per_ip_sem
    async with semaphore:
        if per_ip_sem is not None:
            async with per_ip_sem:
                return await _do_check_port(ip, port, timeout, retries)
        else:
            return await _do_check_port(ip, port, timeout, retries)


async def _do_check_port(ip: str, port: int, timeout: float, retries: int = 2) -> AsyncScanResult:
    """实际端口检查逻辑。"""
    last_error = ""
    for attempt in range(retries + 1):
        start = time.time()
        try:
            reader, writer = await _open_connection(ip, port, timeout)
            latency = (time.time() - start) * 1000
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
            except Exception:
                pass
            return AsyncScanResult(ip=ip, port=port, is_open=True, latency_ms=latency)
        except asyncio.TimeoutError:
            last_error = "timeout"
            break
        except (ConnectionRefusedError, OSError) as e:
            last_error = str(e)[:80]
            if isinstance(e, ConnectionRefusedError):
                break
        except Exception as e:
            last_error = str(e)[:80]
        if attempt < retries:
            await asyncio.sleep(0.05 * (attempt + 1))
    return AsyncScanResult(ip=ip, port=port, is_open=False, error=last_error)


async def _scan_async(targets, concurrency: int, timeout: float,
                      rate_limit: int = 0,
                      progress_cb=None,
                      stop_event=None,
                      profile=None,
                      progress_store=None,
                      controller=None) -> list:
    """异步扫描核心逻辑。"""
    semaphore = asyncio.Semaphore(concurrency)
    # 按IP并发限制：低并发不限制，高并发封顶10
    max_per_ip = max(5, min(10, concurrency))
    per_ip_sems = {}
    per_ip_lock = asyncio.Lock()
    results = []
    done = 0
    open_count = 0
    last_report = time.time()
    # 全局令牌桶限速（避免每任务各自sleep导致实际速率=并发×rate）
    rate_lock = asyncio.Lock()
    last_req = 0.0

    async def _acquire_rate():
        # 自适应开启时速率由 controller 动态调节，否则用固定 rate_limit
        limit = controller.rate if controller is not None else rate_limit
        if limit <= 0:
            return
        min_interval = 1.0 / limit
        nonlocal last_req
        async with rate_lock:
            now = time.time()
            wait = last_req + min_interval - now
            if wait > 0:
                await asyncio.sleep(wait)
            last_req = time.time()

    async def _wrapped(ip, port):
        nonlocal done, open_count, last_report
        if stop_event and stop_event.is_set():
            return AsyncScanResult(ip=ip, port=port, is_open=False, error="stopped")
        await _acquire_rate()
        if stop_event and stop_event.is_set():
            return AsyncScanResult(ip=ip, port=port, is_open=False, error="stopped")
        try:
            r = await _check_port(ip, port, timeout, semaphore,
                                   per_ip_sems=per_ip_sems, per_ip_lock=per_ip_lock,
                                   max_per_ip=max_per_ip,
                                   retries=1)
        except Exception as e:
            r = AsyncScanResult(ip=ip, port=port, is_open=False, error=str(e)[:80])
        results.append(r)
        done += 1
        if r.is_open:
            open_count += 1
        # 自适应控制：按结果类型喂给控制器
        if controller is not None:
            if r.is_open:
                controller.record("open")
            elif "timeout" in (r.error or "").lower():
                controller.record("timeout")
            elif "refused" in (r.error or "").lower():
                controller.record("refused")
            else:
                controller.record("error")
        # 断点续扫：标记完成
        if progress_store is not None:
            progress_store.done((ip, port))
        if progress_cb and (done % 200 == 0 or time.time() - last_report > 1.0):
            progress_cb(done, open_count)
            last_report = time.time()
        return r

    # 分批创建协程，避免一次性创建百万协程导致OOM
    # 保持总在途协程有界（MAX_PENDING）：慢速扫描时完成速度赶不上补充速度，
    # 若每轮都补满 BATCH_SIZE，pending 会累积到目标总数（百万级 → GB 级内存）
    MAX_PENDING = max(concurrency * 2, 200)
    pending = []
    target_iter = iter(targets)

    def _fill_batch():
        """从迭代器填充协程，保持总 pending ≤ MAX_PENDING"""
        while len(pending) < MAX_PENDING:
            try:
                ip, port = next(target_iter)
            except StopIteration:
                break
            if stop_event and stop_event.is_set():
                break
            pending.append(asyncio.create_task(_wrapped(ip, port)))

    _fill_batch()
    since_cooldown = 0
    while pending:
        done_set, pending_set = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
        pending = list(pending_set)
        # 批次冷却：用独立计数器累计（旧实现 done % batch_size == 0 在一次收割
        # 跨过整倍数时永不触发），冷却期间保持可被 stop_event 打断
        since_cooldown += len(done_set)
        if (profile is not None and profile.batch_cooldown > 0
                and since_cooldown >= profile.batch_size):
            since_cooldown = 0
            if not (stop_event and stop_event.is_set()):
                print(f"[*] 批次冷却 {profile.batch_cooldown:.1f}s（已扫 {done}）...")
                deadline = time.monotonic() + profile.batch_cooldown
                while time.monotonic() < deadline:
                    if stop_event and stop_event.is_set():
                        break
                    await asyncio.sleep(min(0.2, max(0.0, deadline - time.monotonic())))
        _fill_batch()

    if progress_cb:
        progress_cb(done, open_count)
    return results


async def scan_ports_coro(targets, concurrency: int = None, timeout: float = 3.0,
                          rate_limit: int = None, progress_cb=None, stop_event=None,
                          mode: str = None, shuffle: bool = None,
                          batch_cooldown: float = None, adaptive: bool = True,
                          progress_file: str = None, seed: int = None,
                          event_cb=None) -> list:
    """异步端口扫描（纯协程入口，必须在事件循环内 await）。

    参数说明见 scan_ports_async。
    """
    # 保持旧行为：首次走异步路径时安装 uvloop（已有运行中的 loop 时只影响后续 loop）
    _install_uvloop()
    profile = get_profile(mode)
    # 副本方式修改参数，绝不改动 SCAN_MODES 全局配置（防跨调用污染）
    if batch_cooldown is not None:
        profile = replace(profile, batch_cooldown=batch_cooldown)
    concurrency = concurrency if concurrency is not None else profile.concurrency
    rate_limit = rate_limit if rate_limit is not None else profile.rate
    do_shuffle = profile.shuffle if shuffle is None else shuffle

    # 断点续扫需要物化（该路径本身有上限保护）；其余情况不物化，
    # 交给分块洗牌惰性消费：旧实现先 list(targets) 再判随机化上限，保护形同虚设
    progress_store = ScanProgressStore(progress_file) if progress_file else None
    try:
        if progress_store is not None and progress_store.enabled:
            targets, _resumed = progress_store.begin(targets)
        if do_shuffle:
            targets = iter_shuffled_chunks(targets, seed=seed)

        # 自适应速率控制器
        controller = None
        if adaptive and profile.adaptive and rate_limit > 0:
            controller = AdaptiveRateController(profile, event_cb=event_cb)

        return await _scan_async(targets, concurrency, timeout, rate_limit,
                                 progress_cb, stop_event, profile,
                                 progress_store, controller)
    finally:
        if progress_store is not None:
            progress_store.finish()


def scan_ports_blocking(targets, **kwargs) -> list:
    """异步端口扫描的阻塞入口：内部 asyncio.run。

    在已有事件循环的线程里调用会抛 RuntimeError：旧实现会返回 coroutine，
    调用方当 list 迭代时只得到难懂的 "coroutine is not iterable"。
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        pass
    else:
        raise RuntimeError(
            "scan_ports_blocking() 不能在运行中的事件循环里调用，"
            "请改用 await scan_ports_coro()")
    _install_uvloop()
    return asyncio.run(scan_ports_coro(targets, **kwargs))


def scan_ports_async(targets, concurrency: int = None, timeout: float = 3.0,
                     rate_limit: int = None, progress_cb=None, stop_event=None,
                     mode: str = None, shuffle: bool = None,
                     batch_cooldown: float = None, adaptive: bool = True,
                     progress_file: str = None, seed: int = None,
                     event_cb=None) -> list:
    """
    异步端口扫描（兼容入口）。

    - 事件循环外调用：阻塞执行，返回 list[AsyncScanResult]
    - 事件循环内调用：返回 coroutine，调用方必须 await（保留以兼容
      core/auto_scanner.py 的 await 用法）

    Args:
        targets: 可迭代的 (ip, port) 元组
        concurrency: 并发数（None 时按 mode 取默认）
        timeout: 连接超时秒数
        rate_limit: 每秒最大连接数（None 时按 mode 取默认，0=不限）
        progress_cb: 进度回调 callback(done, open_count)
        stop_event: threading.Event，设置后停止扫描
        mode: 扫描模式 safe / balanced / aggressive（None=balanced）
        shuffle: 是否打乱任务顺序（None 时按 mode 默认）
        batch_cooldown: 批间冷却秒数（None 时按 mode 默认，0=关闭）
        adaptive: 是否启用失败率自适应降速（默认 True）
        progress_file: 断点续扫进度文件路径（默认 None=不启用）
        seed: 随机种子（用于可复现测试，默认 None=真随机）
        event_cb: 自适应/封禁事件回调 callback(event_dict)

    Returns:
        list[AsyncScanResult]（事件循环内为 coroutine）
    """
    kwargs = dict(concurrency=concurrency, timeout=timeout, rate_limit=rate_limit,
                  progress_cb=progress_cb, stop_event=stop_event, mode=mode,
                  shuffle=shuffle, batch_cooldown=batch_cooldown, adaptive=adaptive,
                  progress_file=progress_file, seed=seed, event_cb=event_cb)
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        # 事件循环外：阻塞执行（旧 asyncio.get_event_loop() 在 3.12 已弃用，
        # 无 loop 时会隐式创建且不关闭）
        return scan_ports_blocking(targets, **kwargs)
    # 已在事件循环内（如 Web 面板）：返回协程让调用方 await
    return scan_ports_coro(targets, **kwargs)


def get_open_ports_async(results: list) -> list:
    """从异步扫描结果中提取开放的 (ip, port)。

    results 必须是 list[AsyncScanResult]；若误传 coroutine（在事件循环内调用了
    scan_ports_async 却没 await），给出明确报错而不是迭代协程的 TypeError。
    """
    if asyncio.iscoroutine(results):
        raise TypeError("get_open_ports_async() 收到 coroutine："
                        "请先 await scan_ports_async(...) 或 scan_ports_coro(...)")
    return [(r.ip, r.port) for r in results if r.is_open]


def has_uvloop() -> bool:
    return _HAS_UVLOOP
