# -*- coding: utf-8 -*-
"""
端口扫描：多线程 TCP 全连接扫描，支持限速、进度回调、停止。
优化：分批提交任务，大网段不OOM；check_port用finally保证socket关闭。
"""
import concurrent.futures
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from typing import Optional

from scanner.safe import AdaptiveRateController, ScanProgressStore, get_profile, iter_shuffled_chunks

# 疑似封禁时暂停投递的秒数（暂停期间继续收割在途任务，可被 stop_event 打断）
BAN_PAUSE_SECONDS = 30.0

_config_cache = None


def _get_config_value(key: str, default):
    """读取用户配置。

    函数内 import 是为了避免 config ↔ scanner 的循环导入；在模块级缓存模块引用，
    避免旧实现"每次提交一个目标就 import 一次"。
    """
    global _config_cache
    if _config_cache is None:
        try:
            import config as _cfg
        except Exception:
            return default
        _config_cache = _cfg
    try:
        return _config_cache.get(key, default)
    except Exception:
        return default


@dataclass
class ScanResult:
    """端口扫描结果"""
    ip: str
    port: int
    is_open: bool
    latency_ms: float = 0.0
    error: str = ""


def check_port(ip: str, port: int, timeout: float = 3.0) -> ScanResult:
    """检查单个端口是否开放（finally保证socket关闭）"""
    start = time.time()
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        latency = (time.time() - start) * 1000
        if result == 0:
            return ScanResult(ip=ip, port=port, is_open=True, latency_ms=latency)
        return ScanResult(ip=ip, port=port, is_open=False, latency_ms=latency,
                          error=f"connect_ex={result}")
    except socket.timeout:
        return ScanResult(ip=ip, port=port, is_open=False, error="timeout")
    except Exception as e:
        return ScanResult(ip=ip, port=port, is_open=False, error=str(e)[:100])
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def scan_ports(targets, max_workers: int = None, timeout: float = 3.0,
               show_progress: bool = True, rate: int = None,
               stop_event: Optional[threading.Event] = None,
               progress_callback=None,
               mode: str = None, shuffle: bool = None,
               batch_cooldown: float = None, adaptive: bool = True,
               progress_file: str = None, seed: int = None,
               event_cb=None) -> list:
    """
    多线程扫描端口（分批提交，大网段不OOM）。
    rate: 每秒最大连接数，0=不限速
    progress_callback: 回调函数(done, total, open_count)，每500个或完成时调用
    mode: 扫描模式 safe / balanced / aggressive（None=balanced）
    shuffle: 是否打乱任务顺序（None 时按 mode 默认）
    batch_cooldown: 批间冷却秒数（None 时按 mode 默认，0=关闭）
    adaptive: 是否启用失败率自适应降速（默认 True）
    progress_file: 断点续扫进度文件路径（默认 None=不启用）
    """
    profile = get_profile(mode)
    # 副本方式修改参数，绝不改动 SCAN_MODES 全局配置（防跨调用污染）
    if batch_cooldown is not None:
        profile = replace(profile, batch_cooldown=batch_cooldown)
    max_workers = max_workers if max_workers is not None else profile.concurrency
    rate = rate if rate is not None else profile.rate
    do_shuffle = profile.shuffle if shuffle is None else shuffle
    BATCH_SIZE = max(max_workers * 4, 200)

    # 断点续扫需要物化（该路径本身有 50 万上限保护）；其余情况不物化，
    # 交给分块洗牌惰性消费，避免"先 list(targets) 再判随机化上限"的假保护
    progress_store = ScanProgressStore(progress_file) if progress_file else None
    if progress_store is not None and progress_store.enabled:
        target_seq, _resumed = progress_store.begin(targets)
        total = len(target_seq)
    else:
        # 传入迭代器时物化（带200万上限），否则total=0导致进度永不更新、
        # 进度步长退化为500，小扫描看起来像卡死。列表/元组直接用len()。
        if not hasattr(targets, '__len__'):
            targets = list(targets)
            if len(targets) > 2_000_000:
                print(f"[!] 目标数超过200万，截断到200万（实际{len(targets)}）")
                targets = targets[:2_000_000]
        target_seq = targets
        total = len(target_seq)
    if do_shuffle:
        target_seq = iter_shuffled_chunks(target_seq, seed=seed)

    results = []
    done = 0
    open_count = 0
    lock = threading.Lock()
    # 进度更新步长：约每1%更新一次，小目标逐个更，大目标封顶500（避免打印/回调过频）
    # total 未知（生成器输入）时用固定步长 500，避免逐个回调
    _progress_step = max(1, min(500, total // 100)) if total else 500

    controller = None
    if adaptive and profile.adaptive and rate > 0:
        controller = AdaptiveRateController(profile, event_cb=event_cb)
        # 从 profile.rate 保守起步，控制器自行提速到 max_rate。
        # 之前直接设为 min(rate, max_rate) 导致 safe 模式单IP扫描从10/s起步，
        # 容易触发服务器限流。保守起步 + 自适应提速更安全。
        # 小扫描（<100条）控制器来不及提速，保持 profile.rate 是预期的安全行为。

    if show_progress:
        _eff_rate = controller.rate if controller is not None else rate
        print(f"[*] 开始扫描 {total} 个目标，并发数 {max_workers}，"
              f"模式 {profile.mode}"
              + (f"，限速 {_eff_rate}/s" if _eff_rate > 0 else "")
              + ("（自适应）" if controller is not None else ""))
        if do_shuffle:
            print("[*] 已随机化扫描顺序（防顺序扫描特征）")

    # 按IP并发限制：单IP最多max(5, min(10, max_workers))个并发连接。
    # 低并发扫描（如5线程）不限制，和之前行为一致；高并发扫描（200线程）
    # 封顶到10，防止单IP被打封。全局并发分散在不同IP时不受影响。
    _per_ip_sems = {}
    _per_ip_lock = threading.Lock()
    MAX_PER_IP = max(5, min(10, max_workers))

    def _check_port_limited(ip, port, timeout):
        with _per_ip_lock:
            sem = _per_ip_sems.get(ip)
            if sem is None:
                sem = threading.Semaphore(MAX_PER_IP)
                _per_ip_sems[ip] = sem
        with sem:
            return check_port(ip, port, timeout)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {}
        target_iter = iter(target_seq)
        last_submit = time.time()
        done_since_cooldown = 0
        pause_until = 0.0

        def _submit_one(ip, port):
            nonlocal last_submit
            cur_rate = controller.rate if controller is not None else rate
            if cur_rate > 0:
                # 令牌桶限速：每次提交间隔至少 1/rate 秒
                min_interval = 1.0 / cur_rate
                elapsed = time.time() - last_submit
                if elapsed < min_interval:
                    time.sleep(min_interval - elapsed)
                last_submit = time.time()
            futures[executor.submit(_check_port_limited, ip, port, timeout)] = (ip, port)

        # 初始填充一批（用较小批次让主循环尽早开始处理已完成的任务，
        # 避免限速下提交全部目标要等很久才看到进度）
        _initial_batch = min(BATCH_SIZE, max_workers * 2)
        targets_left = True
        for ip, port in target_iter:
            if stop_event and stop_event.is_set():
                break
            _submit_one(ip, port)
            if len(futures) >= _initial_batch:
                break
        else:
            # for-else：迭代器已耗尽，没有更多目标可提交
            targets_left = False

        while True:
            if stop_event and stop_event.is_set():
                for f in futures:
                    f.cancel()
                break
            in_pause = time.time() < pause_until
            just_submitted = False
            if not in_pause:
                n_before = len(futures)
                for ip, port in target_iter:
                    if stop_event and stop_event.is_set():
                        break
                    _submit_one(ip, port)
                    if len(futures) >= BATCH_SIZE:
                        break
                else:
                    targets_left = False
                just_submitted = len(futures) > n_before
            # 目标已全部提交并回收：收工（暂停中也不例外，避免空转）
            if not futures and not targets_left:
                break
            if not futures:
                # 还有目标没提交（只可能是封禁暂停中）：等暂停结束再投递，避免空转
                delay = max(0.0, min(1.0, pause_until - time.time()))
                if stop_event is not None:
                    stop_event.wait(delay)
                else:
                    time.sleep(delay)
                continue
            done_set, _ = concurrent.futures.wait(
                futures, return_when=concurrent.futures.FIRST_COMPLETED,
                timeout=1.0 if in_pause else None)
            for future in done_set:
                ip, port = futures.pop(future)
                try:
                    result = future.result()
                except Exception as e:
                    # 失败也要生成结果并计数：旧实现直接 continue，
                    # 目标已从 futures 弹出却被丢弃，done 永远对不上 total
                    result = ScanResult(ip=ip, port=port, is_open=False,
                                        error=f"worker error: {str(e)[:80]}")
                results.append(result)
                with lock:
                    done += 1
                    if result.is_open:
                        open_count += 1
                # 自适应控制：放在锁外，controller.record 会派发 event_cb 回调，
                # 持锁执行可能阻塞投递主循环甚至与回调反向取锁
                if controller is not None:
                    if result.is_open:
                        controller.record("open")
                    elif "timeout" in (result.error or "").lower():
                        controller.record("timeout")
                    elif "refused" in (result.error or "").lower():
                        controller.record("refused")
                    else:
                        controller.record("error")
                # 断点续扫
                if progress_store is not None:
                    progress_store.done((result.ip, result.port))
                if show_progress and (done % _progress_step == 0 or done == total):
                    pct = done * 100 // total if total else 0
                    print(f"[*] 进度: {done}/{total} ({pct}%) 开放: {open_count}")
                if progress_callback and (done % _progress_step == 0 or done == total):
                    try:
                        progress_callback(done, total, open_count)
                    except Exception:
                        pass
                done_since_cooldown += 1
            # 批次冷却：用独立计数器（旧实现 done % batch_size == 0 在一次收割跨过
            # 整倍数时永不触发），并且冷却可被 stop_event 打断
            if (profile.batch_cooldown > 0 and done_since_cooldown >= profile.batch_size
                    and not (stop_event and stop_event.is_set())):
                done_since_cooldown = 0
                print(f"[*] 批次冷却 {profile.batch_cooldown:.1f}s（已扫 {done}）...")
                if stop_event is not None:
                    stop_event.wait(profile.batch_cooldown)
                else:
                    time.sleep(profile.batch_cooldown)
            # 刚投递过一批就检测到疑似封禁：暂停后续投递，在途任务继续收割。
            # 旧实现是在投递循环里 time.sleep(30)：不可被 stop_event 打断，
            # 且 30 秒内完全不收割已完成任务，看起来像卡死。
            if just_submitted and controller is not None and controller.ban_suspected:
                if _get_config_value("on_ban_suspect", "pause") == "abort":
                    if stop_event:
                        stop_event.set()
                    break
                pause_until = time.time() + BAN_PAUSE_SECONDS
                in_pause = True
                print(f"[!] 疑似出口 IP 被封禁，暂停投递 {BAN_PAUSE_SECONDS:.0f}s"
                      f"（在途任务继续回收，随时可停止）")

    if progress_store is not None:
        progress_store.finish()
    if show_progress:
        print(f"[*] 扫描完成，共 {total} 个目标，开放 {open_count} 个")
        if controller is not None and controller.events:
            print("[*] 防封禁事件：")
            for evt in controller.events[-10:]:
                print(f"    [{evt['ts']}] {evt['type']}: {evt['msg']}")
    return results


def get_open_ports(results: list) -> list:
    """从扫描结果中提取开放的 (ip, port)"""
    return [(r.ip, r.port) for r in results if r.is_open]
