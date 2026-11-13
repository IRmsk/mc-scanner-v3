# -*- coding: utf-8 -*-
"""
安全扫描策略（v3.6.0 新增）

解决痛点：全端口扫描时，顺序扫描 + 高并发 + 无限速导致出口 IP 被
目标网络限流/封禁（触发 IDS / fail2ban / 运营商限流），连其他设备都连不上。

提供：
1. 扫描模式分级（safe / balanced / aggressive）
2. 端口随机化（打乱扫描顺序，去掉"顺序递增"特征）
3. 批次 + 冷却（每批扫完暂停，降低突发）
4. 自适应速率（按失败率动态降速/恢复，检测疑似封禁）
5. 断点续扫（中断后从上次位置继续，避免重扫触发二次封禁）

所有功能默认关闭/保守开启，向后兼容 v3 行为。
"""
import json
import os
import random
import threading
import time
from collections import deque
from dataclasses import dataclass, replace
from typing import Optional

# ---------------------------------------------------------------- 模式配置

@dataclass
class ScanProfile:
    """扫描模式参数"""
    mode: str
    concurrency: int          # 并发连接数
    rate: int                 # 每秒最大连接数（0=不限制）
    batch_size: int           # 每批任务数，达到后进入冷却
    batch_cooldown: float     # 批间冷却秒数
    shuffle: bool             # 是否打乱任务顺序
    adaptive: bool            # 是否启用失败率自适应降速
    max_rate: int = 0         # 自适应允许的最大速率（0=用 rate）

    def effective_max_rate(self) -> int:
        return self.max_rate if self.max_rate > 0 else self.rate


SCAN_MODES = {
    # 安全模式：极低并发、低速率、小批次 + 长冷却、随机化、自适应
    "safe": ScanProfile(
        mode="safe", concurrency=30, rate=5,
        batch_size=100, batch_cooldown=3.0,
        shuffle=True, adaptive=True, max_rate=10,
    ),
    # 平衡模式（默认）：保守默认，接近 safe 但保留一定速度
    "balanced": ScanProfile(
        mode="balanced", concurrency=400, rate=25,
        batch_size=2000, batch_cooldown=0.5,
        shuffle=True, adaptive=True, max_rate=50,
    ),
    # 激进模式：仅内网/信任网络，关闭保护
    "aggressive": ScanProfile(
        mode="aggressive", concurrency=5000, rate=0,
        batch_size=20000, batch_cooldown=0.0,
        shuffle=False, adaptive=False, max_rate=0,
    ),
}


def get_profile(mode: Optional[str]) -> ScanProfile:
    """按名称获取扫描模式，未知/None 回退 balanced。

    返回副本而不是 SCAN_MODES 里的共享实例：旧实现返回全局可变 dataclass，
    调用方一个 ".rate = x" 就会永久污染所有后续扫描的配置。
    """
    if mode and mode in SCAN_MODES:
        return replace(SCAN_MODES[mode])
    return replace(SCAN_MODES["balanced"])


# ---------------------------------------------------------------- 随机化

def shuffle_targets(targets, seed: Optional[int] = None, max_items: int = 500_000):
    """
    打乱 (ip, port) 任务顺序，去掉"顺序递增"扫描特征。

    注意：本函数必须先把输入物化成 list 才能整体洗牌，因此只适合中小规模任务；
    大网段请改用 iter_shuffled_chunks()（分块洗牌，不在内存里驻留全量目标）。
    """
    try:
        lst = list(targets)
    except Exception:
        return list(targets)
    if len(lst) > max_items:
        print(f"[!] 任务数 {len(lst)} 超过随机化上限 {max_items}，跳过打乱（建议分批扫描）")
        return lst
    if seed is not None:
        random.Random(seed).shuffle(lst)
    else:
        random.shuffle(lst)
    return lst


def iter_shuffled_chunks(targets, chunk_size: int = 100_000,
                         seed: Optional[int] = None):
    """分块读取 + 块内洗牌（惰性生成器）。

    旧实现在调用点 list(targets) 之后才用 shuffle_targets 判断上限，
    200 万目标时"上限保护"形同虚设；这里改成边读边洗，内存上限 ≈ chunk_size。
    块内洗牌同样能去掉"顺序递增"特征，只是不再是全局均匀排列。
    """
    rng = random.Random(seed) if seed is not None else random
    chunk = []
    for item in targets:
        chunk.append(item)
        if len(chunk) >= chunk_size:
            rng.shuffle(chunk)
            yield from chunk
            chunk = []
    if chunk:
        rng.shuffle(chunk)
        yield from chunk


# ---------------------------------------------------------------- 自适应速率 / 封禁检测

class AdaptiveRateController:
    """
    失败率自适应速率控制 + 连接异常检测。

    原理：正常扫描中，关闭端口返回 ConnectionRefused（秒回）；当网络被
    限流/封禁时，表现为大量超时（包被丢弃）。因此用"超时占比"作为信号：
    - 超时占比低 → 网络通畅，可尝试加速（不超过 max_rate）
    - 超时占比高 → 疑似限流，自动降速
    - 连续多窗口高 → 疑似封禁，触发 pause 事件

    事件通过回调上报（可用来暂停/停止/记录日志）。
    """

    def __init__(self, profile: ScanProfile,
                 window_size: int = 100,
                 event_cb=None):
        self.profile = profile
        self.window_size = window_size
        self.event_cb = event_cb or (lambda evt: None)
        # 固定容量窗口：自动淘汰最旧结果，防止长时间扫描内存无限增长
        self._results = deque(maxlen=window_size)
        self._current_rate = profile.rate
        self._consecutive_bad_windows = 0
        self.events = []            # 检测到的事件记录

    @property
    def rate(self) -> int:
        """当前建议速率"""
        return self._current_rate

    def record(self, kind: str):
        """记录一次连接结果（timeout/refused/error/open）"""
        self._results.append(kind)
        if len(self._results) < self.window_size:
            return
        # 窗口满：评估一次（deque 自动保持最近 window_size 个）
        timeouts = self._results.count("timeout")
        ratio = timeouts / len(self._results)
        # refused 是正常关闭，不计入异常
        if ratio >= 0.8:
            self._consecutive_bad_windows += 1
            new_rate = max(int(self._current_rate * 0.3), 1)
            if new_rate < self._current_rate:
                self._add_event("slowdown",
                                f"超时占比 {ratio:.0%}，疑似限流，速率 {self._current_rate}→{new_rate}")
                self._current_rate = new_rate
            if self._consecutive_bad_windows >= 3:
                self._add_event("ban_suspect",
                                f"连续 {self._consecutive_bad_windows} 个窗口高超时，疑似出口 IP 被封禁，"
                                f"建议暂停扫描或更换网络出口")
        elif ratio <= 0.2:
            self._consecutive_bad_windows = 0
            max_rate = self.profile.effective_max_rate()
            if self._current_rate < max_rate:
                new_rate = min(int(self._current_rate * 1.5) + 1, max_rate)
                self._add_event("speedup", f"网络通畅，速率 {self._current_rate}→{new_rate}")
                self._current_rate = new_rate
        else:
            self._consecutive_bad_windows = 0

    @property
    def ban_suspected(self) -> bool:
        return self._consecutive_bad_windows >= 3

    def _add_event(self, evt_type: str, msg: str):
        event = {"type": evt_type, "msg": msg, "ts": time.strftime("%H:%M:%S")}
        self.events.append(event)
        # 事件记录有界（portscan.py 用 [-10:] 取最近），防长扫描无界增长
        if len(self.events) > 100:
            del self.events[: len(self.events) - 100]
        self.event_cb(event)


# ---------------------------------------------------------------- 断点续扫

# 进度文件格式版本：结构不兼容时递增；读取到不匹配版本拒绝resume，防止字段错位
PROGRESS_VERSION = 1

class ScanProgressStore:
    """
    断点续扫：把"剩余任务"持久化到 JSON 文件。
    中断/暂停后可 --resume 继续，避免重扫触发二次封禁。
    """

    def __init__(self, progress_file: Optional[str] = None):
        self.progress_file = progress_file
        self._remaining = None
        self._dirty = False
        self._last_save = time.time()
        self._save_interval = 5.0   # 距上次保存至少间隔秒数
        self.MAX_MATERIALIZE = 500_000  # 新任务物化上限，超限不启用续扫（防大网段 OOM）
        # 剩余集合由扫描主线程 discard、保存线程/主线程读快照，必须加锁
        self._lock = threading.Lock()
        self._write_lock = threading.Lock()   # 保证同一时刻只有一个写盘者
        self._save_lock = threading.Lock()
        self._save_pending = False
        self._saver = None

    @property
    def enabled(self) -> bool:
        return bool(self.progress_file)

    def begin(self, targets):
        """扫描开始时物化目标并写入剩余列表。返回 (remaining_list, is_resume)"""
        remaining = list(targets)
        resume = False
        if self.progress_file and os.path.exists(self.progress_file):
            try:
                with open(self.progress_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                ver = data.get("version")
                if ver != PROGRESS_VERSION:
                    print(f"[!] 续扫文件版本不兼容（文件={ver}, 程序支持={PROGRESS_VERSION}），"
                          f"请删除 {self.progress_file} 后重新开始")
                else:
                    saved = data.get("remaining", [])
                    if saved:
                        remaining = [tuple(item) for item in saved]
                        resume = True
                        print(f"[*] 续扫模式：读取 {len(remaining)} 个剩余目标 ({self.progress_file})")
            except Exception as e:
                print(f"[!] 读取续扫文件失败: {e}，重新开始")
        # 新任务物化上限保护：超限则本次不启用断点续扫（进度文件也会过大）
        if not resume and len(remaining) > self.MAX_MATERIALIZE:
            print(f"[!] 任务数 {len(remaining)} 超过断点续扫上限 {self.MAX_MATERIALIZE}，"
                  f"本次不启用断点续扫（可分批扫描）")
            self.progress_file = None
            return remaining, False
        if self.progress_file:
            self._remaining = set(remaining)
            self._save()
        return remaining, resume

    def done(self, item):
        """标记一个目标完成（从剩余集合移除，间隔保存）"""
        if self._remaining is None:
            return
        with self._lock:
            self._remaining.discard(item)
            self._dirty = True
        now = time.time()
        if self._dirty and (now - self._last_save) >= self._save_interval:
            # 后台保存：旧实现在扫描主线程里 json.dump 整个剩余集合（上限 50 万条、
            # 单文件可达十几 MB），每 5 秒造成一次秒级 I/O 停顿并阻塞结果收割
            self._schedule_save()

    def _schedule_save(self):
        """唤醒后台保存线程（已有线程在跑时只置一次标志）"""
        with self._save_lock:
            self._save_pending = True
            if self._saver is None or not self._saver.is_alive():
                self._saver = threading.Thread(target=self._save_loop,
                                               name="progress-save", daemon=True)
                self._saver.start()

    def _save_loop(self):
        while True:
            with self._save_lock:
                if not self._save_pending:
                    return
                self._save_pending = False
            self._save()

    def finish(self):
        """扫描结束/中断时保存最终状态（同步写，保证返回时已落盘）"""
        with self._save_lock:
            self._save_pending = False
        saver = self._saver
        if saver is not None and saver.is_alive() and saver is not threading.current_thread():
            saver.join(timeout=10)
        if self._remaining is not None:
            self._save()

    def _save(self):
        if not self.progress_file or self._remaining is None:
            return
        with self._write_lock:
            # 先在锁内取快照，序列化（可能十几 MB）在锁外进行
            with self._lock:
                snapshot = [list(item) for item in self._remaining]
            try:
                tmp = self.progress_file + ".tmp"
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump({
                        "version": PROGRESS_VERSION,
                        "saved_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "remaining_count": len(snapshot),
                        "remaining": snapshot,
                    }, f, ensure_ascii=False)
                os.replace(tmp, self.progress_file)
                self._dirty = False
                self._last_save = time.time()
            except Exception as e:
                print(f"[!] 保存续扫进度失败: {e}")
