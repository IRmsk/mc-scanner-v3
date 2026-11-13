# -*- coding: utf-8 -*-
"""AI Bot 分层记忆：短期原文 + 中期摘要 + 长期玩家档案。
纯本地规则提取，不花API钱。
"""
import atexit
import json
import os
import re
import threading
import time
from collections import Counter
from datetime import datetime

_LOCK = threading.Lock()
_MEMORY_FILE = "ai_memory.json"
_long_term = {}  # player_name -> {first_seen, last_seen, msg_count, keywords, facts}
_loaded = False

# 落盘策略：原先每条聊天消息都在持 _LOCK 的情况下把整个 JSON 重写一遍，
# 而调用点在 bot 的收包线程里（bot.play → chat_callback → update_player_memory），
# 服务器里任何人刷屏都能阻塞 keep-alive。改成脏标记 + 定时/显式 flush。
_SAVE_INTERVAL = 5.0   # 最小落盘间隔（秒）
_dirty = False
_last_save = 0.0
# 玩家档案上限：攻击者可用随机用户名制造无界内存/文件增长
MAX_PLAYERS = 2000
_FLUSH_STOP = threading.Event()
_flusher = None


def _load():
    global _long_term, _loaded
    if _loaded:
        return
    try:
        if os.path.exists(_MEMORY_FILE):
            with open(_MEMORY_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    _long_term = data
    except Exception:
        _long_term = {}
    _loaded = True


def _save():
    try:
        with open(_MEMORY_FILE, "w", encoding="utf-8") as f:
            json.dump(_long_term, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def _save_locked():
    """在持 _LOCK 时立即落盘并清脏标记。"""
    global _dirty, _last_save
    _save()
    _dirty = False
    _last_save = time.monotonic()


def flush_memory(force=False):
    """把脏数据落盘。force=False 时受最小落盘间隔限制，避免刷屏时反复全量写。"""
    global _dirty
    with _LOCK:
        if not _dirty:
            return False
        if not force and (time.monotonic() - _last_save) < _SAVE_INTERVAL:
            return False
        _save_locked()
        return True


def _flush_loop():
    while not _FLUSH_STOP.is_set():
        _FLUSH_STOP.wait(_SAVE_INTERVAL)
        try:
            flush_memory()
        except Exception:
            pass


def _ensure_flusher():
    """首次写入时启动后台落盘线程（daemon，不影响进程退出）。"""
    global _flusher
    if _flusher is not None:
        return
    with _LOCK:
        if _flusher is not None:
            return
        t = threading.Thread(target=_flush_loop, daemon=True, name="ai-memory-flush")
        _flusher = t
        t.start()


def _evict_locked():
    """超过 MAX_PLAYERS 时按 last_seen 淘汰最旧的档案（需持 _LOCK）。"""
    excess = len(_long_term) - MAX_PLAYERS
    if excess <= 0:
        return
    oldest = sorted(_long_term.items(), key=lambda kv: kv[1].get("last_seen", ""))[:excess]
    for name, _ in oldest:
        _long_term.pop(name, None)


try:
    atexit.register(lambda: flush_memory(force=True))
except Exception:
    pass


# 停用词（中文+英文），不参与关键词统计
_STOPWORDS = set("""
的 了 是 在 我 你 他 她 它 我们 你们 他们 这 那 有 和 就 都 而 及 与 或 一个 一些 什么 怎么 为什么
吗 呢 吧 啊 呀 哦 哈 嗯 呃 这个 那个 不是 没有 可以 能 会 要 想 说 看 听 走 去 来 给 把 被 让
the a an is are was were be been being have has had do does did will would shall should may might can could
of in on at to for with by from as into through during before after above below between out off over under
again further then once here there when where why how all any both each few more most other some such no nor
not only own same so than too very just because about up down
""".split())

# 关键信息提取模式
_FACT_PATTERNS = [
    (re.compile(r"我是([^，。！？\s]{1,15})"), "身份"),
    (re.compile(r"我叫([^，。！？\s]{1,15})"), "名字"),
    (re.compile(r"我喜欢([^，。！？\s]{1,15})"), "喜好"),
    (re.compile(r"我在([^，。！？\s]{1,15})"), "位置"),
    (re.compile(r"我来自([^，。！？\s]{1,15})"), "来自"),
    (re.compile(r"我玩([^，。！？\s]{1,15})"), "玩什么"),
    (re.compile(r"我是([^，。！？\s]{1,10})的腐竹"), "腐竹"),
    (re.compile(r"我是([^，。！？\s]{1,10})的管理"), "管理"),
    (re.compile(r"我今年(\d{1,3})岁"), "年龄"),
]


def _extract_keywords(text, top_n=5):
    """从文本提取高频关键词"""
    words = re.findall(r"[\u4e00-\u9fa5]{2,}|[a-zA-Z]{3,}", text)
    words = [w for w in words if w not in _STOPWORDS and len(w) >= 2]
    if not words:
        return []
    counter = Counter(words)
    return [w for w, _ in counter.most_common(top_n)]


def _extract_facts(text):
    """从文本提取关键事实"""
    facts = []
    for pattern, label in _FACT_PATTERNS:
        m = pattern.search(text)
        if m:
            facts.append(f"{label}:{m.group(1).strip()}")
    return facts


def update_player_memory(sender, text):
    """更新玩家长期记忆（只标脏，落盘交给后台 flusher，不阻塞收包线程）"""
    global _dirty
    if not sender or sender in ("系统", "system", "Server"):
        return
    _ensure_flusher()
    with _LOCK:
        _load()
        now = datetime.now().strftime("%Y-%m-%d %H:%M")
        if sender not in _long_term:
            _long_term[sender] = {
                "first_seen": now,
                "last_seen": now,
                "msg_count": 0,
                "keywords": [],
                "facts": [],
            }
            _evict_locked()
        p = _long_term[sender]
        p["last_seen"] = now
        p["msg_count"] += 1
        # 关键词
        kws = _extract_keywords(text)
        p["keywords"] = list(set(p["keywords"] + kws))[:20]
        # 事实提取
        facts = _extract_facts(text)
        for f in facts:
            if f not in p["facts"]:
                p["facts"].append(f)
        if len(p["facts"]) > 10:
            p["facts"] = p["facts"][-10:]
        # 只标脏：真正的落盘由 _flush_loop / flush_memory 完成
        _dirty = True


def get_player_profile(sender):
    """获取单个玩家档案"""
    with _LOCK:
        _load()
        return _long_term.get(sender)


def get_relevant_profiles(senders, limit=5):
    """获取相关玩家的档案摘要（用于prompt）"""
    with _LOCK:
        _load()
        lines = []
        for s in senders[:limit]:
            p = _long_term.get(s)
            if not p:
                continue
            parts = [f"{s}(发言{p['msg_count']}次)"]
            if p["facts"]:
                parts.append("，".join(p["facts"][:3]))
            if p["keywords"]:
                parts.append(f"常聊:{'、'.join(p['keywords'][:5])}")
            lines.append(" - " + "，".join(parts))
        return "\n".join(lines) if lines else ""


class MidTermMemory:
    """中期滚动摘要：每N条消息压缩成一个话题片段"""

    def __init__(self, window_size=30, max_segments=3):
        self.window_size = window_size
        self.max_segments = max_segments
        self._buffer = []  # 当前窗口的消息
        self._segments = []  # 已压缩的摘要片段
        self._all_senders = set()

    def add(self, sender, text):
        if sender in ("系统", "system", "Server"):
            return
        self._buffer.append((sender, text))
        self._all_senders.add(sender)
        if len(self._buffer) >= self.window_size:
            self._compress()

    def _compress(self):
        """把当前窗口压缩成摘要片段，保留代表性对话"""
        if not self._buffer:
            return
        senders = [s for s, _ in self._buffer]
        all_text = " ".join(t for _, t in self._buffer)
        top_senders = Counter(senders).most_common(3)
        keywords = _extract_keywords(all_text, top_n=8)
        sender_str = "、".join(f"{s}({c}条)" for s, c in top_senders)
        kw_str = "、".join(keywords) if keywords else "无明显话题"
        # 挑选2-3条代表性对话（不同说话人、长度适中、非纯语气词）
        quotes = []
        seen_senders = set()
        for sender, text in self._buffer:
            if sender in seen_senders:
                continue
            t = text.strip()
            if len(t) < 4 or len(t) > 60:
                continue
            if t in ("？", "?", "。", "…", "嗯", "哦", "啊", "哈", "哈哈"):
                continue
            quotes.append(f"{sender}:{t}")
            seen_senders.add(sender)
            if len(quotes) >= 3:
                break
        quote_str = " | ".join(quotes) if quotes else ""
        segment = f"[前{len(self._buffer)}条] 活跃:{sender_str} | 话题:{kw_str}"
        if quote_str:
            segment += f" | 代表:{quote_str}"
        self._segments.append(segment)
        if len(self._segments) > self.max_segments:
            self._segments = self._segments[-self.max_segments:]
        self._buffer = []

    def get_summary(self):
        """获取中期摘要文本"""
        if not self._segments and not self._buffer:
            return ""
        parts = list(self._segments)
        if self._buffer:
            senders = [s for s, _ in self._buffer]
            top = Counter(senders).most_common(2)
            sender_str = "、".join(f"{s}({c})" for s, c in top)
            parts.append(f"[当前{len(self._buffer)}条] 活跃:{sender_str}")
        return "\n".join(parts)

    def get_active_senders(self):
        return list(self._all_senders)

    def reset(self):
        self._buffer = []
        self._segments = []
        self._all_senders = set()


def build_memory_prompt(chat_log, mid_memory, sender, short_count=50, self_name=None):
    """构建完整的记忆prompt文本。
    chat_log: deque of (seq, ts, sender, text)
    mid_memory: MidTermMemory实例
    sender: 当前触发回复的玩家
    self_name: 当前AI自己的用户名（用于区分"自己说的话"）
    返回: (memory_text, used_short_count)
    """
    parts = []
    if self_name:
        parts.append(f"你叫{self_name}，以下是聊天记录，标注「你」的条目就是你自己说的话，别把它们当成别人的。")
    # 长期记忆：相关玩家档案（排除自己）
    recent_senders = [s for _, _, s, _ in list(chat_log)[-30:]
                      if s not in ("系统", "system", "Server") and s != self_name]
    profiles = get_relevant_profiles(list(dict.fromkeys(recent_senders)), limit=5)
    if profiles:
        parts.append("【玩家档案】\n" + profiles)
    # 中期记忆
    mid = mid_memory.get_summary() if mid_memory else ""
    if mid:
        parts.append("【之前聊了啥】\n" + mid)
    # 短期记忆：最近N条原文（自己的消息标记为「你」）
    recent = list(chat_log)[-short_count:]
    if recent:
        lines = []
        for _, _, s, t in recent:
            if self_name and s == self_name:
                lines.append(f"[你] {t}")
            else:
                lines.append(f"[{s}] {t}")
        parts.append("【最近聊天】\n" + "\n".join(lines))
    return "\n\n".join(parts) if parts else ""


def clear_all_memory():
    """清除全部长期玩家档案并落盘。返回清除的玩家数量。"""
    with _LOCK:
        _load()
        n = len(_long_term)
        _long_term.clear()
        _save_locked()
    return n


def clear_player(sender):
    """清除单个玩家的长期档案。返回是否存在并删除。"""
    with _LOCK:
        _load()
        if sender in _long_term:
            del _long_term[sender]
            _save_locked()
            return True
        return False
