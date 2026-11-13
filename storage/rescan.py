# -*- coding: utf-8 -*-
"""
智能重扫队列（v3.2.1 新增，融合 matscan 特性）。
根据服务器状态动态调整重扫频率：
- 有人在线的服务器：5分钟重扫（追踪玩家变化）
- 离线/破解服：30分钟重扫
- 正版/白名单服：2小时重扫
- 新发现服务器：1分钟内快速确认（前5次）
"""
import time

from storage.db import get_conn

RESCAN_QUEUE_SCHEMA = """
CREATE TABLE IF NOT EXISTS rescan_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    strategy TEXT DEFAULT 'default',
    next_scan INTEGER DEFAULT 0,
    scan_count INTEGER DEFAULT 0,
    last_state TEXT DEFAULT '',
    last_auth TEXT DEFAULT '',
    last_online INTEGER DEFAULT 0,
    last_scan INTEGER DEFAULT 0,
    UNIQUE(ip, port)
);
CREATE INDEX IF NOT EXISTS idx_rq_next ON rescan_queue(next_scan);
CREATE INDEX IF NOT EXISTS idx_rq_strategy ON rescan_queue(strategy);
"""

# 重扫策略配置（秒）
# 注：原配置里的 max_retries 全项目零读取点（死配置，会误导调用方以为有重试上限），已删除。
DEFAULT_STRATEGIES = {
    "has_players": {"interval": 300, "description": "有人在线，高频重扫"},
    "cracked": {"interval": 1800, "description": "离线/破解服，中等频率"},
    "online": {"interval": 7200, "description": "正版服，低频率"},
    "whitelist": {"interval": 7200, "description": "白名单服，低频率"},
    "new": {"interval": 60, "description": "新发现服务器，快速确认"},
    "default": {"interval": 3600, "description": "默认策略"},
}


def init_rescan_queue(db_path: str):
    """初始化重扫队列表。"""
    conn = get_conn(db_path)
    conn.executescript(RESCAN_QUEUE_SCHEMA)
    conn.commit()


def update_rescan(db_path: str, ip: str, port: int, result: dict,
                  strategies: dict = None):
    """
    根据扫描结果更新重扫计划。
    result: {"state", "auth", "players_online", ...}
    """
    strategies = strategies or DEFAULT_STRATEGIES
    now = int(time.time())

    # 确定策略
    strategy_name = _determine_strategy(result)
    default_strategy = strategies.get("default")
    strategy = strategies.get(strategy_name) or default_strategy

    conn = get_conn(db_path)
    # 检查是否已存在
    row = conn.execute("SELECT scan_count FROM rescan_queue WHERE ip=? AND port=?",
                       (ip, port)).fetchone()
    if row is None:
        # 新发现：自定义策略表可能没有 "new"，退回 default 而不是直接 KeyError 崩掉
        strategy_name = "new"
        strategy = strategies.get("new") or default_strategy
        scan_count = 0
    else:
        scan_count = row[0]

    if strategy is None:
        raise ValueError("strategies 缺少 default 策略，无法计算下次重扫时间")
    next_scan = now + strategy["interval"]
    conn.execute(
        """INSERT INTO rescan_queue (ip, port, strategy, next_scan, scan_count, last_state, last_auth, last_online, last_scan)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(ip, port) DO UPDATE SET
               strategy=excluded.strategy,
               next_scan=excluded.next_scan,
               scan_count=scan_count+1,
               last_state=excluded.last_state,
               last_auth=excluded.last_auth,
               last_online=excluded.last_online,
               last_scan=excluded.last_scan""",
        (ip, port, strategy_name, next_scan, scan_count + 1,
         result.get("state", ""), result.get("auth", ""),
         result.get("players_online", 0), now)
    )
    conn.commit()
    return strategy_name


def get_due_rescans(db_path: str, now: int = None, limit: int = 100) -> list:
    """获取到期需要重扫的目标。"""
    if now is None:
        now = int(time.time())
    conn = get_conn(db_path)
    rows = conn.execute(
        "SELECT ip, port, strategy, scan_count, last_state, last_auth, last_online FROM rescan_queue WHERE next_scan <= ? ORDER BY next_scan ASC LIMIT ?",
        (now, limit)
    ).fetchall()
    return [{"ip": r[0], "port": r[1], "strategy": r[2], "scan_count": r[3],
             "last_state": r[4], "last_auth": r[5], "last_online": r[6]} for r in rows]


def claim_due(db_path: str, now: int = None, limit: int = 100,
              strategies: dict = None) -> list:
    """原子领取到期的重扫目标：同一事务内选出并顺延 next_scan。

    get_due_rescans 只读不标记，同一到期目标会被多轮/多 worker 反复取出重复扫描。
    这里在 BEGIN IMMEDIATE 事务内 SELECT + UPDATE，保证一个目标只会被领取一次。
    领取只推进 next_scan（不增加 scan_count），真正的扫描结果仍由 update_rescan 写。
    """
    if now is None:
        now = int(time.time())
    strategies = strategies or DEFAULT_STRATEGIES
    default_interval = (strategies.get("default") or {}).get("interval", 3600)

    conn = get_conn(db_path)
    if conn.in_transaction:
        conn.commit()
    claimed = []
    conn.execute("BEGIN IMMEDIATE")
    try:
        rows = conn.execute(
            "SELECT ip, port, strategy, scan_count, last_state, last_auth, last_online "
            "FROM rescan_queue WHERE next_scan <= ? ORDER BY next_scan ASC LIMIT ?",
            (now, limit)
        ).fetchall()
        for r in rows:
            interval = (strategies.get(r[2]) or {}).get("interval", default_interval)
            conn.execute("UPDATE rescan_queue SET next_scan = ? WHERE ip = ? AND port = ?",
                         (now + interval, r[0], r[1]))
            claimed.append({"ip": r[0], "port": r[1], "strategy": r[2], "scan_count": r[3],
                            "last_state": r[4], "last_auth": r[5], "last_online": r[6]})
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return claimed


def get_all_rescans(db_path: str, limit: int = 200) -> list:
    """获取全部重扫计划。"""
    conn = get_conn(db_path)
    rows = conn.execute(
        "SELECT ip, port, strategy, next_scan, scan_count, last_state, last_auth, last_online FROM rescan_queue ORDER BY next_scan ASC LIMIT ?",
        (limit,)
    ).fetchall()
    return [{"ip": r[0], "port": r[1], "strategy": r[2], "next_scan": r[3],
             "scan_count": r[4], "last_state": r[5], "last_auth": r[6], "last_online": r[7]} for r in rows]


def remove_rescan(db_path: str, ip: str, port: int):
    """移除某个目标的重扫计划。"""
    conn = get_conn(db_path)
    conn.execute("DELETE FROM rescan_queue WHERE ip=? AND port=?", (ip, port))
    conn.commit()


def clear_rescan(db_path: str):
    """清空重扫队列。"""
    conn = get_conn(db_path)
    conn.execute("DELETE FROM rescan_queue")
    conn.commit()


def get_stats(db_path: str) -> dict:
    """获取重扫队列统计。"""
    conn = get_conn(db_path)
    total = conn.execute("SELECT COUNT(*) FROM rescan_queue").fetchone()[0]
    by_strategy = {}
    for row in conn.execute("SELECT strategy, COUNT(*) FROM rescan_queue GROUP BY strategy"):
        by_strategy[row[0]] = row[1]
    now = int(time.time())
    due = conn.execute("SELECT COUNT(*) FROM rescan_queue WHERE next_scan <= ?", (now,)).fetchone()[0]
    return {"total": total, "by_strategy": by_strategy, "due_now": due}


def _determine_strategy(result: dict) -> str:
    """根据扫描结果确定重扫策略（原签名带 db_path/ip/port 但从未使用，已删除）。"""
    # 有人在线
    if result.get("players_online", 0) > 0:
        return "has_players"
    # 认证状态
    auth = result.get("auth", "")
    if auth == "cracked":
        return "cracked"
    if auth == "online":
        return "online"
    if auth == "whitelist":
        return "whitelist"
    return "default"
