# -*- coding: utf-8 -*-
"""
玩家历史追踪（v3.2.1 新增，融合 matscan 特性）。
记录每个玩家在各服务器的出现/消失/次数，支持按玩家名或服务器查询。
"""
from datetime import datetime, timezone

from storage.db import get_conn

PLAYER_HISTORY_SCHEMA = """
CREATE TABLE IF NOT EXISTS player_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    player_name TEXT NOT NULL,
    player_uuid TEXT DEFAULT '',
    first_seen TEXT,
    last_seen TEXT,
    seen_count INTEGER DEFAULT 1,
    UNIQUE(ip, port, player_name)
);
CREATE INDEX IF NOT EXISTS idx_ph_player ON player_history(player_name);
CREATE INDEX IF NOT EXISTS idx_ph_server ON player_history(ip, port);
CREATE INDEX IF NOT EXISTS idx_ph_last_seen ON player_history(last_seen);
"""


def init_player_history(db_path: str):
    """初始化玩家历史表。"""
    conn = get_conn(db_path)
    conn.executescript(PLAYER_HISTORY_SCHEMA)
    conn.commit()


def update_players(db_path: str, ip: str, port: int, player_list: list):
    """
    更新一批玩家的历史记录。
    player_list: [{"name": "...", "id": "..."}, ...] 或 ["name1", "name2", ...]
    """
    if not player_list:
        return
    now = datetime.now(timezone.utc).isoformat()
    conn = get_conn(db_path)
    # 同一批里同名玩家只算一次：否则一次扫描的重复名单会让 seen_count 虚高
    seen_names = set()
    for player in player_list:
        if isinstance(player, dict):
            name = player.get("name", "")
            uuid = player.get("id", "")
        else:
            name = str(player)
            uuid = ""
        if not name or name in seen_names:
            continue
        seen_names.add(name)
        conn.execute(
            """INSERT INTO player_history (ip, port, player_name, player_uuid, first_seen, last_seen, seen_count)
               VALUES (?, ?, ?, ?, ?, ?, 1)
               ON CONFLICT(ip, port, player_name) DO UPDATE SET
                   last_seen=excluded.last_seen,
                   seen_count=seen_count+1,
                   player_uuid=COALESCE(NULLIF(excluded.player_uuid,''), player_uuid)""",
            (ip, port, name, uuid, now, now)
        )
    conn.commit()


def get_player_history(db_path: str, player_name: str = None,
                        ip: str = None, port: int = None,
                        limit: int = 100, offset: int = 0) -> list:
    """
    查询玩家历史。
    可按玩家名、服务器IP:Port过滤。
    """
    # 显式列名：schema 增列时 SELECT * 会与下面的手写列顺序列表错位
    cols = ["id", "ip", "port", "player_name", "player_uuid", "first_seen", "last_seen", "seen_count"]
    # 分页边界：limit<=0 时 SQLite 的 LIMIT -1 表示无上限
    limit = int(limit)
    offset = max(0, int(offset))
    if limit <= 0:
        limit = 100
    limit = min(limit, 10000)
    conn = get_conn(db_path)
    sql = "SELECT " + ", ".join(cols) + " FROM player_history WHERE 1=1"
    args = []
    if player_name:
        sql += " AND player_name LIKE ?"
        args.append(f"%{player_name}%")
    if ip:
        sql += " AND ip = ?"
        args.append(ip)
        if port:
            sql += " AND port = ?"
            args.append(port)
    sql += " ORDER BY last_seen DESC LIMIT ? OFFSET ?"
    args.extend([limit, offset])
    rows = conn.execute(sql, args).fetchall()
    return [dict(zip(cols, r)) for r in rows]


def get_unique_players(db_path: str) -> int:
    """获取追踪到的唯一玩家数。"""
    conn = get_conn(db_path)
    count = conn.execute("SELECT COUNT(DISTINCT player_name) FROM player_history").fetchone()[0]
    return count


def get_player_servers(db_path: str, player_name: str) -> list:
    """获取某个玩家出现过的所有服务器。"""
    conn = get_conn(db_path)
    rows = conn.execute(
        "SELECT ip, port, seen_count, last_seen FROM player_history WHERE player_name = ? ORDER BY last_seen DESC",
        (player_name,)
    ).fetchall()
    return [{"ip": r[0], "port": r[1], "seen_count": r[2], "last_seen": r[3]} for r in rows]


def get_server_players(db_path: str, ip: str, port: int, limit: int = 50) -> list:
    """获取某台服务器追踪到的所有玩家。"""
    conn = get_conn(db_path)
    rows = conn.execute(
        "SELECT player_name, seen_count, last_seen, first_seen FROM player_history WHERE ip=? AND port=? ORDER BY last_seen DESC LIMIT ?",
        (ip, port, limit)
    ).fetchall()
    return [{"name": r[0], "seen_count": r[1], "last_seen": r[2], "first_seen": r[3]} for r in rows]


def clean_old_players(db_path: str, retention_days: int = 90) -> int:
    """清理长期未再出现的玩家记录（表原本只增不减）。retention_days<=0 时不清。"""
    if retention_days <= 0:
        return 0
    from datetime import timedelta
    cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()
    conn = get_conn(db_path)
    cursor = conn.execute("DELETE FROM player_history WHERE last_seen < ?", (cutoff,))
    deleted = cursor.rowcount
    conn.commit()
    return deleted


def get_stats(db_path: str) -> dict:
    """获取玩家历史统计。"""
    conn = get_conn(db_path)
    total_records = conn.execute("SELECT COUNT(*) FROM player_history").fetchone()[0]
    unique_players = conn.execute("SELECT COUNT(DISTINCT player_name) FROM player_history").fetchone()[0]
    unique_servers = conn.execute("SELECT COUNT(DISTINCT ip || ':' || port) FROM player_history").fetchone()[0]
    return {
        "total_records": total_records,
        "unique_players": unique_players,
        "unique_servers": unique_servers,
    }
