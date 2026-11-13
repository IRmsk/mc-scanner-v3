# -*- coding: utf-8 -*-
"""
SQLite 存储层。
支持去重更新、按认证/模组/核心类型/搜索查询、统计。
v3.1 新增：core_type、mods、forge_channels 字段（自动迁移旧数据库）。
"""
import atexit
import json
import os
import sqlite3
import threading
from datetime import datetime, timedelta, timezone

import logger

# 线程局部连接池：每个线程每个db_path复用一个连接，避免频繁创建
_local = threading.local()
# 全局连接注册表，用于程序退出时统一关闭（防文件描述符泄漏）
_all_conns = []
_all_conns_lock = threading.Lock()

# 每个线程最多缓存的连接数。db_path 可由请求参数控制（web/state.py 只限「纯 *.db 文件名」），
# 不设上限时每个新 db 名都会常驻一条连接，攻击者用 ?db_path=x1.db、x2.db… 即可耗尽 fd/内存。
_MAX_CONNS_PER_THREAD = 8
# init_db 的进程级互斥：并发初始化会触发 duplicate column / database is locked，
# 甚至留下半迁移 schema；跨进程的并发由事务里的 BEGIN IMMEDIATE 兜底。
_INIT_LOCK = threading.Lock()


def _register_conn(conn):
    with _all_conns_lock:
        _all_conns.append(conn)


def _unregister_conn(conn):
    """按对象身份从注册表移除（list.remove 走 ==，不适合 sqlite 连接）。"""
    with _all_conns_lock:
        for i, c in enumerate(_all_conns):
            if c is conn:
                del _all_conns[i]
                break


def _close_conn_obj(conn):
    """关闭连接并同步清理注册表/线程缓存，避免关闭后又被 get_conn 复用到。"""
    try:
        conn.close()
    except Exception:
        pass
    _unregister_conn(conn)
    conns = getattr(_local, "conns", None)
    if conns:
        for path, c in list(conns.items()):
            if c is conn:
                del conns[path]
    order = getattr(_local, "order", None)
    if order is not None:
        alive = set(getattr(_local, "conns", {}).keys())
        _local.order = [p for p in order if p in alive]


def close_conn(db_path: str = None):
    """关闭当前线程缓存的连接（path 为空则全部）。供测试与长驻进程回收连接用。"""
    conns = getattr(_local, "conns", None)
    if not conns:
        return
    if db_path is None:
        for conn in list(conns.values()):
            _close_conn_obj(conn)
    else:
        conn = conns.get(db_path)
        if conn is not None:
            _close_conn_obj(conn)


def close_all():
    """关闭所有线程登记过的连接（进程退出或测试清理）。"""
    with _all_conns_lock:
        conns = list(_all_conns)
    for conn in conns:
        try:
            conn.close()
        except Exception:
            pass
    with _all_conns_lock:
        _all_conns.clear()
    # 线程局部缓存同步失效，否则会复用已关闭的连接
    if hasattr(_local, "conns"):
        _local.conns = {}
        _local.order = []


@atexit.register
def _close_all_conns():
    close_all()


def get_conn(db_path: str):
    """获取线程局部持久连接（首次创建时设置PRAGMA，后续复用）。"""
    if not hasattr(_local, 'conns'):
        _local.conns = {}
        _local.order = []          # LRU：最近使用过的 db_path 排在末尾
    conns = _local.conns
    if db_path in conns:
        try:
            _local.order.remove(db_path)
        except ValueError:
            pass
        _local.order.append(db_path)
        return conns[db_path]
    conn = sqlite3.connect(db_path, check_same_thread=False, timeout=30)
    # WAL 在不支持的文件系统上会静默退化为 delete 模式，这里留痕以免并发假设失效
    mode = conn.execute("PRAGMA journal_mode=WAL").fetchone()
    if not mode or str(mode[0]).lower() != "wal":
        logger.warning(f"journal_mode 未能切换为 WAL（当前 {mode}）: {db_path}")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA temp_store=MEMORY")
    conns[db_path] = conn
    _local.order.append(db_path)
    _register_conn(conn)
    # 超出上限时淘汰最久未用的连接并真正 close，防止连接只增不减
    while len(_local.order) > _MAX_CONNS_PER_THREAD:
        old_path = _local.order.pop(0)
        old_conn = conns.pop(old_path, None)
        if old_conn is not None:
            try:
                old_conn.close()
            except Exception:
                pass
            _unregister_conn(old_conn)
    return conn

SCHEMA = """
CREATE TABLE IF NOT EXISTS servers (
    ip TEXT,
    port INTEGER,
    version TEXT,
    proto INTEGER,
    motd TEXT,
    is_modded INTEGER,
    players_online INTEGER,
    players_max INTEGER,
    favicon TEXT,
    auth TEXT,
    ping_ms INTEGER,
    json TEXT,
    last_updated TEXT,
    core_type TEXT,
    mods TEXT,
    forge_channels TEXT,
    fingerprint TEXT,
    PRIMARY KEY (ip, port)
);
CREATE TABLE IF NOT EXISTS server_popularity (
    ip TEXT,
    port INTEGER,
    players_online INTEGER,
    players_max INTEGER,
    recorded_at TEXT,
    PRIMARY KEY (ip, port, recorded_at)
);
CREATE INDEX IF NOT EXISTS idx_popularity_ip_port ON server_popularity(ip, port);
"""

UPSERT_SQL = """
    INSERT INTO servers (ip, port, version, proto, motd, is_modded, players_online,
                         players_max, favicon, auth, ping_ms, json, last_updated,
                         core_type, mods, forge_channels, fingerprint)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(ip, port) DO UPDATE SET
        version=excluded.version, proto=excluded.proto, motd=excluded.motd,
        is_modded=excluded.is_modded, players_online=excluded.players_online,
        players_max=excluded.players_max, favicon=excluded.favicon,
        auth=excluded.auth, ping_ms=excluded.ping_ms,
        json=excluded.json, last_updated=excluded.last_updated,
        core_type=excluded.core_type, mods=excluded.mods,
        forge_channels=excluded.forge_channels, fingerprint=excluded.fingerprint
"""

# 需要确保存在的列（用于旧数据库自动迁移）
_REQUIRED_COLUMNS = {
    "core_type": "TEXT",
    "mods": "TEXT",
    "forge_channels": "TEXT",
    "fingerprint": "TEXT",
}

QUERY_COLS = ["ip", "port", "version", "proto", "motd", "is_modded",
              "players_online", "players_max", "favicon", "auth", "ping_ms",
              "last_updated", "core_type", "mods", "forge_channels", "fingerprint"]

# 单次查询的行数硬上限（导出接口 web/routes_data.py 用 20000，故上限须高于它）
_MAX_QUERY_LIMIT = 50000


def _migrate(conn):
    """检查并添加缺失的列（旧数据库自动升级）。"""
    existing = {row[1] for row in conn.execute("PRAGMA table_info(servers)").fetchall()}
    for col, col_type in _REQUIRED_COLUMNS.items():
        if col not in existing:
            conn.execute(f"ALTER TABLE servers ADD COLUMN {col} {col_type}")


def init_db(db_path: str):
    # 进程级互斥：多线程并发初始化会互相看到「列刚建了一半」的中间态，
    # 报 duplicate column name / no such column / database is locked。
    with _INIT_LOCK:
        conn = get_conn(db_path)
        conn.executescript(SCHEMA)   # executescript 会隐式提交，只用来建基础表
        if conn.in_transaction:
            conn.commit()
        # 迁移 + 建索引放进同一个事务（BEGIN IMMEDIATE 同时拿到写锁，跨进程也串行）
        conn.execute("BEGIN IMMEDIATE")
        try:
            _migrate(conn)
            # 二级索引：加速过滤和排序
            conn.execute("CREATE INDEX IF NOT EXISTS idx_servers_auth ON servers(auth)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_servers_core_type ON servers(core_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_servers_is_modded ON servers(is_modded)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_servers_last_updated ON servers(last_updated)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_servers_players_online ON servers(players_online)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_servers_ip_port ON servers(ip, port)")
        except Exception:
            conn.rollback()
            raise          # 迁移失败必须暴露，否则后续只会表现为 no such table/column
        conn.commit()
    # v3.2.1: 初始化扩展表（玩家历史、重扫队列）
    try:
        from storage import player_history, rescan
    except ModuleNotFoundError as e:
        # 只忽略「模块确实不存在」；原来 except ImportError 会把子模块初始化的
        # ImportError 一并吞掉，之后表现为玩家历史表不存在的怪象。
        logger.warning(f"跳过扩展表初始化（模块缺失）: {e}")
        return
    player_history.init_player_history(db_path)
    rescan.init_rescan_queue(db_path)


def upsert_server(db_path: str, rec: dict):
    conn = get_conn(db_path)
    conn.execute(UPSERT_SQL, _record_to_tuple(rec))
    conn.commit()


def upsert_many(db_path: str, records: list) -> int:
    if not records:
        return 0
    conn = get_conn(db_path)
    rows = [_record_to_tuple(r) for r in records]
    conn.executemany(UPSERT_SQL, rows)
    # 记录人数趋势
    try:
        # 时间戳精确到秒，而主键是 (ip, port, recorded_at)：同一秒内重复 upsert
        # 同一台服务器（批量导入、多线程引擎回写）必然撞主键。裸 INSERT 时
        # executemany 整体失败，一次冲突就把这一批的趋势数据全丢掉，还刷一条警告。
        now = _utc_now_str()
        pop_rows = [(r.get('ip'), r.get('port'), r.get('players_online', 0), r.get('players_max', 0), now)
                    for r in records if r.get('players_online', 0) > 0]
        if pop_rows:
            conn.executemany(
                'INSERT OR REPLACE INTO server_popularity '
                '(ip, port, players_online, players_max, recorded_at) VALUES (?,?,?,?,?)',
                pop_rows
            )
    except Exception as e:
        # 人数趋势是附加数据，失败不阻塞主流程，但要留痕（原为静默吞错，难排查）
        logger.warning(f"记录人数趋势失败: {e}")
    conn.commit()
    return len(rows)


def _utc_now_str() -> str:
    """统一的写库时间戳：UTC 的 '%Y-%m-%d %H:%M:%S'。

    原实现用 isoformat()（'2026-01-01T03:00:00+00:00'），而 web 健康监控写的是
    strftime('%Y-%m-%d %H:%M:%S')，查询侧又用字符串比较 recorded_at > datetime('now', ?)。
    由于 'T'(0x54) > ' '(0x20)，同日但更早的记录会被错误算进 24 小时窗口。
    统一成空格分隔格式后，字符串比较与 datetime('now') 的语义一致。
    """
    return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')


# 大字段入库上限
_MAX_JSON_TEXT = 2000
_MAX_MODS_ITEMS = 200
_MAX_FAVICON_LEN = 20480


def _dump_limited(value, limit: int = _MAX_JSON_TEXT, max_items: int = None,
                  empty: str = "[]") -> str:
    """把值序列化成「长度受限且一定合法」的 JSON 文本。

    原实现 json.dumps(...)[:2000] 是按字符截断，截出来的是非法 JSON；
    _row_to_dict 解析失败后只能静默回退成 []/{}，前端无法区分「真没数据」和「被截断」。
    这里改为按元素裁剪：先限个数，再逐步减半，宁可少存也保证可解析。
    """
    if isinstance(value, list):
        items = value[:max_items] if (max_items and len(value) > max_items) else value
        text = json.dumps(items, ensure_ascii=False)
        n = len(items)
        while len(text) > limit and n > 0:
            n //= 2
            text = json.dumps(items[:n], ensure_ascii=False)
        return text if len(text) <= limit else "[]"
    text = json.dumps(value, ensure_ascii=False)
    if len(text) <= limit:
        return text
    # dict/标量无法安全裁剪，退回空结构，绝不做字符截断
    return empty


def _record_to_tuple(rec: dict) -> tuple:
    mods = rec.get("mods")
    if mods is not None and not isinstance(mods, str):
        mods = _dump_limited(mods, max_items=_MAX_MODS_ITEMS, empty="[]")
    channels = rec.get("forge_channels")
    if channels is not None and not isinstance(channels, str):
        channels = _dump_limited(channels, empty="[]")
    fp = rec.get("fingerprint")
    if fp is not None and not isinstance(fp, str):
        fp = _dump_limited(fp, empty="{}")
    # favicon 是 base64 图片：按字符截断会破坏 base64/PNG，超限就整块丢弃并留痕
    favicon = rec.get('favicon')
    if favicon is not None and isinstance(favicon, str) and len(favicon) > _MAX_FAVICON_LEN:
        logger.warning(f"favicon 超长({len(favicon)}字符)，已丢弃: {rec.get('ip')}:{rec.get('port')}")
        favicon = None
    return (
        rec.get('ip'), rec.get('port'),
        rec.get('version'), rec.get('proto'),
        rec.get('motd'), rec.get('is_modded', 0),
        rec.get('players_online', 0), rec.get('players_max', 0),
        favicon, rec.get('auth', 'unknown'),
        rec.get('ping_ms'), rec.get('json'),
        _utc_now_str(),
        rec.get('core_type', 'unknown'),
        mods,
        channels,
        fp,
    )


def _row_to_dict(row, cols):
    d = dict(zip(cols, row))
    for key, fallback in (("mods", []), ("forge_channels", []), ("fingerprint", {})):
        val = d.get(key)
        if val and isinstance(val, str):
            try:
                d[key] = json.loads(val)
            except (json.JSONDecodeError, TypeError):
                # 旧版按字符截断留下的脏数据；留痕而不是完全静默
                logger.warning(f"字段 {key} 不是合法 JSON，已回退为空值: {val[:80]!r}")
                d[key] = fallback
    return d


def _escape_like(s: str) -> str:
    return s.replace("\\", "\\\\").replace("%", r"\%").replace("_", r"\_")


def query(db_path: str, auth: str = None, modded: int = None,
          core_type: str = None, search: str = None,
          only_online: bool = False,
          limit: int = 200, offset: int = 0) -> list:
    # 分页边界必须在存储层强制，不能只依赖调用方：
    # SQLite 中 LIMIT -1 表示「无上限」，?limit=-1 一条请求就能把整库读进内存。
    try:
        limit = int(limit)
    except (TypeError, ValueError):
        limit = 200
    try:
        offset = int(offset)
    except (TypeError, ValueError):
        offset = 0
    if limit <= 0:
        limit = 1000
    limit = min(limit, _MAX_QUERY_LIMIT)   # 上限取 50000：导出接口硬编码 20000，不能砍到它以下
    offset = max(0, offset)
    conn = get_conn(db_path)
    sql = "SELECT " + ", ".join(QUERY_COLS) + " FROM servers"
    conds, args = [], []
    if auth:
        conds.append("auth = ?")
        args.append(auth)
    if modded is not None:
        conds.append("is_modded = ?")
        args.append(1 if modded else 0)
    if core_type:
        conds.append("core_type = ?")
        args.append(core_type)
    if only_online:
        conds.append("players_online > 0")
    if search:
        conds.append("(motd LIKE ? ESCAPE '\\' OR version LIKE ? ESCAPE '\\' OR ip LIKE ? ESCAPE '\\')")
        escaped = f"%{_escape_like(search)}%"
        args += [escaped] * 3
    if conds:
        sql += " WHERE " + " AND ".join(conds)
    sql += " ORDER BY last_updated DESC LIMIT ? OFFSET ?"
    args += [limit, offset]
    rows = conn.execute(sql, args).fetchall()
    return [_row_to_dict(r, QUERY_COLS) for r in rows]


def count(db_path: str, auth: str = None, modded: int = None,
          core_type: str = None, search: str = None,
          only_online: bool = False) -> int:
    conn = get_conn(db_path)
    sql = "SELECT COUNT(*) FROM servers"
    conds, args = [], []
    if auth:
        conds.append("auth = ?")
        args.append(auth)
    if modded is not None:
        conds.append("is_modded = ?")
        args.append(1 if modded else 0)
    if core_type:
        conds.append("core_type = ?")
        args.append(core_type)
    if only_online:
        conds.append("players_online > 0")
    if search:
        conds.append("(motd LIKE ? ESCAPE '\\' OR version LIKE ? ESCAPE '\\' OR ip LIKE ? ESCAPE '\\')")
        escaped = f"%{_escape_like(search)}%"
        args += [escaped] * 3
    if conds:
        sql += " WHERE " + " AND ".join(conds)
    total = conn.execute(sql, args).fetchone()[0]
    return total


def clean_old_records(db_path: str, retention_days: int = 30, only_offline: bool = True) -> int:
    """清理超旧记录。retention_days=0时不清理。
    only_offline=True时只清理离线且超旧的服务器，保留有人的记录。
    返回删除条数。
    """
    if retention_days <= 0:
        return 0
    conn = get_conn(db_path)
    # 与写入格式保持一致（_utc_now_str 的 '%Y-%m-%d %H:%M:%S'）
    cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).strftime('%Y-%m-%d %H:%M:%S')
    if only_offline:
        cursor = conn.execute(
            "DELETE FROM servers WHERE last_updated < ? AND (players_online IS NULL OR players_online = 0)",
            (cutoff,)
        )
    else:
        cursor = conn.execute("DELETE FROM servers WHERE last_updated < ?", (cutoff,))
    deleted = cursor.rowcount
    conn.commit()
    return deleted


def stats(db_path: str) -> dict:
    conn = get_conn(db_path)
    total = conn.execute("SELECT COUNT(*) FROM servers").fetchone()[0]
    by_auth = {r[0]: r[1] for r in conn.execute(
        "SELECT auth, COUNT(*) FROM servers GROUP BY auth")}
    online_servers = conn.execute(
        "SELECT COUNT(*) FROM servers WHERE players_online > 0").fetchone()[0]
    by_version = {}
    try:
        by_version = {(r[0] or '未知'): r[1] for r in conn.execute(
            "SELECT version, COUNT(*) FROM servers GROUP BY version ORDER BY COUNT(*) DESC LIMIT 20")}
    except Exception:
        pass
    by_auth = {(k or '未知'): v for k, v in by_auth.items()}
    by_core = {}
    try:
        by_core = {r[0]: r[1] for r in conn.execute(
            "SELECT core_type, COUNT(*) FROM servers WHERE core_type IS NOT NULL AND core_type != '' GROUP BY core_type ORDER BY COUNT(*) DESC")}
    except Exception:
        pass
    return {
        "total": total,
        "by_auth": by_auth,
        "online_servers": online_servers,
        "by_version": by_version,
        "by_core": by_core,
    }


def default_db_path() -> str:
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'mcscanner.db')
