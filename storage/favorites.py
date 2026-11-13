# -*- coding: utf-8 -*-
"""
收藏管理模块。
JSON 文件存储，支持标签、备注、自动重查、导入导出。
融合 a4v3l1 的收藏管理体验，融入 v3Pro 的扫描引擎。
"""
import json
import os
import tempfile
import threading
from datetime import datetime
from typing import Optional

# core.probe 会把 core.protocol/core.packets 整条链拖起来，
# 而收藏的增删改查根本用不到探测：延迟到 rescan 真正要发包时再导入。

# 可重入锁：读-改-写整段加锁，避免健康监控线程与 Web 操作并发丢更新
_LOCK = threading.RLock()
_DEFAULT_PATH = "favorites.json"


def _default_path() -> str:
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), _DEFAULT_PATH)


def load_favorites(path: str = None) -> list:
    """加载收藏列表，返回 [{ip, port, tags, note, added_at, last_check, last_info}, ...]"""
    path = path or _default_path()
    if not os.path.exists(path):
        return []
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
        if isinstance(data, dict) and "favorites" in data:
            return data["favorites"]
        return []
    except (json.JSONDecodeError, OSError):
        return []


def _write_atomic(favorites: list, path: str):
    """原子写盘：唯一临时名（mkstemp）→ fsync → os.replace。

    固定用 path + ".tmp" 会让多进程同时保存互相覆盖；不 fsync 则掉电可能丢数据。
    """
    directory = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp = tempfile.mkstemp(prefix=os.path.basename(path) + ".", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(favorites, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def save_favorites(favorites: list, path: str = None):
    """保存收藏列表到 JSON 文件（原子写：先写临时文件再替换，读取方不会读到半截文件）。"""
    path = path or _default_path()
    with _LOCK:
        try:
            _write_atomic(favorites, path)
        except (OSError, TypeError, ValueError) as e:
            # TypeError/ValueError 来自 json.dump（如集合不可序列化）：原实现会直接抛出，
            # 导致调用方的整段 mutation 丢失。这里统一记录，不向上炸。
            print(f"[!] 收藏保存失败: {e}")


def update_favorite(host: str, port: int, mutator, path: str = None,
                    create: bool = False) -> Optional[dict]:
    """收藏项的原子「读-改-写」入口（跨调用唯一安全的修改方式）。

    背景：load_favorites() → 内存修改 → save_favorites() 这组操作若不在锁内，
    健康监控线程会拿陈旧快照整文件回写，把并发新增/删除的收藏静默吞掉。
    所有需要跨函数调用的修改都必须走这里（带锁完成读、改、写三步）。

    mutator(fav) 在持锁状态下被调用：
      - fav 为命中项的 dict；create=True 且不存在时传入仅含 ip/port 的新 dict
      - 返回 dict 表示写回（通常返回同一个 fav，可原地改）；返回 None 表示放弃本次写盘
    返回写回后的 dict；未命中且 create=False 时返回 None。
    """
    with _LOCK:
        favorites = load_favorites(path)
        idx = _find(favorites, host, port)
        if idx < 0:
            if not create:
                return None
            fav = {"ip": host, "port": port}
            favorites.append(fav)
        else:
            fav = favorites[idx]
        result = mutator(fav)
        if result is None:
            # 放弃写盘：若是 create 临时追加的占位项要一并撤销
            if idx < 0:
                favorites.pop()
            return None
        if idx < 0:
            favorites[-1] = result
        else:
            favorites[idx] = result
        save_favorites(favorites, path)
        return result


def _find(favorites: list, ip: str, port: int) -> int:
    for i, fav in enumerate(favorites):
        if fav.get("ip") == ip and fav.get("port") == port:
            return i
    return -1


def add_favorite(ip: str, port: int, tags: list = None, note: str = "",
                 info: dict = None, path: str = None) -> dict:
    """添加收藏。已存在则更新标签和备注。"""
    def _apply(fav: dict) -> dict:
        now = datetime.now().isoformat()
        if "added_at" in fav:  # 已存在：只更新显式传入的字段
            if tags is not None:
                fav["tags"] = tags
            if note:
                fav["note"] = note
            if info:
                fav["last_info"] = info
                fav["last_check"] = now
        else:                   # 新增
            fav["tags"] = tags or []
            fav["note"] = note
            fav["added_at"] = now
            fav["last_check"] = now if info else None
            fav["last_info"] = info or None
        return fav
    return update_favorite(ip, port, _apply, path=path, create=True)


def remove_favorite(ip: str, port: int, path: str = None) -> bool:
    """移除收藏。返回是否成功移除。"""
    with _LOCK:
        favorites = load_favorites(path)
        idx = _find(favorites, ip, port)
        if idx < 0:
            return False
        favorites.pop(idx)
        save_favorites(favorites, path)
    return True


def update_tags(ip: str, port: int, tags: list, path: str = None) -> Optional[dict]:
    """更新收藏的标签。"""
    def _apply(fav: dict) -> dict:
        fav["tags"] = tags
        return fav
    return update_favorite(ip, port, _apply, path=path)


def update_note(ip: str, port: int, note: str, path: str = None) -> Optional[dict]:
    """更新收藏的备注。"""
    def _apply(fav: dict) -> dict:
        fav["note"] = note
        return fav
    return update_favorite(ip, port, _apply, path=path)


def is_favorite(ip: str, port: int, path: str = None) -> bool:
    """检查是否已收藏。"""
    return _find(load_favorites(path), ip, port) >= 0


def update_from_probe(ip: str, port: int, info: dict, path: str = None,
                      force: bool = False) -> Optional[dict]:
    """用一次探测结果更新收藏。

    在线：刷新 last_info 和 last_good_info（保留最近一次在线时的完整信息）。
    离线：只记录离线状态，不覆盖 last_good_info（上次在线信息）。
    内容无变化时不写盘（避免监控每轮重写文件）；force=True 时强制更新 last_check 并写盘。
    """
    if not info:
        return None

    def _apply(fav: dict):
        now = datetime.now().isoformat()
        changed = False
        if info.get("state") == "up":
            clean = {k: v for k, v in info.items() if k != "_raw"}
            if fav.get("last_info") != clean:
                fav["last_info"] = clean
                changed = True
            if fav.get("last_good_info") != clean:
                fav["last_good_info"] = clean
                changed = True
        else:
            # 离线：不覆盖上次在线信息
            if (fav.get("last_info") or {}).get("state") == "up":
                if fav.get("last_good_info") != fav["last_info"]:
                    fav["last_good_info"] = fav["last_info"]
                    changed = True
            offline = {"state": "offline", "error": info.get("error", "")}
            if fav.get("last_info") != offline:
                fav["last_info"] = offline
                changed = True
        if changed or force:
            fav["last_check"] = now
            return fav
        return None  # 无变化时不写盘（避免监控每轮重写文件）

    return update_favorite(ip, port, _apply, path=path)


def rescan_one(ip: str, port: int, timeout: float = 5.0, path: str = None) -> Optional[dict]:
    """重新探测单个收藏服务器，更新 last_info 和 last_check。
    离线时保留上次在线信息（last_good_info）。"""
    from core.probe import auth_probe, slp_probe

    info = slp_probe(ip, port, timeout=timeout)
    if not info or info.get("state") != "up":
        info = {"state": "offline", "error": info.get("error", "") if info else "unreachable"}
    else:
        # SLP成功后做认证模式检测（cracked/online/unknown）
        try:
            auth = auth_probe(ip, port, info.get("proto", 0), timeout=timeout)
            if auth:
                info["auth"] = auth.get("state", "unknown")
                info["auth_detail"] = auth.get("detail", "")
                info["plugin_channels"] = auth.get("plugin_channels", [])
        except Exception:
            pass
    update_from_probe(ip, port, info, path=path, force=True)
    return info


def rescan_all(timeout: float = 5.0, workers: int = 10, path: str = None,
               progress_callback=None) -> list:
    """重新探测所有收藏服务器。离线时保留上次在线信息。返回更新后的收藏列表。

    注意：耗时的网络探测必须在锁外执行。原实现在整个线程池探测期间持有全局 _LOCK，
    单个超时目标就能把 add/remove/tags/note 与健康监控回写全部阻塞数秒（实测 5.68s），
    收藏上千条时等于整个收藏子系统卡死。
    """
    import concurrent.futures
    favorites = load_favorites(path)
    if not favorites:
        return []
    results = {}
    def _probe_with_auth(ip, port):
        from core.probe import auth_probe, slp_probe

        info = slp_probe(ip, port, timeout=timeout)
        if info and info.get("state") == "up":
            try:
                auth = auth_probe(ip, port, info.get("proto", 0), timeout=timeout)
                if auth:
                    info["auth"] = auth.get("state", "unknown")
                    info["auth_detail"] = auth.get("detail", "")
                    info["plugin_channels"] = auth.get("plugin_channels", [])
            except Exception:
                pass
        return info
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {}
        for fav in favorites:
            fut = ex.submit(_probe_with_auth, fav["ip"], fav["port"])
            futures[fut] = (fav["ip"], fav["port"])
        done = 0
        for fut in concurrent.futures.as_completed(futures):
            ip, port = futures[fut]
            try:
                info = fut.result()
                if info and info.get("state") == "up":
                    results[(ip, port)] = {k: v for k, v in info.items() if k != "_raw"}
                else:
                    results[(ip, port)] = {"state": "offline",
                                           "error": info.get("error", "") if info else "unreachable"}
            except Exception:
                results[(ip, port)] = {"state": "offline", "error": "probe error"}
            done += 1
            if progress_callback:
                progress_callback(done, len(favorites))
    # 只把「重新读当前状态 + 合并探测结果 + 写盘」放进临界区，
    # 这样探测期间发生的 add/remove 不会被这份快照覆盖掉。
    now = datetime.now().isoformat()
    with _LOCK:
        current = load_favorites(path)
        for fav in current:
            key = (fav["ip"], fav["port"])
            if key in results:
                fav["last_check"] = now
                res = results[key]
                if res.get("state") == "up":
                    fav["last_info"] = res
                    fav["last_good_info"] = res
                else:
                    # 离线：不覆盖上次在线信息
                    if (fav.get("last_info") or {}).get("state") == "up":
                        fav["last_good_info"] = fav["last_info"]
                    fav["last_info"] = res
        save_favorites(current, path)
    return current


# 手写导入上限：防止超大上传逐行解析打满 CPU/磁盘
_MAX_IMPORT_LINES = 100000


def import_favorites(filepath: str, path: str = None) -> tuple:
    """从文件导入收藏，支持 JSON（完整字段）和 TXT（仅 ip:port）。

    JSON 格式恢复：ip, port, tags, note, added_at, last_check, last_info, last_good_info。
    TXT 格式：每行 ip:port 或 ip，tags/note 为空。

    返回 (成功条数, 失败行列表)。
    失败行格式为 (行号, 原文)。
    """
    if not os.path.exists(filepath):
        return 0, []
    parsed = []
    failed = []
    truncated = False
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
    except OSError as e:
        print(f"[!] 收藏导入读取失败: {e}")
        return 0, failed

    # 尝试 JSON 解析（导出的 JSON 格式）
    stripped = content.lstrip()
    if stripped.startswith('{') or stripped.startswith('['):
        try:
            data = json.loads(content)
            if isinstance(data, dict):
                # 兼容收藏导出(favorites)、扫描结果(results)、数据库导出(servers)
                data = data.get("favorites", data.get("results", data.get("servers", [])))
            if isinstance(data, list):
                for item in data:
                    if not isinstance(item, dict) or not item.get("ip"):
                        continue
                    try:
                        port = int(item.get("port", 25565))
                        if not (0 < port < 65536):
                            continue
                    except (ValueError, TypeError):
                        continue
                    parsed.append({
                        "ip": item["ip"],
                        "port": port,
                        "tags": item.get("tags", []) or [],
                        "note": item.get("note", "") or "",
                        "added_at": item.get("added_at") or datetime.now().isoformat(),
                        "last_check": item.get("last_check"),
                        "last_info": item.get("last_info"),
                        "last_good_info": item.get("last_good_info"),
                    })
            if parsed:
                _write_imported(parsed, path)
                return len(parsed), []
        except (json.JSONDecodeError, ValueError):
            pass  # 不是有效 JSON，回退到 TXT 解析

    # TXT 格式：每行 ip:port
    for lineno, line in enumerate(content.strip().splitlines(), 1):
        if lineno > _MAX_IMPORT_LINES:
            truncated = True
            break
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        try:
            if ':' in line:
                parts = line.rsplit(':', 1)
                ip, port = parts[0].strip(), int(parts[1])
            else:
                ip, port = line, 25565
            if not ip:
                raise ValueError("IP 为空")
            if not (0 < port < 65536):
                raise ValueError(f"端口越界: {port}")
        except (ValueError, IndexError):
            failed.append((lineno, line))
            continue
        parsed.append({"ip": ip, "port": port, "tags": [], "note": "",
                       "added_at": datetime.now().isoformat(),
                       "last_check": None, "last_info": None, "last_good_info": None})

    if truncated:
        print(f"[!] 收藏导入超过 {_MAX_IMPORT_LINES} 行，已截断")

    if parsed:
        _write_imported(parsed, path)
    return len(parsed), failed


def _write_imported(entries: list, path: str = None):
    """将解析好的收藏条目写入文件，已存在的跳过不覆盖。"""
    with _LOCK:
        favorites = load_favorites(path)
        for entry in entries:
            if _find(favorites, entry["ip"], entry["port"]) >= 0:
                continue  # 已收藏的不覆盖原有标签/备注
            favorites.append(entry)
        save_favorites(favorites, path)


def import_from_file(filepath: str, path: str = None) -> int:
    """从文本文件导入收藏（每行 ip:port），返回成功条数。

    保留旧的「只返回条数」签名以兼容 web/routes_data.py；需要失败行明细请用
    import_favorites()（返回 (成功条数, 失败行列表)）。
    """
    count, _failed = import_favorites(filepath, path=path)
    return count


def get_all_tags(path: str = None) -> list:
    """获取所有标签（去重排序）。"""
    favorites = load_favorites(path)
    tags = set()
    for fav in favorites:
        for t in fav.get("tags", []):
            tags.add(t)
    return sorted(tags)


def filter_favorites(tag: str = None, search: str = None, path: str = None) -> list:
    """按标签或关键词筛选收藏。"""
    favorites = load_favorites(path)
    result = []
    for fav in favorites:
        if tag and tag not in fav.get("tags", []):
            continue
        if search:
            haystack = f"{fav['ip']}:{fav['port']} {fav.get('note', '')} {' '.join(fav.get('tags', []))}"
            info = fav.get("last_info") or {}
            good = fav.get("last_good_info") or (info if info.get("state") == "up" else {})
            haystack += f" {good.get('version', '')} {good.get('motd', '')}"
            if search.lower() not in haystack.lower():
                continue
        result.append(fav)
    return result
