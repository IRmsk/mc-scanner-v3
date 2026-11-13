# -*- coding: utf-8 -*-
"""Health monitor loop."""
import json
import os
import sqlite3
from datetime import datetime, timezone

import config
from core.notifier import _html_escape

try:
    from web import state
except ImportError:
    import state  # type: ignore
health_monitor = state.health_monitor
scan_lock = state.scan_lock
health_lock = state.health_lock

def _log(msg):
    state.log_scan(msg)


def _health_monitor_loop(once=False):
    """后台健康监控线程：定期检查收藏的服务器，状态/人数变化时记录，一轮汇总发一封邮件。
    once=True 时只跑一轮就返回（供 Web "立即检查"按钮调用）。"""
    import asyncio

    from scanner.async_probe import async_slp_probe
    db_path = config.get("db_path", "mcscanner.db")
    _log(f"[健康监控] {'启动单次手动检查' if once else '启动定时监控'}")
    while not health_monitor["stop_event"].is_set():
        # 每轮重读配置，Web 面板改完下一轮即生效，无需重启
        #   health_probe_concurrency: 同时探测的最大服务器数（默认3，保守温和）
        #   health_probe_ip_gap:      同一IP两次探测最小间隔秒（不同IP不受限）
        #   health_interval:          每轮间隔秒数（默认300，最小60）
        probe_concurrency = max(1, min(int(config.get("health_probe_concurrency", 8)), 20))
        probe_ip_gap = max(0.0, float(config.get("health_probe_ip_gap", 1.5)))
        probe_interval = max(60, int(config.get("health_interval", 300)))
        health_monitor["interval"] = probe_interval
        # 本轮收集到变化的服务器（用于汇总邮件）
        changed_servers = []  # [{ip, port, prev, curr, joined, left, player_names, new_players, left_players}]
        try:
            # 从收藏列表获取服务器
            targets = []
            try:
                from storage.favorites import filter_favorites
                favs = filter_favorites()
                targets = [(f['ip'], f['port']) for f in favs]
            except Exception:
                # 兜底：直接读收藏文件（与 favorites 模块默认路径一致）
                fav_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'favorites.json')
                if os.path.exists(fav_file):
                    try:
                        with open(fav_file, 'r', encoding='utf-8') as f:
                            favs = json.load(f)
                        if isinstance(favs, list):
                            targets = [(f['ip'], f['port']) for f in favs]
                        elif isinstance(favs, dict) and 'servers' in favs:
                            targets = [(f['ip'], f['port']) for f in favs['servers']]
                    except Exception:
                        pass
            # 也从数据库取有人过的服务器（默认关闭，只监控收藏）
            if config.get("health_monitor_db_extra", False):
                conn = None
                try:
                    conn = sqlite3.connect(db_path)
                    rows = conn.execute("SELECT ip, port FROM servers WHERE players_online > 0 LIMIT 20").fetchall()
                    for ip, port in rows:
                        if (ip, port) not in targets:
                            targets.append((ip, port))
                except Exception:
                    pass
                finally:
                    if conn:
                        conn.close()

            # 清理已不在监控列表中的残留状态（收藏删除后不留脏数据）
            valid_keys = {f"{ip}:{port}" for ip, port in targets}
            # 持锁删除：请求线程（/api/health/status、/api/favorites/realtime）
            # 会遍历同一批字典，无锁 del 会让它们抛 RuntimeError 变 500
            with health_lock:
                for k in list(health_monitor["status"].keys()):
                    if k not in valid_keys:
                        del health_monitor["status"][k]
                for k in list(health_monitor.get("last_players", {}).keys()):
                    if k not in valid_keys:
                        del health_monitor["last_players"][k]
            _log(f"[健康监控] 本轮目标数: {len(targets)}, 并发{probe_concurrency} 同IP间隔{probe_ip_gap}s")

            # 逐台探测、逐台更新（扫一个报一个，不用等全部跑完）
            async def _probe_stream():
                sem = asyncio.Semaphore(max(1, probe_concurrency))
                last_hit = {}
                async def _one(ip, port):
                    async with sem:
                        if probe_ip_gap > 0:
                            while True:
                                now = asyncio.get_event_loop().time()
                                wait = last_hit.get(ip, 0.0) + probe_ip_gap - now
                                if wait <= 0:
                                    last_hit[ip] = now
                                    break
                                await asyncio.sleep(wait)
                        try:
                            r = await async_slp_probe(ip, port, timeout=4.0, fast=True)
                            # SLP成功且需要补认证时，在线程池跑auth_probe不阻塞事件循环
                            if r and r.get("state") == "up":
                                try:
                                    from storage.favorites import load_favorites
                                    favs = load_favorites()
                                    need_auth = True
                                    for f in favs:
                                        if f.get("ip") == ip and f.get("port") == port:
                                            li = f.get("last_info") or {}
                                            lgi = f.get("last_good_info") or {}
                                            if li.get("auth") or lgi.get("auth"):
                                                need_auth = False
                                            break
                                    if need_auth:
                                        loop = asyncio.get_event_loop()
                                        from core.probe import auth_probe
                                        a = await loop.run_in_executor(None, lambda: auth_probe(ip, port, r.get("proto", 0) or 767, timeout=3.0))
                                        if a:
                                            r["auth"] = a.get("state", "unknown")
                                            r["plugin_channels"] = a.get("plugin_channels", [])
                                except Exception as e:
                                    _log(f"[健康监控] {ip}:{port} 认证补全异常: {e}")
                            return (ip, port, r)
                        except Exception:
                            return (ip, port, None)
                for fut in asyncio.as_completed([_one(ip, port) for ip, port in targets]):
                    ip, port, r = await fut
                    _process_one(ip, port, r)

            def _process_one(ip, port, r):
                key = f"{ip}:{port}"
                try:
                    if r and r.get("state") == "up":
                        try:
                            from storage.favorites import update_from_probe
                            update_from_probe(ip, port, r)
                        except Exception:
                            pass
                    online = r.get('online', 0) if r else 0
                    online_flag = bool(r and r.get("state") == "up")
                    with health_lock:
                        prev = health_monitor["status"].get(key, {})
                    prev_online = prev.get('players', 0)
                    prev_flag = prev.get('online', False)
                    player_names = []
                    if r:
                        sample = r.get('sample', [])
                        if isinstance(sample, list):
                            player_names = [p.get('name', '') for p in sample if isinstance(p, dict) and p.get('name')]
                    if r and online > 0:
                        conn = None
                        try:
                            conn = sqlite3.connect(db_path)
                            conn.execute(
                                'INSERT INTO server_popularity (ip, port, players_online, players_max, recorded_at) VALUES (?,?,?,?,?)',
                                (ip, port, online, r.get('max', 0), datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'))
                            )
                            conn.commit()
                        except Exception as e:
                            _log(f"[健康监控] 写popularity表失败: {e}")
                        finally:
                            if conn:
                                conn.close()
                    with health_lock:
                        prev_players = set(health_monitor.get("last_players", {}).get(key, []))
                    curr_players = set(player_names)
                    new_players = list(curr_players - prev_players)
                    left_players = list(prev_players - curr_players)
                    if online_flag != prev_flag:
                        event = {
                            "time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            "ip": ip, "port": port,
                            "from": prev_online, "to": online,
                            "joined": len(new_players), "left": len(left_players),
                            "new_players": new_players, "left_players": left_players,
                            "type": "up" if online_flag else "down"
                        }
                        with health_lock:
                            health_monitor["events"].insert(0, event)
                            health_monitor["events"] = health_monitor["events"][:100]
                        changed_servers.append({
                            "ip": ip, "port": port,
                            "prev": prev_online, "curr": online,
                            "joined": len(new_players), "left": len(left_players),
                            "player_names": player_names,
                            "new_players": new_players, "left_players": left_players,
                        })
                        _log(f"[健康监控] {ip}:{port} 状态变化: {'在线' if online_flag else '离线'} ({prev_online}→{online}人)")
                    elif online != prev_online:
                        event = {
                            "time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            "ip": ip, "port": port,
                            "from": prev_online, "to": online,
                            "joined": len(new_players), "left": len(left_players),
                            "new_players": new_players, "left_players": left_players,
                            "type": "change"
                        }
                        with health_lock:
                            health_monitor["events"].insert(0, event)
                            health_monitor["events"] = health_monitor["events"][:100]
                        changed_servers.append({
                            "ip": ip, "port": port,
                            "prev": prev_online, "curr": online,
                            "joined": len(new_players), "left": len(left_players),
                            "player_names": player_names,
                            "new_players": new_players, "left_players": left_players,
                        })
                        _log(f"[健康监控] {ip}:{port} 人数变化: {prev_online}→{online} (进{len(new_players)}走{len(left_players)})")
                    with health_lock:
                        if "last_players" not in health_monitor:
                            health_monitor["last_players"] = {}
                        health_monitor["last_players"][key] = player_names
                        health_monitor["status"][key] = {
                            "online": online_flag, "players": online,
                            "max": r.get("max", 0) if r else 0,
                            "prev_players": prev_online,
                            "joined": len(new_players), "left": len(left_players),
                            "player_names": player_names,
                            "last_check": datetime.now().strftime('%H:%M:%S')
                        }
                    # 写回favorites.json，重启后保留上次状态（只更新在线字段，保留之前的core_type/auth等）
                    try:
                        from storage import favorites as favorites_mod
                        _r = r or {}  # r 为 None（探测失败）时原来会 AttributeError，被外层 except 吞掉
                        _check_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                        def _mutate_fav(fav):
                            """在 favorites 的 _LOCK 内完成读-改-写。

                            原实现 load_favorites()→改→save_favorites() 是跨调用的读-改-写，
                            与 /api/favorites/add 并发时监控线程会用陈旧快照整文件回写，
                            把用户刚新增的收藏静默吞掉。
                            """
                            li = fav.get("last_info") or {}
                            li["version"] = _r.get("version", li.get("version", ""))
                            li["core_type"] = _r.get("core_type", li.get("core_type", ""))
                            li["state"] = "up" if online_flag else "down"
                            li["online"] = online
                            li["max"] = _r.get("max", li.get("max", 0))
                            li["players_online"] = online
                            li["players_max"] = _r.get("max", li.get("players_max", 0))
                            li["motd"] = _r.get("motd", li.get("motd", ""))
                            if _r.get("auth"):
                                li["auth"] = _r["auth"]
                            fav["last_info"] = li
                            # 在线时同步更新last_good_info（保留之前的auth等字段）
                            if online_flag:
                                old_good = fav.get("last_good_info") or {}
                                new_good = dict(li)
                                for k in ("auth", "auth_detail", "proto", "ping_ms", "sample", "player_list", "favicon", "fingerprint", "mods", "forge_channels"):
                                    if k in old_good and k not in new_good:
                                        new_good[k] = old_good[k]
                                fav["last_good_info"] = new_good
                            fav["last_check"] = _check_time
                            return fav

                        favorites_mod.update_favorite(ip, port, _mutate_fav)
                    except Exception as e:
                        _log(f"[健康监控] {ip}:{port} 写回favorites失败: {e}")
                except Exception as e:
                    # 不能静默吞掉：否则单台服务器出错会让后续状态记录被整段跳过
                    _log(f"[健康监控] {ip}:{port} 处理异常: {e}")

            if targets:
                asyncio.run(_probe_stream())
            # 一轮检查结束，汇总发送一封邮件（有人数变化就发）
            if changed_servers:
                try:
                    from core.notifier import send_email
                    email_enabled = config.get("email_enabled", False)
                    email_to = config.get("email_to", "")
                    if email_enabled and email_to:
                        lines = [f"<h2>服务器人数变化（共{len(changed_servers)}个）</h2>"]
                        for s in changed_servers:
                            addr = f"{s['ip']}:{s['port']}"
                            delta = s['curr'] - s['prev']
                            delta_str = f"+{delta}" if delta > 0 else str(delta)
                            delta_color = "#e94560" if delta > 0 else "#4caf50"
                            lines.append(f"<p><b>{addr}</b> - {s['prev']}人 → <span style='color:{delta_color}'>{s['curr']}人 ({delta_str})</span></p>")
                            lines.append(f"<p style='margin-left:20px;color:#666;'>进了 {s['joined']} 人，走了 {s['left']} 人</p>")
                            if s['player_names']:
                                lines.append(f"<p style='margin-left:20px;color:#888;'>当前玩家: {', '.join(_html_escape(p) for p in s['player_names'])}</p>")
                            if s['new_players']:
                                lines.append(f"<p style='margin-left:20px;color:#e94560;'>新增: {', '.join(_html_escape(p) for p in s['new_players'])}</p>")
                            if s['left_players']:
                                lines.append(f"<p style='margin-left:20px;color:#999;'>离开: {', '.join(_html_escape(p) for p in s['left_players'])}</p>")
                            lines.append("<hr style='border:none;border-top:1px solid #eee;'>")
                        body = "\n".join(lines)
                        ok, err = send_email(
                            f"[MC监控] {len(changed_servers)}个服务器人数变化",
                            body, html=True
                        )
                        _log(f"[健康监控] 汇总邮件推送: {len(changed_servers)}个服, success={ok} error={err}")
                    else:
                        _log(f"[健康监控] 邮件未推送: enabled={email_enabled} to={email_to}")
                except Exception as e:
                    import traceback
                    _log(f"[健康监控] 汇总邮件异常: {e}\n{traceback.format_exc()}")
        except Exception as e:
            _log(f"[健康监控] 错误: {e}")
        finally:
            health_monitor["last_check"] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        # 手动单次检查：跑完一轮就退出，不进入等待
        if once:
            return
        # 等待间隔，可被中断
        health_monitor["stop_event"].wait(health_monitor["interval"])


