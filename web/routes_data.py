# -*- coding: utf-8 -*-
"""Routes: data"""
import json
import os
import sqlite3
import time
from datetime import datetime

from flask import Response, jsonify, request

import logger
from storage import db, favorites

try:
    from web import state
except ImportError:
    import state  # type: ignore


def _html_escape(s):
    if s is None:
        return ""
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _csv_field(s):
    """CSV字段转义：含逗号/引号/换行时加双引号，内部引号转义为两个"""
    s = str(s) if s is not None else ""
    if ',' in s or '"' in s or '\n' in s or '\r' in s:
        return '"' + s.replace('"', '""') + '"'
    return s


def _to_int(value, default=0):
    """请求参数转 int，非法值回退默认值（原实现直接 int() 会 500）。"""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def register(app):
    scan_state = state.scan_state
    scan_lock = state.scan_lock
    health_monitor = state.health_monitor
    def _log(msg):
        state.log_scan(msg)
    def _safe_db_path(path):
        return state.safe_db_path(path)
    def parse_ports_spec(ports_spec):
        return state.parse_ports_spec(ports_spec)


    @app.route('/api/db/query')
    def db_query():
        db_path = _safe_db_path(request.args.get("db_path", "mcscanner.db"))
        auth = request.args.get("auth")
        modded = request.args.get("modded")
        search = request.args.get("search")
        only_online = request.args.get("only_online", "0") == "1"
        try:
            limit = int(request.args.get("limit", 100))
        except (ValueError, TypeError):
            limit = 100
        try:
            offset = int(request.args.get("offset", 0))
        except (ValueError, TypeError):
            offset = 0
        # 上下界收敛：SQLite 里 LIMIT -1 表示"不限"，?limit=-1 一次就把整库拉进内存
        limit = max(1, min(limit, 1000))
        offset = max(0, offset)
        try:
            modded_val = int(modded) if modded else None
        except (ValueError, TypeError):
            modded_val = None
        if not os.path.exists(db_path):
            return jsonify({"total": 0, "results": []})
        rows = db.query(db_path, auth=auth, modded=modded_val,
                         search=search, only_online=only_online,
                         limit=limit, offset=offset)
        total = db.count(db_path, auth=auth, modded=modded_val,
                         search=search, only_online=only_online)
        return jsonify({"total": total, "results": rows})

    @app.route('/api/db/export')
    def db_export():
        """导出扫描数据库，支持 txt/csv/json/html 格式，带筛选条件"""
        db_path = _safe_db_path(request.args.get("db_path", "mcscanner.db"))
        fmt = request.args.get("format", "txt").lower()
        auth = request.args.get("auth")
        modded = request.args.get("modded")
        search = request.args.get("search")
        only_online = request.args.get("only_online", "0")
        try:
            modded_val = int(modded) if modded else None
        except (ValueError, TypeError):
            modded_val = None
        if not os.path.exists(db_path):
            return jsonify({"error": "数据库不存在"}), 404

        # 导出最多20000条，避免文件过大
        rows = db.query(db_path, auth=auth, modded=modded_val, search=search, limit=20000, offset=0)
        if only_online == "1":
            rows = [r for r in rows if r.get("players_online", 0) > 0]
        total = len(rows)
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ts = int(time.time())

        if fmt == "json":
            resp = jsonify({"total": total, "exported_at": now, "results": rows})
            resp.headers["Content-Disposition"] = f"attachment; filename=scan_results_{ts}.json"
            return resp

        if fmt == "csv":
            lines = ["IP,端口,版本,协议,人数,延迟,验证,核心,Mod,MOTD"]
            for r in rows:
                ip = _csv_field(r.get("ip", ""))
                port = _csv_field(r.get("port", 25565))
                ver = _csv_field(r.get("version") or "")
                proto = _csv_field(r.get("proto", ""))
                players = _csv_field(f"{r.get('players_online', 0)}/{r.get('players_max', 0)}")
                ping = _csv_field(r.get("ping_ms", ""))
                auth_v = _csv_field(r.get("auth", ""))
                core = _csv_field(r.get("core_type") or "")
                mods = "是" if r.get("is_modded") else "否"
                motd = _csv_field(r.get("motd") or "")
                lines.append(f"{ip},{port},{ver},{proto},{players},{ping},{auth_v},{core},{mods},{motd}")
            return Response("\n".join(lines), mimetype="text/csv; charset=utf-8",
                            headers={"Content-Disposition": f"attachment; filename=scan_results_{ts}.csv"})

        if fmt == "html":
            rows_html = ""
            for r in rows:
                ip = _html_escape(r.get("ip", ""))
                port = _html_escape(r.get("port", 25565))
                ver = _html_escape(r.get("version") or "-")
                players = f"{r.get('players_online', 0)}/{r.get('players_max', 0)}"
                online = r.get("players_online", 0)
                pcolor = "#e94560" if online > 0 else "#555"
                auth_v = _html_escape(r.get("auth") or "-")
                core = _html_escape(r.get("core_type") or "-")
                motd = _html_escape((r.get("motd") or "")[:50])
                rows_html += f"""<tr>
    <td><a href="http://{ip}:{port}" style="color:#00d992;">{ip}:{port}</a></td>
    <td>{ver}</td><td style="color:{pcolor};font-weight:bold;">{players}</td><td>{auth_v}</td><td>{core}</td><td style="color:#888;font-size:12px;">{motd}</td>
    </tr>"""
            html = f"""<!DOCTYPE html>
    <html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
    <title>扫描结果导出</title>
    <style>*{{margin:0;padding:0;box-sizing:border-box}}body{{background:#0a0a0a;color:#e0e0e0;font-family:Consolas,Monaco,monospace;padding:20px}}
    .container{{max-width:1100px;margin:0 auto}}
    .header{{background:linear-gradient(135deg,#1a1a2e,#16213e);border:1px solid #0f3460;border-radius:12px;padding:24px;margin-bottom:20px}}
    .header h1{{color:#00d992;font-size:22px;margin-bottom:8px}}
    .header .info{{color:#888;font-size:13px}}.header .info span{{color:#e94560}}
    table{{width:100%;border-collapse:collapse;background:#111;border:1px solid #222;border-radius:12px;overflow:hidden}}
    th{{background:#0f3460;color:#fff;padding:10px;text-align:left;font-size:13px}}
    td{{padding:8px 10px;border-bottom:1px solid #1a1a1a;font-size:13px}}
    tr:hover{{background:#161616}}
    .footer{{text-align:center;color:#444;font-size:12px;margin-top:16px}}</style>
    </head><body><div class="container">
    <div class="header"><h1>MC扫描结果</h1>
    <div class="info">共 <span>{total}</span> 个服务器 | 导出时间: <span>{now}</span></div>
    </div>
    <table><tr><th>地址</th><th>版本</th><th>人数</th><th>验证</th><th>核心</th><th>MOTD</th></tr>{rows_html}</table>
    <div class="footer">Generated by mc-scanner-v3</div>
    </div></body></html>"""
            return Response(html, mimetype="text/html; charset=utf-8",
                            headers={"Content-Disposition": f"attachment; filename=scan_results_{ts}.html"})

        # 默认 TXT
        lines = ["MC扫描结果导出", f"共 {total} 个服务器", f"导出时间: {now}", "=" * 60, ""]
        for i, r in enumerate(rows, 1):
            ip = r.get("ip", "")
            port = r.get("port", 25565)
            ver = r.get("version") or "?"
            players = f"{r.get('players_online', 0)}/{r.get('players_max', 0)}"
            auth_v = r.get("auth") or "?"
            core = r.get("core_type") or "?"
            motd = (r.get("motd") or "")[:60]
            lines.append(f"[{i}] {ip}:{port}")
            lines.append(f"    版本: {ver} | 人数: {players} | 验证: {auth_v} | 核心: {core}")
            if motd:
                lines.append(f"    MOTD: {motd}")
            lines.append("")
        return Response("\n".join(lines), mimetype="text/plain; charset=utf-8",
                        headers={"Content-Disposition": f"attachment; filename=scan_results_{ts}.txt"})

    @app.route('/api/server/popularity')
    def server_popularity():
        """查询服务器人数历史趋势"""
        ip = request.args.get("ip", "")
        port = request.args.get("port", type=int)
        hours = request.args.get("hours", type=int, default=24)
        if not ip or not port:
            return jsonify({"error": "ip和port必填"}), 400
        hours = max(1, min(hours, 24 * 365))
        db_path = _safe_db_path(request.args.get("db_path", "mcscanner.db"))
        # 库不存在时直接返回空：原实现会静默新建一个空 .db 污染 CWD
        if not os.path.exists(db_path):
            return jsonify({"ip": ip, "port": port, "hours": hours, "data": []})
        conn = None
        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            # 按小时聚合，取每小时最大人数
            # 时间窗用 julianday 比较：recorded_at 里混存 "T...%z"（storage/db.py）和
            # 空格格式（健康监控），字符串比较会把窗口外的记录也算进来
            rows = conn.execute(
                """SELECT strftime('%Y-%m-%d %H:00', recorded_at) as hour,
                          MAX(players_online) as online, MAX(players_max) as max_p
                   FROM server_popularity
                   WHERE ip=? AND port=? AND julianday(recorded_at) > julianday('now', ?)
                   GROUP BY hour ORDER BY hour ASC""",
                (ip, port, f'-{hours} hours')
            ).fetchall()
        finally:
            # 缺表/查询异常也必须关连接，否则 sqlite 句柄泄漏
            if conn is not None:
                conn.close()
        return jsonify({
            "ip": ip, "port": port, "hours": hours,
            "data": [{"time": r["hour"], "online": r["online"], "max": r["max_p"]} for r in rows]
        })

    @app.route('/api/db/stats')
    def db_stats():
        db_path = _safe_db_path(request.args.get("db_path", "mcscanner.db"))
        if not os.path.exists(db_path):
            return jsonify({"total": 0, "by_auth": {}, "online_servers": 0, "by_version": {}})
        return jsonify(db.stats(db_path))

    @app.route('/api/history')
    def history():
        with scan_lock:
            return jsonify({"history": scan_state["history"]})

    @app.route('/api/favorites')
    def fav_list():
        tag = request.args.get("tag")
        search = request.args.get("search", "")
        favs = favorites.filter_favorites(tag=tag or None, search=search or None)
        return jsonify({"total": len(favs), "favorites": favs, "tags": favorites.get_all_tags()})

    @app.route('/api/favorites/add', methods=['POST'])
    def fav_add():
        data = request.json or {}
        ip = data.get("ip")
        port = int(data.get("port") or 25565)
        tags = data.get("tags", [])
        note = data.get("note", "")
        info = data.get("info")
        if not ip:
            return jsonify({"error": "IP 不能为空"}), 400
        fav = favorites.add_favorite(ip, port, tags=tags, note=note, info=info)
        _log(f"收藏添加: {ip}:{port}")
        # 没有带info时后台自动跑一次完整探测（SLP+认证）
        if not info:
            import threading
            def _auto_probe():
                try:
                    from storage.favorites import rescan_one
                    rescan_one(ip, port, timeout=5.0)
                except Exception:
                    logger.exception("[api] _auto_probe 未处理异常")
            threading.Thread(target=_auto_probe, daemon=True).start()
        return jsonify({"success": True, "favorite": fav})

    @app.route('/api/favorites/remove', methods=['POST'])
    def fav_remove():
        data = request.json or {}
        ip = data.get("ip")
        port = int(data.get("port") or 25565)
        ok = favorites.remove_favorite(ip, port)
        if ok:
            _log(f"收藏移除: {ip}:{port}")
        return jsonify({"success": ok})

    @app.route('/api/favorites/batch_remove', methods=['POST'])
    def fav_batch_remove():
        data = request.json or {}
        items = data.get("items") or []
        removed = 0
        for it in items:
            try:
                if favorites.remove_favorite(it["ip"], int(it["port"])):
                    removed += 1
            except Exception:
                logger.exception("[api] fav_batch_remove 未处理异常")
        _log(f"批量删除收藏: {removed}/{len(items)} 个")
        return jsonify({"success": True, "removed": removed})

    @app.route('/api/favorites/tags', methods=['POST'])
    def fav_tags():
        data = request.json or {}
        ip = data.get("ip")
        port = int(data.get("port") or 25565)
        tags = data.get("tags", [])
        fav = favorites.update_tags(ip, port, tags)
        return jsonify({"success": fav is not None, "favorite": fav})

    @app.route('/api/favorites/note', methods=['POST'])
    def fav_note():
        data = request.json or {}
        ip = data.get("ip")
        port = int(data.get("port") or 25565)
        note = data.get("note", "")
        fav = favorites.update_note(ip, port, note)
        return jsonify({"success": fav is not None, "favorite": fav})

    @app.route('/api/favorites/import', methods=['POST'])
    def fav_import():
        if 'file' not in request.files:
            return jsonify({"error": "请选择文件"}), 400
        f = request.files['file']
        import tempfile
        fd, tmp_path = tempfile.mkstemp(suffix='.txt', prefix='fav_import_')
        os.close(fd)
        f.save(tmp_path)
        try:
            count = favorites.import_from_file(tmp_path)
            _log(f"收藏导入: {count} 个")
            return jsonify({"success": True, "count": count})
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    @app.route('/api/favorites/export')
    def fav_export():
        """导出收藏列表，支持 txt/csv/json/html 格式"""
        fmt = request.args.get("format", "txt").lower()
        tag = request.args.get("tag")
        search = request.args.get("search", "")
        favs = favorites.filter_favorites(tag=tag or None, search=search or None)
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ts = int(time.time())

        if fmt == "json":
            resp = jsonify({"total": len(favs), "exported_at": now, "favorites": favs})
            resp.headers["Content-Disposition"] = f"attachment; filename=favorites_{ts}.json"
            return resp

        if fmt == "csv":
            lines = ["IP,端口,版本,人数,验证,标签,备注,MOTD"]
            for f in favs:
                info = f.get("last_info") or {}
                ip = _csv_field(f.get("ip", ""))
                port = _csv_field(f.get("port", 25565))
                ver = _csv_field(info.get("version") or "")
                players = _csv_field(f"{info.get('players_online', 0)}/{info.get('players_max', 0)}")
                auth = _csv_field(info.get("auth", ""))
                tags = _csv_field("|".join(f.get("tags", [])))
                note = _csv_field(f.get("note") or "")
                motd = _csv_field(info.get("motd") or "")
                lines.append(f"{ip},{port},{ver},{players},{auth},{tags},{note},{motd}")
            return Response("\n".join(lines), mimetype="text/csv; charset=utf-8",
                            headers={"Content-Disposition": f"attachment; filename=favorites_{ts}.csv"})

        if fmt == "html":
            rows = ""
            for f in favs:
                info = f.get("last_info") or {}
                ip = _html_escape(f.get("ip", ""))
                port = _html_escape(f.get("port", 25565))
                ver = _html_escape(info.get("version") or "-")
                players = f"{info.get('players_online', 0)}/{info.get('players_max', 0)}"
                auth = _html_escape(info.get("auth") or "-")
                tags = " ".join(f'<span style="background:#0f3460;padding:2px 6px;border-radius:3px;font-size:11px;">{_html_escape(t)}</span>' for t in f.get("tags", []))
                note = _html_escape(f.get("note") or "")
                motd = _html_escape((info.get("motd") or "")[:50])
                rows += f"""<tr>
    <td><a href="http://{ip}:{port}" style="color:#00d992;">{ip}:{port}</a></td>
    <td>{ver}</td><td>{players}</td><td>{auth}</td><td>{tags}</td><td>{note}</td><td style="color:#888;font-size:12px;">{motd}</td>
    </tr>"""
            html = f"""<!DOCTYPE html>
    <html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
    <title>收藏列表导出</title>
    <style>*{{margin:0;padding:0;box-sizing:border-box}}body{{background:#0a0a0a;color:#e0e0e0;font-family:Consolas,Monaco,monospace;padding:20px}}
    .container{{max-width:1100px;margin:0 auto}}
    .header{{background:linear-gradient(135deg,#1a1a2e,#16213e);border:1px solid #0f3460;border-radius:12px;padding:24px;margin-bottom:20px}}
    .header h1{{color:#00d992;font-size:22px;margin-bottom:8px}}
    .header .info{{color:#888;font-size:13px}}.header .info span{{color:#e94560}}
    table{{width:100%;border-collapse:collapse;background:#111;border:1px solid #222;border-radius:12px;overflow:hidden}}
    th{{background:#0f3460;color:#fff;padding:10px;text-align:left;font-size:13px}}
    td{{padding:8px 10px;border-bottom:1px solid #1a1a1a;font-size:13px}}
    tr:hover{{background:#161616}}
    .footer{{text-align:center;color:#444;font-size:12px;margin-top:16px}}</style>
    </head><body><div class="container">
    <div class="header"><h1>MC服务器收藏列表</h1>
    <div class="info">共 <span>{len(favs)}</span> 个服务器 | 导出时间: <span>{now}</span></div>
    </div>
    <table><tr><th>地址</th><th>版本</th><th>人数</th><th>验证</th><th>标签</th><th>备注</th><th>MOTD</th></tr>{rows}</table>
    <div class="footer">Generated by mc-scanner-v3</div>
    </div></body></html>"""
            return Response(html, mimetype="text/html; charset=utf-8",
                            headers={"Content-Disposition": f"attachment; filename=favorites_{ts}.html"})

        # 默认 TXT
        lines = ["MC服务器收藏列表", f"共 {len(favs)} 个服务器", f"导出时间: {now}", "=" * 60, ""]
        for i, f in enumerate(favs, 1):
            info = f.get("last_info") or {}
            ip = f.get("ip", "")
            port = f.get("port", 25565)
            ver = info.get("version") or "?"
            players = f"{info.get('players_online', 0)}/{info.get('players_max', 0)}"
            auth = info.get("auth") or "?"
            tags = ",".join(f.get("tags", []))
            note = f.get("note") or ""
            motd = (info.get("motd") or "")[:60]
            lines.append(f"[{i}] {ip}:{port}")
            lines.append(f"    版本: {ver} | 人数: {players} | 验证: {auth}")
            if tags:
                lines.append(f"    标签: {tags}")
            if note:
                lines.append(f"    备注: {note}")
            if motd:
                lines.append(f"    MOTD: {motd}")
            lines.append("")
        return Response("\n".join(lines), mimetype="text/plain; charset=utf-8",
                        headers={"Content-Disposition": f"attachment; filename=favorites_{ts}.txt"})

    @app.route('/api/players')
    def players_history():
        db_path = _safe_db_path(request.args.get("db_path", "mcscanner.db"))
        player_name = request.args.get("name")
        ip = request.args.get("ip")
        port = request.args.get("port", type=int)
        limit = max(1, min(_to_int(request.args.get("limit"), 100), 1000))
        if not os.path.exists(db_path):
            return jsonify({"total": 0, "players": []})
        from storage import player_history as ph
        players = ph.get_player_history(db_path, player_name=player_name, ip=ip, port=port, limit=limit)
        return jsonify({"total": len(players), "players": players})

    @app.route('/api/players/stats')
    def players_stats():
        db_path = _safe_db_path(request.args.get("db_path", "mcscanner.db"))
        if not os.path.exists(db_path):
            return jsonify({"total_records": 0, "unique_players": 0, "unique_servers": 0})
        from storage import player_history as ph
        return jsonify(ph.get_stats(db_path))

    @app.route('/api/favorites/realtime')
    def favorites_realtime():
        """返回收藏服务器的实时监控状态（当前人数、上次人数、进出玩家）"""
        try:
            from storage.favorites import filter_favorites
            favs = filter_favorites()
        except Exception:
            logger.exception("[api] favorites_realtime 未处理异常")
            favs = []
        result = []
        # 持锁快照：健康监控线程会在同一字典里删/写，无锁遍历会抛 RuntimeError 变 500
        with state.health_lock:
            status_snapshot = dict(health_monitor["status"])
        for f in favs:
            key = f"{f['ip']}:{f['port']}"
            st = status_snapshot.get(key)
            if not st:
                # 还没有实时监控数据：不返回该项，前端保留收藏中上次探查的信息
                continue
            result.append({
                "ip": f['ip'], "port": f['port'],
                # 收藏里存的是 tags（列表），原来读 f['tag'] 永远是空字符串
                "tag": f.get('tags') or [],
                "note": f.get('note', ''),
                "online": st.get("online", False),
                "players": st.get("players", 0),
                "max": st.get("max", 0),
                "prev_players": st.get("prev_players", 0),
                "joined": st.get("joined", 0),
                "left": st.get("left", 0),
                "player_names": st.get("player_names", []),
                "last_check": st.get("last_check", ""),
            })
        return jsonify({"servers": result, "last_check": health_monitor.get("last_check")})

    @app.route('/api/db/clear', methods=['POST'])
    def db_clear():
        """清空servers表（需二次确认）"""
        # body 为合法 JSON null 时 request.json 是 None，原来直接 .get() → AttributeError 500
        data = request.json or {}
        db_path = _safe_db_path(data.get("db_path", "mcscanner.db"))
        confirm = data.get("confirm", "")
        if confirm != "CLEAR":
            return jsonify({"error": "需传confirm=CLEAR确认"}), 400
        if not os.path.exists(db_path):
            return jsonify({"success": True, "deleted": 0})
        from storage.db import get_conn
        conn = get_conn(db_path)
        cur = conn.execute("DELETE FROM servers")
        deleted = cur.rowcount
        conn.commit()
        conn.close()
        _log(f"数据库已清空，删除 {deleted} 条记录")
        return jsonify({"success": True, "deleted": deleted})

    @app.route('/api/db/import', methods=['POST'])
    def db_import():
        """导入txt或JSON格式的服务器数据。
        txt: 每行一个 ip:port 或 ip
        JSON: [{ip, port, version, players_online, ...}, ...]
        """
        if 'file' not in request.files:
            return jsonify({"error": "请选择文件"}), 400
        f = request.files['file']
        db_path = _safe_db_path(request.form.get("db_path", "mcscanner.db"))
        import tempfile
        fd, tmp_path = tempfile.mkstemp(suffix='.txt', prefix='db_import_')
        os.close(fd)
        f.save(tmp_path)
        try:
            records = []
            fname = f.filename.lower()
            with open(tmp_path, 'r', encoding='utf-8') as fh:
                content = fh.read()
            if fname.endswith('.json'):
                data = json.loads(content)
                if isinstance(data, dict):
                    data = data.get("servers", data.get("results", [data]))
                for item in data:
                    if isinstance(item, dict) and item.get("ip"):
                        rec = {
                            "ip": item["ip"],
                            "port": item.get("port", 25565),
                            "version": item.get("version", ""),
                            "proto": item.get("proto", 0),
                            "motd": item.get("motd", ""),
                            "players_online": item.get("players_online", 0),
                            "players_max": item.get("players_max", 0),
                            "auth": item.get("auth", ""),
                            "ping_ms": item.get("ping_ms"),
                            "core_type": item.get("core_type", ""),
                            "is_modded": item.get("is_modded", 0),
                        }
                        records.append(rec)
            else:
                import re
                for line in content.strip().splitlines():
                    line = line.strip()
                    if not line or line.startswith('#') or line.startswith('='):
                        continue
                    # 匹配导出格式: "[1] 1.2.3.4:25565" 或纯 "1.2.3.4:25565"
                    m = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)', line)
                    if not m:
                        continue
                    records.append({"ip": m.group(1), "port": int(m.group(2))})
            if not records:
                return jsonify({"error": "文件中无有效记录"}), 400
            from storage.db import upsert_many
            count = upsert_many(db_path, records)
            _log(f"数据库导入: {count} 条记录")
            return jsonify({"success": True, "imported": count})
        except Exception as e:
            logger.exception("[api] db_import 未处理异常")
            return jsonify({"error": str(e)}), 500
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
