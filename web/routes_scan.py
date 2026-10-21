# -*- coding: utf-8 -*-
"""Routes: scan"""
from flask import request, jsonify, Response
import os
import json
import time
import threading
from datetime import datetime
from storage import db, favorites
from scanner.exclude import Excluder
from scanner.targets import parse_targets
from scanner.random_scan import random_scan, parse_port_ranges as _parse_random_port_ranges
from scanner.engine import ScanEngine
try:
    from scanner.masscan import has_masscan, get_masscan_version, parse_masscan_json
except ImportError:
    def has_masscan():
        return False
    def get_masscan_version():
        return None
    def parse_masscan_json(*a, **kw):
        return []
try:
    from web import state
except ImportError:
    import state  # type: ignore

def _html_escape(s):
    if s is None:
        return ""
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _to_int(value, default=0):
    """请求参数转 int，非法值回退默认值（原实现直接 int() 会 500）。"""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _to_float(value, default=0.0):
    """请求参数转 float，非法值回退默认值。"""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


_SAFE_EXCLUDE_FILES = {"exclude.conf"}


def _safe_exclude_file(name):
    """排除列表文件名白名单（默认 exclude.conf）。

    原实现把请求参数直接交给 Excluder() -> open(filepath)：可读任意路径，
    指向 /dev/zero 或 FIFO 时该文件的逐行迭代永不结束，扫描线程直接挂死。
    """
    if isinstance(name, str) and name in _SAFE_EXCLUDE_FILES:
        return name
    return "exclude.conf"


def register(app):
    scan_state = state.scan_state
    scan_lock = state.scan_lock
    scan_stop_event = state.scan_stop_event
    def _log(msg):
        state.log_scan(msg)
    def _safe_db_path(path):
        return state.safe_db_path(path)
    def parse_ports_spec(ports_spec):
        return state.parse_ports_spec(ports_spec)

    try:
        from web import services_scan
    except ImportError:
        import services_scan  # type: ignore


    @app.route('/api/scan/start', methods=['POST'])
    def start_scan():
        if state.is_read_only():
            return jsonify({"error": "只读模式：禁止扫描操作"}), 403
        data = request.json or {}
        targets_str = data.get("targets", "")
        if not targets_str:
            return jsonify({"error": "请输入目标"}), 400
        targets_list = list(targets_str.split(','))
        continuous = data.get("continuous", False)
        ports = parse_ports_spec(data.get("ports", [25565]))
        if not ports:
            return jsonify({"error": "端口格式无效，请输入如 25565 或 25565-25575"}), 400
        exclude_file = _safe_exclude_file(data.get("exclude_file"))
        excluder = Excluder(exclude_file)
        try:
            parsed_raw = list(parse_targets(targets_list, ports))
        except Exception as e:
            return jsonify({"error": f"目标解析失败: {e}"}), 400
        parsed = list(excluder.filter_targets(parsed_raw))
        if not parsed:
            if not parsed_raw:
                return jsonify({"error": "没有有效的目标，请检查输入格式（如 1.2.3.4 或 1.2.3.0/24）"}), 400
            return jsonify({"error": f"目标被排除列表全部过滤（原始{len(parsed_raw)}个，排除后0个）"}), 400
        scan_config = {
            "workers": data.get("workers", 32),
            "timeout": data.get("timeout", 4.0),
            "scan_threads": data.get("scan_threads", 200),
            "scan_timeout": data.get("scan_timeout", 2.5),
            "rate": data.get("rate", 0),
            "auth_check": data.get("auth_check", True),
            "db_path": _safe_db_path(data.get("db_path", "mcscanner.db")),
            "use_masscan": data.get("use_masscan", "auto"),
            "portscan_only": data.get("portscan_only", False),
            "masscan_rate": data.get("masscan_rate", 5000),
            # masscan 子进程最长运行秒数（可选）：防止卡死的 masscan 让任务永不结束
            "masscan_timeout": data.get("masscan_timeout", 600),
            "ports": ports,
            "exclude_file": exclude_file,
            "continuous": continuous,
            "async_mode": data.get("async_mode", True),
            "scan_mode": data.get("scan_mode", "balanced"),
        }
        task_id = services_scan.start_scan_task(parsed, scan_config, scan_type="manual")
        queued = services_scan._get_task_state(task_id)["status"] == "queued"
        return jsonify({"status": "queued" if queued else "started", "targets": len(parsed), "task_id": task_id, "queued": queued})

    @app.route('/api/scan/random', methods=['POST'])
    def random_scan_api():
        # 与 /api/scan/start 同一套门禁：随机全网扫描风险最高，不能反而无门禁
        if state.is_read_only():
            return jsonify({"error": "只读模式下禁止扫描"}), 403
        if not state.capability_enabled("scan"):
            return jsonify({"error": "扫描能力未启用，请在config中设置 capabilities.scan=true"}), 403
        data = request.json or {}
        # 持锁快照：另一线程正在 start_scan_task 里插入键时无锁遍历 values()
        # 会抛 RuntimeError: dictionary changed size during iteration → 500
        with scan_lock:
            has_running = scan_state["running"] or any(t["running"] for t in state.scan_tasks.values())
        if has_running:
            return jsonify({"error": "已有扫描任务在运行"}), 400
        # task_id 在锁内分配：原实现直接读写全局 task_counter，
        # 并发请求会拿到同一个 id，后写入的任务状态覆盖前者
        with scan_lock:
            state.task_counter += 1
            task_id = state.task_counter
        count = max(1, min(_to_int(data.get("count"), 1000), 65536))
        ports = data.get("ports", "25565-25575")
        workers = max(1, min(_to_int(data.get("workers"), 200), 1000))
        timeout = data.get("timeout", 2.0)
        do_probe = data.get("probe", True)

        def _random_worker():
            try:
                with scan_lock:
                    scan_state["task_id"] = task_id
                    scan_state["running"] = True
                    scan_state["results"] = []
                    scan_state["logs"] = []
                    scan_state["progress"] = 0
                    scan_state["start_time"] = time.time()
                scan_stop_event.clear()
                _log(f"随机暴力扫描开始: {count} 个目标, 端口 {ports}")
                port_ranges = _parse_random_port_ranges(ports)
                def progress(done, total, found):
                    with scan_lock:
                        scan_state["progress"] = done
                        scan_state["total"] = total
                        if done % 50 == 0:
                            _log(f"随机扫描进度: {done}/{total}, 发现 {found} 个开放端口")
                open_ports = random_scan(count, workers, timeout, port_ranges, progress)
                _log(f"随机扫描完成: 发现 {len(open_ports)} 个开放端口")
                if do_probe and open_ports:
                    _log(f"开始 SLP 探测 {len(open_ports)} 个目标...")
                    engine = ScanEngine(stop_event=scan_stop_event, workers=min(32, workers), timeout=3.0)
                    results = engine.probe_list(open_ports)
                    with scan_lock:
                        scan_state["results"] = results
                        scan_state["progress"] = len(results)
                        scan_state["total"] = len(results)
                    _log(f"SLP 探测完成: 发现 {len(results)} 个 MC 服务器")
                else:
                    results = [{"ip": ip, "port": port, "auth": "unknown", "version": None,
                               "players_online": 0, "players_max": 0, "motd": None}
                              for ip, port in open_ports]
                    with scan_lock:
                        scan_state["results"] = results
                        scan_state["progress"] = len(results)
                        scan_state["total"] = len(results)
            except Exception as e:
                _log(f"随机扫描出错: {e}")
            finally:
                with scan_lock:
                    scan_state["running"] = False

        t = threading.Thread(target=_random_worker, daemon=True)
        t.start()
        return jsonify({"status": "started", "count": count, "task_id": task_id})

    @app.route('/api/scan/stop', methods=['POST'])
    def stop_scan():
        data = request.json or {}
        task_id = data.get("task_id")
        stopped_id = services_scan.stop_task(task_id)
        scan_stop_event.set()  # 兼容旧引擎
        _log(f"收到停止请求，正在终止扫描任务 #{stopped_id}...")
        return jsonify({"status": "stop_requested", "task_id": stopped_id})

    @app.route('/api/scan/tasks')
    def scan_tasks():
        tasks = services_scan.list_tasks()
        return jsonify({"tasks": tasks, "current_id": state.current_task_id, "queue_length": len(state.scan_queue)})

    @app.route('/api/scan/status')
    def scan_status():
        with scan_lock:
            return jsonify({
                "running": scan_state["running"],
                "progress": scan_state["progress"],
                "total": scan_state["total"],
                "scanned": scan_state.get("scanned", 0),
                "open_count": scan_state.get("open_count", 0),
                "results_count": len(scan_state["results"]),
                "logs": scan_state["logs"][-100:],
                "start_time": scan_state["start_time"],
                "task_id": scan_state["task_id"],
                "elapsed": time.time() - scan_state["start_time"] if scan_state["start_time"] else 0,
                "error": scan_state.get("error", ""),
            })

    @app.route('/api/scan/results')
    def scan_results():
        auth = request.args.get("auth")
        search = request.args.get("search", "")
        modded = request.args.get("modded")
        core_type = request.args.get("core_type")
        version = request.args.get("version", "")
        only_online = request.args.get("only_online") == "1"
        page = max(1, _to_int(request.args.get("page"), 1))
        # per_page 上限 1000：原实现允许 ?per_page=100000000 一次把结果拉进内存
        per_page = max(1, min(_to_int(request.args.get("per_page"), 50), 1000))
        with scan_lock:
            results = list(scan_state["results"])
        filtered = []
        for r in results:
            if auth and r.get("auth") != auth:
                continue
            if modded and str(r.get("is_modded", 0)) != modded:
                continue
            if core_type and r.get("core_type", "") != core_type:
                continue
            if version and not str(r.get("version", "")).startswith(version):
                continue
            if only_online and r.get("players_online", 0) <= 0:
                continue
            if search:
                search_lower = search.lower()
                if (search_lower not in str(r.get("ip", "")).lower()
                        and search_lower not in str(r.get("motd", "")).lower()
                        and search_lower not in str(r.get("version", "")).lower()):
                    continue
            filtered.append(r)
        total = len(filtered)
        start = (page - 1) * per_page
        end = start + per_page
        return jsonify({
            "total": total,
            "page": page,
            "per_page": per_page,
            "results": filtered[start:end],
        })

    @app.route('/api/scan/export')
    def export_results():
        fmt = request.args.get("format", "json")
        auth = request.args.get("auth")
        with scan_lock:
            results = list(scan_state["results"])
        if auth:
            results = [r for r in results if r.get("auth") == auth]
        if fmt == "csv":
            import csv
            def _csv_generator():
                if results:
                    # fieldnames 取所有行的键并集：原实现只用第一行的键，
                    # 后面某行字段更多时 DictWriter 会抛 ValueError，响应流中途断裂
                    keys = []
                    seen = set()
                    for r in results:
                        for k in r.keys():
                            if k not in seen:
                                seen.add(k)
                                keys.append(k)
                    # 用yield逐行输出，避免大结果集全量进内存
                    import io
                    output = io.StringIO()
                    writer = csv.DictWriter(output, fieldnames=keys, extrasaction="ignore")
                    writer.writeheader()
                    yield output.getvalue()
                    for r in results:
                        output = io.StringIO()
                        writer = csv.DictWriter(output, fieldnames=keys, extrasaction="ignore")
                        writer.writerow(r)
                        yield output.getvalue()
            return Response(_csv_generator(), mimetype="text/csv",
                            headers={"Content-Disposition": "attachment; filename=results.csv"})
        elif fmt == "html":
            offline = sum(1 for r in results if r.get("auth") == "offline")
            online = sum(1 for r in results if r.get("auth") == "online")
            whitelist = sum(1 for r in results if r.get("auth") == "whitelist")
            has_players = sum(1 for r in results if r.get("players_online", 0) > 0)
            total_players = sum(r.get("players_online", 0) for r in results)
            versions = {}
            for r in results:
                v = r.get("version") or "未知"
                versions[v] = versions.get(v, 0) + 1
            version_rows = "".join("<tr><td>" + _html_escape(v) + "</td><td>" + str(c) + "</td></tr>" for v, c in sorted(versions.items(), key=lambda x: -x[1]))
            server_rows = ""
            for r in results:
                players = ", ".join(r.get("player_list", [])) or "-"
                server_rows += "<tr><td>" + _html_escape(r.get('ip')) + ":" + _html_escape(r.get('port')) + "</td><td>" + _html_escape(r.get('version','?')) + "</td><td>" + _html_escape(r.get('players_online',0)) + "/" + _html_escape(r.get('players_max',0)) + "</td><td>" + _html_escape(players) + "</td><td>" + _html_escape(r.get('auth','?')) + "</td><td>" + _html_escape((r.get('motd','') or '')[:60]) + "</td></tr>"
            html_content = "<!DOCTYPE html><html><head><meta charset='utf-8'><title>MC Scanner 扫描报告</title>"
            html_content += "<style>body{font-family:sans-serif;max-width:1200px;margin:0 auto;padding:20px;background:#f8fafc;color:#1e293b}"
            html_content += "h1{color:#0f172a;border-bottom:3px solid #3b82f6;padding-bottom:10px}"
            html_content += ".stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:15px;margin:20px 0}"
            html_content += ".stat{background:#fff;border-radius:10px;padding:15px;box-shadow:0 1px 3px rgba(0,0,0,0.1);text-align:center}"
            html_content += ".stat .num{font-size:28px;font-weight:bold;color:#3b82f6}"
            html_content += ".stat .label{font-size:12px;color:#64748b;margin-top:5px}"
            html_content += "table{width:100%;border-collapse:collapse;margin:15px 0;background:#fff;border-radius:8px;overflow:hidden}"
            html_content += "th{background:#3b82f6;color:#fff;padding:10px;text-align:left;font-size:13px}"
            html_content += "td{padding:8px 10px;border-bottom:1px solid #e2e8f0;font-size:12px}"
            html_content += "tr:hover{background:#f1f5f9}h2{color:#334155;margin-top:30px}"
            html_content += ".footer{text-align:center;color:#94a3b8;font-size:11px;margin-top:30px}</style></head><body>"
            html_content += "<h1>MC Scanner v3-3.1 扫描报告</h1><p>生成时间: " + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + "</p>"
            html_content += "<div class='stats'>"
            html_content += "<div class='stat'><div class='num'>" + str(len(results)) + "</div><div class='label'>总服务器</div></div>"
            html_content += "<div class='stat'><div class='num'>" + str(offline) + "</div><div class='label'>离线模式</div></div>"
            html_content += "<div class='stat'><div class='num'>" + str(online) + "</div><div class='label'>正版模式</div></div>"
            html_content += "<div class='stat'><div class='num'>" + str(whitelist) + "</div><div class='label'>白名单</div></div>"
            html_content += "<div class='stat'><div class='num'>" + str(has_players) + "</div><div class='label'>有人在线</div></div>"
            html_content += "<div class='stat'><div class='num'>" + str(total_players) + "</div><div class='label'>总玩家数</div></div>"
            html_content += "</div><h2>版本分布</h2><table><tr><th>版本</th><th>数量</th></tr>" + version_rows + "</table>"
            html_content += "<h2>服务器列表</h2><table><tr><th>地址</th><th>版本</th><th>人数</th><th>在线玩家</th><th>认证</th><th>MOTD</th></tr>" + server_rows + "</table>"
            html_content += "<div class='footer'>MC Scanner v3-3.1 | 扫描报告自动生成</div></body></html>"
            return Response(html_content, mimetype="text/html",
                            headers={"Content-Disposition": "attachment; filename=mcscanner_report.html"})
        else:
            return Response(json.dumps(results, ensure_ascii=False, indent=2),
                            mimetype="application/json",
                            headers={"Content-Disposition": "attachment; filename=results.json"})

    @app.route('/api/import', methods=['POST'])
    def import_masscan_results():
        if 'file' not in request.files:
            return jsonify({"error": "请选择文件"}), 400
        f = request.files['file']
        if not f.filename:
            return jsonify({"error": "文件名为空"}), 400
        do_auth = request.form.get('do_auth', '1') == '1'
        import tempfile
        fd, tmp_path = tempfile.mkstemp(suffix='.ndjson', prefix='import_')
        os.close(fd)
        f.save(tmp_path)
        _log(f"导入 masscan 结果: {f.filename}")
        try:
            if do_auth:
                engine = ScanEngine(stop_event=scan_stop_event, db_path="mcscanner.db", workers=32, timeout=4.0, auth_check=True)
                results = engine.import_masscan(tmp_path, then_auth=True)
            else:
                raw = parse_masscan_json(tmp_path)
                results = [{"ip": ip, "port": port, "auth": "unknown",
                            "version": None, "motd": None,
                            "players_online": 0, "players_max": 0,
                            "ping_ms": None, "proto": None}
                           for ip, port, _ in raw]
            with scan_lock:
                scan_state["results"] = results
                scan_state["progress"] = 100
                scan_state["total"] = len(results)
            _log(f"导入完成，共 {len(results)} 个服务器")
            return jsonify({"status": "ok", "count": len(results)})
        except Exception as e:
            return jsonify({"error": str(e)}), 500
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    @app.route('/api/masscan/status')
    def masscan_status():
        return jsonify({
            "available": has_masscan(),
            "version": get_masscan_version() or "unknown",
        })

    @app.route('/api/db/rescan', methods=['POST'])
    def db_rescan():
        """数据库一键重新探查：对选中服务器重新SLP探测并更新数据库"""
        data = request.json or {}
        targets_raw = data.get("targets", [])
        db_path = _safe_db_path(data.get("db_path", "mcscanner.db"))
        workers = max(1, min(_to_int(data.get("workers"), 10), 64))

        targets = []
        for t in targets_raw:
            if isinstance(t, dict):
                targets.append((t["ip"], int(t.get("port", 25565))))
            elif isinstance(t, str) and ":" in t:
                ip, port = t.rsplit(":", 1)
                targets.append((ip, int(port)))
        if not targets:
            return jsonify({"error": "请先选择要重新探查的服务器"}), 400

        _log(f"数据库重新探查开始: {len(targets)} 个目标")
        from core.probe import slp_probe, auth_probe
        from concurrent.futures import ThreadPoolExecutor, as_completed
        results = []

        def probe_one(ip, port):
            try:
                r = slp_probe(ip, port, timeout=5.0)
                if r and r.get("state") == "up":
                    auth = auth_probe(ip, port, r.get("proto", 0))
                    if auth:
                        r["auth"] = auth.get("state", "unknown")
                        r["auth_detail"] = auth.get("detail", "")
                        r["plugin_channels"] = auth.get("plugin_channels", [])
                    r["ip"] = ip
                    r["port"] = port
                    r["last_updated"] = int(time.time())
                    return r
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = {ex.submit(probe_one, ip, port): (ip, port) for ip, port in targets}
            for fut in as_completed(futures):
                r = fut.result()
                if r:
                    results.append(r)

        if results:
            db.upsert_many(db_path, results)
        up = len(results)
        _log(f"数据库重新探查完成: {len(targets)} 个目标, {up} 个在线, 已更新数据库")
        return jsonify({"total": len(targets), "up": up, "updated": up})

    @app.route('/api/favorites/rescan', methods=['POST'])
    def fav_rescan():
        data = request.json or {}
        timeout = _to_float(data.get("timeout"), 5.0)
        workers = max(1, min(_to_int(data.get("workers"), 10), 64))
        def _progress(done, total):
            _log(f"收藏重查进度: {done}/{total}")
        favs = favorites.rescan_all(timeout=timeout, workers=workers, progress_callback=_progress)
        _log(f"收藏重查完成: {len(favs)} 个")
        return jsonify({"success": True, "total": len(favs), "favorites": favs})

    @app.route('/api/favorites/rescan_one', methods=['POST'])
    def fav_rescan_one():
        data = request.json or {}
        ip = data.get("ip")
        if not ip:
            return jsonify({"success": False, "error": "请指定ip"}), 400
        port = int(data.get("port") or 25565)
        info = favorites.rescan_one(ip, port, timeout=_to_float(data.get("timeout"), 5.0))
        return jsonify({"success": True, "info": info})

