# -*- coding: utf-8 -*-
"""Routes: scan_extra"""
from flask import jsonify, request

try:
    from web import state
except ImportError:
    import state  # type: ignore


def _to_int(value, default=0):
    """请求参数转 int，非法值回退默认值（原实现直接 int() 会 500）。"""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


# 会自动进服交互的自动任务类型：这些任务在无人值守下持续发警告/观察/AI聊天，
# 必须与 /api/warn、/api/ai_bot/start 走同一套只读+能力开关
_INTERACT_TASK_TYPES = {"scan_warn", "monitor_players", "scheduled_warn", "ai_hijack"}


def _deny_auto_task(task_type):
    """返回拒绝响应，或 None 表示放行。"""
    if state.is_read_only():
        return jsonify({"success": False, "error": "只读模式下禁止创建/启动自动任务"}), 403
    if not state.capability_enabled("scan"):
        return jsonify({"success": False, "error": "扫描能力未启用，请在config中设置 capabilities.scan=true"}), 403
    if task_type in _INTERACT_TASK_TYPES and not state.capability_enabled("login_interact"):
        return jsonify({"success": False,
                        "error": "进服交互能力未启用，请在config中设置 capabilities.login_interact=true"}), 403
    return None


def register(app):
    def _log(msg):
        state.log_scan(msg)
    def _safe_db_path(path):
        return state.safe_db_path(path)
    def parse_ports_spec(ports_spec):
        return state.parse_ports_spec(ports_spec)


    @app.route('/api/rescan')
    def rescan_list():
        db_path = _safe_db_path(request.args.get("db_path", "mcscanner.db"))
        action = request.args.get("action", "list")
        limit = max(1, min(_to_int(request.args.get("limit"), 100), 1000))
        from storage import rescan as rescan_db
        rescan_db.init_rescan_queue(db_path)
        if action == "stats":
            return jsonify(rescan_db.get_stats(db_path))
        if action == "due":
            due = rescan_db.get_due_rescans(db_path, limit=limit)
            return jsonify({"total": len(due), "items": due})
        all_items = rescan_db.get_all_rescans(db_path, limit=limit)
        return jsonify({"total": len(all_items), "items": all_items, "stats": rescan_db.get_stats(db_path)})

    @app.route('/api/rescan/run', methods=['POST'])
    def rescan_run():
        data = request.json or {}
        db_path = _safe_db_path(data.get("db_path", "mcscanner.db"))
        limit = max(1, min(_to_int(data.get("limit"), 50), 1000))
        from scanner.engine import ScanEngine
        from storage import rescan as rescan_db
        rescan_db.init_rescan_queue(db_path)
        due = rescan_db.get_due_rescans(db_path, limit=limit)
        if not due:
            return jsonify({"status": "no_due", "count": 0})
        _log(f"智能重扫开始: {len(due)} 个到期目标")
        engine = ScanEngine(db_path=db_path, workers=16, timeout=4.0, rescan_enabled=True)
        results = []
        for item in due:
            try:
                r = engine.probe_one(item["ip"], item["port"])
                results.append(r)
            except Exception:
                continue
        up = sum(1 for r in results if r.get("state") == "up")
        _log(f"智能重扫完成: {len(results)} 个目标, {up} 个在线")
        return jsonify({"status": "completed", "total": len(results), "up": up})

    @app.route('/api/rescan/clear', methods=['POST'])
    def rescan_clear():
        data = request.json or {}
        db_path = _safe_db_path(data.get("db_path", "mcscanner.db"))
        from storage import rescan as rescan_db
        rescan_db.clear_rescan(db_path)
        _log("重扫队列已清空")
        return jsonify({"success": True})

    @app.route('/api/auto_scan/tasks')
    def auto_scan_tasks():
        from core.auto_scanner import auto_scanner
        return jsonify({"tasks": auto_scanner.list_tasks()})

    @app.route('/api/auto_scan/types')
    def auto_scan_types():
        from core.auto_scanner import AutoScanner
        return jsonify({"types": [
            {"value": k, "label": v} for k, v in AutoScanner.TASK_TYPES.items()
        ]})

    @app.route('/api/auto_scan/add', methods=['POST'])
    def auto_scan_add():
        data = request.json or {}
        if not data.get("targets"):
            return jsonify({"success": False, "error": "请指定扫描目标"}), 400
        # 能力/只读门禁：add 默认 auto_start=True，不校验的话一个请求就能开 AI 托管/自动警告
        deny = _deny_auto_task(str(data.get("task_type") or "scan_warn"))
        if deny:
            return deny
        from core.auto_scanner import auto_scanner
        task_id = auto_scanner.add_task(data)
        if data.get("auto_start", True):
            auto_scanner.start_task(task_id)
        return jsonify({"success": True, "task_id": task_id})

    @app.route('/api/auto_scan/start', methods=['POST'])
    def auto_scan_start():
        data = request.json or {}
        tid = data.get("task_id")
        if not tid:
            return jsonify({"success": False, "error": "请指定task_id"}), 400
        from core.auto_scanner import auto_scanner
        # 按任务实际类型再校验一次，堵住"先建后启"绕过 add 门禁的路径
        task_type = "scan_warn"
        for t in auto_scanner.list_tasks():
            if t.get("task_id") == tid:
                task_type = t.get("task_type", "scan_warn")
                break
        deny = _deny_auto_task(task_type)
        if deny:
            return deny
        ok = auto_scanner.start_task(tid)
        return jsonify({"success": ok})

    @app.route('/api/auto_scan/stop', methods=['POST'])
    def auto_scan_stop():
        data = request.json or {}
        tid = data.get("task_id")
        if not tid:
            return jsonify({"success": False, "error": "请指定task_id"}), 400
        from core.auto_scanner import auto_scanner
        auto_scanner.stop_task(tid)
        return jsonify({"success": True})

    @app.route('/api/auto_scan/remove', methods=['POST'])
    def auto_scan_remove():
        data = request.json or {}
        tid = data.get("task_id")
        if not tid:
            return jsonify({"success": False, "error": "请指定task_id"}), 400
        from core.auto_scanner import auto_scanner
        auto_scanner.remove_task(tid)
        return jsonify({"success": True})

    @app.route('/api/auto_scan/logs')
    def auto_scan_logs():
        tid = request.args.get("task_id")
        from core.auto_scanner import auto_scanner
        return jsonify({"logs": auto_scanner.get_logs(tid)})

