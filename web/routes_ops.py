# -*- coding: utf-8 -*-
"""Routes: ops"""
import threading

from flask import jsonify

try:
    from web import state
except ImportError:
    import state  # type: ignore


def register(app):
    health_monitor = state.health_monitor
    health_lock = state.health_lock
    def _log(msg):
        state.log_scan(msg)
    def _safe_db_path(path):
        return state.safe_db_path(path)
    def parse_ports_spec(ports_spec):
        return state.parse_ports_spec(ports_spec)

    try:
        from web.services_health import _health_monitor_loop
    except ImportError:
        try:
            from services_health import _health_monitor_loop  # type: ignore
        except Exception:
            _health_monitor_loop = None


    @app.route('/api/health/status')
    def health_status():
        # 持锁快照：监控线程会在同一批 dict 里 del/insert，无锁遍历 values()/切片
        # 会抛 RuntimeError: dictionary changed size during iteration → 间歇性 500
        with health_lock:
            return jsonify({
                "running": health_monitor["running"],
                "once_running": health_monitor.get("once_running", False),
                "interval": health_monitor["interval"],
                "last_check": health_monitor["last_check"],
                "monitored": len(health_monitor["status"]),
                "online_servers": sum(1 for s in health_monitor["status"].values() if s.get("online")),
                "events": health_monitor["events"][:30],
                "status": {k: dict(v) for k, v in health_monitor["status"].items()}
            })

    @app.route('/api/health/toggle', methods=['POST'])
    def health_toggle():
        # 与监控线程共享 running/thread，加锁避免并发 toggle 起两个监控线程
        with health_lock:
            if health_monitor["running"]:
                health_monitor["stop_event"].set()
                health_monitor["running"] = False
                return jsonify({"success": True, "running": False})
            health_monitor["stop_event"].clear()
            health_monitor["thread"] = threading.Thread(target=_health_monitor_loop, daemon=True)
            health_monitor["thread"].start()
            health_monitor["running"] = True
            return jsonify({"success": True, "running": True})

    @app.route('/api/health/run_once', methods=['POST'])
    def health_run_once():
        """立即手动跑一轮探测。定时监控或上一次手动检查在跑时不重复触发。"""
        if _health_monitor_loop is None:
            return jsonify({"success": False, "error": "监控模块未加载"}), 500
        if health_monitor.get("running"):
            return jsonify({"success": False, "error": "定时监控正在运行，本轮结束后会自动检查"}), 409
        if health_monitor.get("once_running"):
            return jsonify({"success": False, "error": "上一次手动检查还在进行中"}), 409
        health_monitor["once_running"] = True
        def _run():
            try:
                _health_monitor_loop(once=True)
            finally:
                health_monitor["once_running"] = False
        threading.Thread(target=_run, daemon=True).start()
        return jsonify({"success": True})

    @app.route("/api/shutdown", methods=["POST"])
    def shutdown():
        import os
        threading.Timer(0.5, lambda: os._exit(0)).start()
        return jsonify({"success": True, "msg": "正在关闭..."})

