# -*- coding: utf-8 -*-
"""Web 控制面板（拆分路由版）。"""
import logging
import os
import secrets
import sys

from flask import Flask, jsonify, request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
import logger

logging.getLogger("werkzeug").setLevel(logging.WARNING)

app = Flask(__name__)
try:
    app.json.ensure_ascii = False
except AttributeError:
    app.config["JSON_AS_ASCII"] = False


# PWA 文件路由
@app.route('/manifest.json')
def _manifest():
    from flask import send_from_directory
    return send_from_directory(os.path.join(os.path.dirname(__file__), 'static'), 'manifest.json', mimetype='application/manifest+json')

@app.route('/sw.js')
def _sw():
    from flask import send_from_directory
    return send_from_directory(os.path.join(os.path.dirname(__file__), 'static'), 'sw.js', mimetype='application/javascript')




# API限流：按IP+模块，滑动窗口60秒
import threading as _threading
import time as _time

_rate_limit_store = {}  # (ip, module) -> [timestamps]
_rate_limit_lock = _threading.Lock()
_RATE_WINDOW = 60.0  # 秒

# 单模块收紧上限：配置文件里的 api_rate_limit 与本表取小值。
#   auth  —— 每次登录要算两次 200k 轮 PBKDF2，不限速=无限爆破+CPU DoS
#   ai    —— 面板会轮询 /api/ai_bot/chat、/api/ai_multi/chat（各1次/2秒），留足余量
# scan 不单独设限：/api/scan/status 与 /api/scan/tasks 每秒各轮询一次，由 api_rate_limit（600）兜底
_RATE_MODULE_CAP = {"auth": 20, "ai": 180}


def _get_module(path):
    if path.startswith("/api/scan/") or path.startswith("/api/masscan/"):
        return "scan"
    if path.startswith("/api/ai_bot/") or path.startswith("/api/ai_multi/") or path.startswith("/api/assistant/"):
        return "ai"
    if path.startswith("/api/auth/"):
        return "auth"
    return None

@app.before_request
def _rate_limit():
    try:
        limit = int(config.get("api_rate_limit", 0))
        if limit <= 0:
            return None
        module = _get_module(request.path)
        if not module:
            return None
        limit = min(limit, _RATE_MODULE_CAP.get(module, limit))
        ip = request.remote_addr or "unknown"
        key = (ip, module)
        now = _time.time()
        with _rate_limit_lock:
            # 清理过期时间戳，空列表的key也删掉防内存泄漏
            if key in _rate_limit_store:
                active = [t for t in _rate_limit_store[key] if now - t < _RATE_WINDOW]
                if active:
                    _rate_limit_store[key] = active
                else:
                    del _rate_limit_store[key]
            if key not in _rate_limit_store:
                _rate_limit_store[key] = []
            if len(_rate_limit_store[key]) >= limit:
                return jsonify({"error": f"请求过于频繁，{module}模块限{limit}次/分钟"}), 429
            _rate_limit_store[key].append(now)
    except Exception:
        pass
    return None


# 无需鉴权的路径：页面壳、静态资源、登录入口。
# 页面本身只是空壳，数据全部在 /api/ 后面，所以放行 HTML 不泄露任何状态。
_PUBLIC_PATHS = frozenset({
    "/", "/index.html", "/favicon.ico",
    "/manifest.json", "/sw.js",
    "/api/auth/login", "/api/auth/status",
})
_PUBLIC_PREFIXES = ("/static/",)


def _extract_token():
    """按 头 > 查询参数 > 请求体 的顺序取 token。"""
    token = request.headers.get("X-API-Token", "")
    if not token:
        token = request.args.get("token", "")
    if not token and request.method in ("POST", "PUT", "PATCH"):
        body = request.get_json(silent=True)
        if isinstance(body, dict) and isinstance(body.get("token"), str):
            token = body["token"]
    return token.strip() if isinstance(token, str) else ""


@app.before_request
def _check_auth():
    """token 鉴权：/api/* 需要登录会话，或配置的固定 token（web_token / MC_WEB_TOKEN）。

    两种情况都通过：
      1. 前端登录拿到的会话 token（X-API-Token，7 天有效）
      2. config.web_token / MC_WEB_TOKEN 配置的固定 token（给脚本和 CLI 用）
    """
    path = request.path
    if not path.startswith("/api/"):
        return None
    if path in _PUBLIC_PATHS or path.startswith(_PUBLIC_PREFIXES):
        return None

    from web import auth as _auth
    token = _extract_token()

    username = _auth.verify_session(token)
    if username:
        # 默认账号未改密时只放行 auth 接口，否则"强制改密"只是前端弹窗
        if _auth.must_change_pending() and not path.startswith("/api/auth/"):
            return jsonify({"error": "请先修改默认账号密码", "must_change": True}), 403
        request.environ["mc.username"] = username
        return None

    fixed = _auth.fixed_token()
    if fixed and token and secrets.compare_digest(token, fixed):
        request.environ["mc.username"] = "web_token"
        return None

    return jsonify({"error": "未登录或会话已过期", "need_login": True}), 401


@app.before_request
def _audit_log():
    """写操作审计日志：记录所有POST/DELETE/PUT请求"""
    try:
        if request.method in ("POST", "DELETE", "PUT") and request.path.startswith("/api/"):
            ip = request.remote_addr or "unknown"
            # 提取目标信息（从请求体里取ip/port/target等关键字段）
            target = ""
            try:
                data = request.get_json(silent=True) or {}
                if data.get("ip") and data.get("port"):
                    target = f" {data['ip']}:{data['port']}"
                elif data.get("targets"):
                    target = f" targets={str(data['targets'])[:50]}"
                elif data.get("username"):
                    target = f" user={data['username']}"
            except Exception:
                pass
            logger.info(f"[审计] {ip} {request.method} {request.path}{target}")
    except Exception:
        pass
    return None


def _register_routes():
    modules = [
        "auth", "routes_core", "routes_scan", "routes_scan_extra",
        "routes_data", "routes_ai", "routes_ai_bots", "routes_observer",
        "routes_config", "routes_ops", "routes_tools",
    ]
    for name in modules:
        if __package__:
            mod = __import__(f"{__package__}.{name}", fromlist=["register"])
        else:
            mod = __import__(name, fromlist=["register"])
        mod.register(app)
        logger.info(f"[web] registered {name}")


_register_routes()


@app.errorhandler(404)
def _not_found(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "接口不存在", "path": request.path}), 404
    return "Not Found", 404


@app.errorhandler(500)
def _internal_error(e):
    # API 统一返回 JSON，避免前端 fetch().json() 拿到 HTML 错误页
    if request.path.startswith("/api/"):
        return jsonify({"error": "服务器内部错误"}), 500
    return "Internal Server Error", 500


@app.after_request
def _security_headers(resp):
    # 基础安全响应头：防 MIME 嗅探、防嵌入、限制来源泄露
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("X-XSS-Protection", "1; mode=block")
    return resp


def _guard_public_bind(host):
    """绑定 0.0.0.0 时的安全检查，没设 ALLOW_PUBLIC_BIND 就拒绝。"""
    import os
    if host in ("0.0.0.0", "::"):
        if not os.environ.get("ALLOW_PUBLIC_BIND"):
            logger.error("[!] 安全拦截：绑定 0.0.0.0 需显式确认（无鉴权 + 含敏感凭据）")
            logger.error("    如确需局域网访问，请设置环境变量 ALLOW_PUBLIC_BIND=1 后重试")
            raise SystemExit(1)
        logger.warning("[!] 已绑定 0.0.0.0（局域网可访问）——本工具无鉴权，局域网内任何人可操作，请确保网络可信")


def run(db_path: str = "mcscanner.db", port: int = 8080, host: str = "127.0.0.1"):
    logger.setup_logger()
    from storage import db
    db.init_db(db_path)
    # 定期清理超旧离线记录
    try:
        retention = int(config.get("db_retention_days", 0))
        if retention > 0:
            deleted = db.clean_old_records(db_path, retention_days=retention, only_offline=True)
            if deleted > 0:
                logger.info(f"[*] 清理超旧离线记录: {deleted} 条（保留{retention}天）")
    except Exception as e:
        logger.warning(f"[!] 旧记录清理失败: {e}")
    try:
        from core.conn import set_global_proxy_manager
        from core.proxy import get_proxy_manager
        proxy_file = config.get("proxy_file", "proxies.txt")
        if os.path.exists(proxy_file):
            mgr = get_proxy_manager(proxy_file=proxy_file, auto_fetch=False)
            if mgr and mgr.proxies:
                set_global_proxy_manager(mgr)
                logger.info(f"[*] 已启用代理: {len(mgr.proxies)} 个")
    except Exception as e:
        logger.warning(f"[!] 代理初始化失败: {e}")
    logger.info(f"[*] Web 面板启动: http://{host}:{port}")
    _guard_public_bind(host)
    app.run(host=host, port=port, debug=False, threaded=True)


if __name__ == "__main__":
    run()
