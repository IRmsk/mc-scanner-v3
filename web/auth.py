# -*- coding: utf-8 -*-
"""Web 面板账号与登录会话管理。

- 默认账号 admin / admin123，首次登录强制修改用户名和密码
- 账号信息存 auth.json（已被 .gitignore 排除，不会入库）
- 密码使用标准库 PBKDF2-SHA256 加盐哈希存储（零依赖、抗暴力破解）
- 会话：随机会话 token 存内存，7 天过期；前端存 localStorage 并以 X-API-Token 头携带
"""
import hashlib
import json
import os
import secrets
import threading
import time
from datetime import datetime

_AUTH_FILE = "auth.json"
_SESSION_TTL = 7 * 24 * 3600  # 7 天
_PBKDF2_ITER = 200_000

_lock = threading.Lock()
_sessions = {}  # token -> {"username": str, "expires": float}


def _auth_path() -> str:
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), _AUTH_FILE)


def _hash_password(password: str, salt: bytes = None) -> str:
    if salt is None:
        salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _PBKDF2_ITER)
    return f"pbkdf2_sha256${_PBKDF2_ITER}${salt.hex()}${digest.hex()}"


def _verify_password(password: str, stored: str) -> bool:
    if not stored:
        return False
    try:
        algo, iter_s, salt_hex, hash_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iter_s))
        return secrets.compare_digest(digest.hex(), hash_hex)
    except Exception:
        return False


def load_account() -> dict:
    """返回当前账号；auth.json 不存在时返回默认账号（admin/admin123，需首次修改）。"""
    path = _auth_path()
    if os.path.exists(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            if isinstance(data, dict) and data.get("username") and data.get("password_hash"):
                return data
        except (json.JSONDecodeError, OSError):
            pass
    # 默认账号：密码固定 admin123，第一次登录必须改
    return {
        "username": "admin",
        "password_hash": _hash_password("admin123"),
        "must_change": True,
    }


def save_account(account: dict) -> bool:
    """原子写 auth.json。"""
    path = _auth_path()
    with _lock:
        try:
            tmp = path + ".tmp"
            with open(tmp, 'w', encoding='utf-8') as f:
                json.dump(account, f, ensure_ascii=False, indent=2)
            os.replace(tmp, path)
            return True
        except OSError as e:
            print(f"[!] 账号保存失败: {e}")
            return False


def check_login(username: str, password: str):
    """校验用户名密码，成功返回账号 dict，失败返回 None。"""
    account = load_account()
    if username == account.get("username") and _verify_password(password or "", account.get("password_hash", "")):
        return account
    return None


def create_session(username: str) -> str:
    token = secrets.token_hex(32)
    with _lock:
        _sessions[token] = {"username": username, "expires": time.time() + _SESSION_TTL}
    return token


def verify_session(token: str):
    """校验会话 token，返回用户名；无效/过期返回 None。"""
    if not token:
        return None
    with _lock:
        s = _sessions.get(token)
        if not s:
            return None
        if s["expires"] < time.time():
            del _sessions[token]
            return None
        return s["username"]


def destroy_session(token: str):
    with _lock:
        _sessions.pop(token, None)


def fixed_token() -> str:
    """配置里的固定 token（config.web_token / MC_WEB_TOKEN）。

    给脚本、CLI 和外部调用方用：它们没有登录会话，但可以带这个长期 token。
    返回空字符串表示未启用固定 token。
    """
    try:
        import config as _cfg
        return str(_cfg.get("web_token", "") or "").strip()
    except Exception:
        return ""


def must_change_pending() -> bool:
    """默认账号是否还没改过密码（must_change=True 时后端会拒绝非 auth 接口）。"""
    return bool(load_account().get("must_change"))


def change_account(new_username: str, new_password: str) -> bool:
    """更新账号用户名和密码（must_change 置 False），原子写盘。"""
    account = load_account()
    account["username"] = new_username
    account["password_hash"] = _hash_password(new_password)
    account["must_change"] = False
    account["updated_at"] = datetime.now().isoformat()
    return save_account(account)


def register(app):
    """注册登录相关路由。"""
    from flask import request, jsonify

    @app.route('/api/auth/login', methods=['POST'])
    def auth_login():
        data = request.json or {}
        username = (data.get("username") or "").strip()
        password = data.get("password") or ""
        if not username or not password:
            return jsonify({"error": "请输入用户名和密码"}), 400
        account = check_login(username, password)
        if not account:
            return jsonify({"error": "用户名或密码错误"}), 401
        token = create_session(username)
        return jsonify({
            "success": True,
            "token": token,
            "username": username,
            "must_change": bool(account.get("must_change")),
        })

    @app.route('/api/auth/status')
    def auth_status():
        token = request.headers.get("X-API-Token", "")
        username = verify_session(token)
        if not username:
            return jsonify({"logged_in": False}), 401
        return jsonify({
            "logged_in": True,
            "username": load_account().get("username", username),
            "must_change": bool(load_account().get("must_change")),
        })

    @app.route('/api/auth/change_password', methods=['POST'])
    def auth_change_password():
        data = request.json or {}
        token = request.headers.get("X-API-Token", "")
        username = verify_session(token)
        if not username:
            return jsonify({"error": "会话已过期，请重新登录"}), 401
        account = load_account()
        old_password = data.get("old_password") or ""
        if not _verify_password(old_password, account.get("password_hash", "")):
            return jsonify({"error": "当前密码错误"}), 400
        new_username = (data.get("new_username") or "").strip()
        new_password = data.get("new_password") or ""
        if len(new_username) < 2:
            return jsonify({"error": "用户名至少 2 个字符"}), 400
        if len(new_password) < 6:
            return jsonify({"error": "密码至少 6 位"}), 400
        if not change_account(new_username, new_password):
            return jsonify({"error": "账号保存失败"}), 500
        return jsonify({"success": True, "username": new_username, "must_change": False})

    @app.route('/api/auth/logout', methods=['POST'])
    def auth_logout():
        token = request.headers.get("X-API-Token", "")
        destroy_session(token)
        return jsonify({"success": True})
