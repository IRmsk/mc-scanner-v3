# -*- coding: utf-8 -*-
"""Routes: config"""
from datetime import datetime

from flask import jsonify, request

import config
import logger
from core.bot import DEFAULT_WARNING_MESSAGES

try:
    from web import state
except ImportError:
    import state  # type: ignore


def register(app):
    def _log(msg):
        state.log_scan(msg)
    def _safe_db_path(path):
        return state.safe_db_path(path)
    def parse_ports_spec(ports_spec):
        return state.parse_ports_spec(ports_spec)

    # ===== 正版多账户管理 =====
    def _msa_accounts():
        """获取正版账户列表（兼容旧字段自动迁移）"""
        accounts = config.get("msa_accounts", []) or []
        old_token = config.get("msa_access_token", "") or ""
        old_uuid = config.get("msa_uuid", "") or ""
        old_name = config.get("msa_name", "") or ""
        if old_token and old_uuid and not any(a.get("uuid") == old_uuid for a in accounts):
            accounts.append({"name": old_name, "uuid": old_uuid, "access_token": old_token})
            config.set("msa_accounts", accounts)
            try:
                config.save_config()
            except Exception:
                logger.exception("[api] _msa_accounts 未处理异常")
        return accounts

    def _msa_save_account(name, uuid, access_token, refresh_token=None):
        """保存/更新一个正版账户，并设为活跃"""
        accounts = _msa_accounts()
        found = False
        for a in accounts:
            if a.get("uuid") == uuid:
                a["name"] = name
                a["access_token"] = access_token
                if refresh_token:
                    a["refresh_token"] = refresh_token
                found = True
                break
        if not found:
            acct = {"name": name, "uuid": uuid, "access_token": access_token}
            if refresh_token:
                acct["refresh_token"] = refresh_token
            accounts.append(acct)
        config.set("msa_accounts", accounts)
        config.set("msa_active_uuid", uuid)
        # 新字段（清晰命名）
        config.set("mc_access_token", access_token)
        config.set("mc_uuid", uuid)
        config.set("mc_name", name)
        if refresh_token:
            config.set("msa_refresh_token", refresh_token)
        # 兼容旧字段
        config.set("msa_access_token", access_token)
        config.set("msa_uuid", uuid)
        config.set("msa_name", name)
        try:
            config.save_config()
        except Exception:
            logger.exception("[api] _msa_save_account 未处理异常")

    def _msa_active_account():
        """获取当前活跃的正版账户"""
        accounts = _msa_accounts()
        active_uuid = config.get("msa_active_uuid", "") or ""
        if active_uuid:
            for a in accounts:
                if a.get("uuid") == active_uuid:
                    return a
        return accounts[0] if accounts else None


    @app.route('/api/config/default')
    def default_config():
        return jsonify({
            "workers": 32,
            "timeout": 4.0,
            "scan_threads": 200,
            "scan_timeout": 2.5,
            "rate": 0,
            "auth_check": True,
            "username": "SecurityBot",
            "messages": DEFAULT_WARNING_MESSAGES,
            "use_masscan": False,
            "portscan_only": False,
            "masscan_rate": 5000,
            "ports": [25565],
        })

    @app.route('/api/config/get')
    def config_get():
        """读取当前配置（敏感字段打码）"""
        import copy
        cfg = copy.deepcopy(config.get_all())  # 深拷贝，打码不污染内存中的真实配置
        # 敏感字段打码（前缀只露2位，降低定向攻击风险）
        for k in ("ai_api_key", "authme_password", "email_password",
                  "mc_access_token", "msa_access_token", "msa_refresh_token"):
            if cfg.get(k):
                v = str(cfg[k])
                cfg[k] = v[:2] + "****" + v[-2:] if len(v) > 8 else "****"
        # msa_accounts列表里的access_token/refresh_token也打码
        if isinstance(cfg.get("msa_accounts"), list):
            for a in cfg["msa_accounts"]:
                if isinstance(a, dict):
                    for tk in ("access_token", "refresh_token"):
                        if a.get(tk):
                            v = str(a[tk])
                            a[tk] = v[:2] + "****" + v[-2:] if len(v) > 8 else "****"
        # ai_api_keys预设列表里的api_key也打码
        if isinstance(cfg.get("ai_api_keys"), list):
            for p in cfg["ai_api_keys"]:
                if isinstance(p, dict) and p.get("api_key"):
                    v = str(p["api_key"])
                    p["api_key"] = v[:2] + "****" + v[-2:] if len(v) > 8 else "****"
        return jsonify(cfg)

    @app.route('/api/config/save', methods=['POST'])
    def config_save():
        """保存配置到文件"""
        data = request.json or {}
        # 只允许保存白名单字段
        allowed = {"ai_api_key", "ai_base_url", "ai_model", "ai_api_keys", "ai_allow_insecure",
                   "ai_request_timeout", "ai_max_tokens", "web_host", "web_port",
                   "message_delay", "bot_timeout", "exclude_file", "db_path", "log_level",
                   "email_enabled", "email_smtp_host", "email_smtp_port", "email_smtp_ssl",
                   "email_username", "email_password", "email_from", "email_to",
                   "health_interval", "health_probe_concurrency", "health_probe_ip_gap",
                   "health_monitor_db_extra"}
        to_save = {k: v for k, v in data.items() if k in allowed}
        # 路径类字段强校验：白名单里的 db_path/exclude_file 原来是任意字符串，
        # 可把库指到任意可写路径、让 Excluder 去 open 任意文件（鉴权受限下的最小收敛）
        if "db_path" in to_save:
            db_path = _safe_db_path(to_save["db_path"])
            if db_path != to_save["db_path"]:
                return jsonify({"success": False, "error": "db_path 只允许纯文件名（.db 结尾）"}), 400
            to_save["db_path"] = db_path
        if "exclude_file" in to_save:
            exclude_name = str(to_save["exclude_file"] or "")
            if exclude_name != "exclude.conf":
                return jsonify({"success": False, "error": "exclude_file 只允许 exclude.conf"}), 400
            to_save["exclude_file"] = exclude_name
        # api_key如果是打码状态（含****），不覆盖原值
        if "ai_api_key" in to_save and "****" in str(to_save["ai_api_key"]):
            del to_save["ai_api_key"]
        if "email_password" in to_save and "****" in str(to_save["email_password"]):
            del to_save["email_password"]
        # ai_api_keys预设列表里打码的api_key保留原值
        if isinstance(to_save.get("ai_api_keys"), list):
            existing = config.get("ai_api_keys", []) or []
            for i, p in enumerate(to_save["ai_api_keys"]):
                if isinstance(p, dict) and "****" in str(p.get("api_key", "")):
                    # 找同名预设保留原key
                    orig = next((e for e in existing if isinstance(e, dict) and e.get("name") == p.get("name")), None)
                    if orig and orig.get("api_key"):
                        p["api_key"] = orig["api_key"]
                    elif i < len(existing) and isinstance(existing[i], dict):
                        p["api_key"] = existing[i].get("api_key", "")
        ok = config.save_config(to_save)
        return jsonify({"success": ok, "saved": list(to_save.keys())})

    @app.route('/api/config/read_only', methods=['POST'])
    def config_read_only():
        """切换只读模式：开启后禁止警告/进服/扫描等危险操作"""
        data = request.json or {}
        enabled = bool(data.get("enabled", False))
        state.set_read_only(enabled)
        # 同时持久化到config
        config.save_config({"read_only_mode": enabled})
        return jsonify({"success": True, "read_only": enabled})

    @app.route('/api/config/read_only', methods=['GET'])
    def config_read_only_status():
        return jsonify({"read_only": state.is_read_only()})

    @app.route('/api/config/capability', methods=['POST'])
    def config_capability():
        """切换能力开关（进服交互/RCON命令等高风险能力）。
        开启前必须先由前端展示风险确认；本接口仅做白名单校验与持久化。"""
        data = request.json or {}
        cap = str(data.get("cap", ""))
        enabled = bool(data.get("enabled", False))
        allowed_caps = {"scan", "login_interact", "rcon_commands"}
        if cap not in allowed_caps:
            return jsonify({"success": False, "error": f"未知能力: {cap}"}), 400
        caps = config.get("capabilities", {}) or {}
        if not isinstance(caps, dict):
            caps = {}
        caps[cap] = enabled
        if not config.save_config({"capabilities": caps}):
            return jsonify({"success": False, "error": "保存配置失败"}), 500
        return jsonify({
            "success": True,
            "capabilities": {
                "scan": state.capability_enabled("scan"),
                "login_interact": state.capability_enabled("login_interact"),
                "rcon_commands": state.capability_enabled("rcon_commands"),
            },
        })

    @app.route('/api/security/status', methods=['GET'])
    def security_status():
        """返回完整安全/能力状态，供前端常显并禁用未授权按钮"""
        return jsonify({
            "read_only": state.is_read_only(),
            "capabilities": {
                "scan": state.capability_enabled("scan"),
                "login_interact": state.capability_enabled("login_interact"),
                "rcon_commands": state.capability_enabled("rcon_commands"),
            },
        })

    @app.route('/api/email/test', methods=['POST'])
    def email_test():
        """发送测试邮件。

        主机、端口、账号密码只取服务端保存的配置：原实现允许请求体覆盖 smtp_host/
        username/password，等于任何人可拿服务端保存的邮箱凭据去连任意主机
        （出站 SSRF/内网端口探测 + 凭据外泄）。收件人与显示名仍可用请求值，它们不决定出站目标。
        """
        data = request.json or {}
        cfg = {
            "smtp_host": config.get("email_smtp_host", ""),
            "smtp_port": config.get("email_smtp_port", 465),
            "smtp_ssl": config.get("email_smtp_ssl", True),
            "username": config.get("email_username", ""),
            "password": config.get("email_password", ""),
            "from": data.get("from_addr") or config.get("email_from", "") or config.get("email_username", ""),
            "to": data.get("to") or config.get("email_to", ""),
        }
        if not cfg["smtp_host"]:
            return jsonify({"success": False, "error": "请先在设置中保存 SMTP 服务器地址，再发送测试邮件"})
        from core.notifier import send_email
        subject = "[MC扫描] 邮件测试"
        body = f"""<html><body>
    <h2>MC扫描器邮件测试</h2>
    <p>如果你收到这封邮件，说明邮件配置正确！</p>
    <p>扫描完成后会自动发送结果摘要到这里。</p>
    <p style="color:#999;font-size:12px;">发送时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </body></html>"""
        ok, err = send_email(subject, body, html=True, cfg=cfg)
        return jsonify({"success": ok, "error": err})

    # ===== 正版账号登录 =====
    _msa_state = {"step": "idle", "device_code": None, "interval": 5, "client_id": ""}

    @app.route('/api/msa/start', methods=['POST'])
    def msa_start():
        from core.microsoft_auth import CLIENT_ID, start_device_code
        data = request.get_json(silent=True) or {}
        cid = data.get("client_id", "") or CLIENT_ID
        try:
            r = start_device_code(cid)
            if "error" in r:
                return jsonify({"success": False, "error": r.get("error_description", str(r))})
            _msa_state["step"] = "waiting"
            _msa_state["device_code"] = r["device_code"]
            _msa_state["interval"] = r.get("interval", 5)
            _msa_state["client_id"] = cid
            return jsonify({"success": True, "user_code": r["user_code"],
                            "verification_uri": r["verification_uri"], "interval": r["interval"]})
        except Exception as e:
            logger.exception("[api] msa_start 未处理异常")
            import traceback
            traceback.print_exc()
            return jsonify({"success": False, "error": str(e)})

    @app.route('/api/msa/poll', methods=['GET', 'POST'])
    def msa_poll():
        from core.microsoft_auth import full_login_flow, poll_token
        # 支持POST传device_code，或GET用全局state
        device_code = None
        if request.method == 'POST':
            device_code = (request.get_json(silent=True) or {}).get("device_code", "") or request.form.get("device_code", "")
        if not device_code and _msa_state.get("step") == "waiting":
            device_code = _msa_state["device_code"]
        if not device_code:
            return jsonify({"success": False, "error": "未开始登录", "waiting": False})
        try:
            r = poll_token(device_code, _msa_state.get("client_id"))
            if "error" in r:
                err = r.get("error", "")
                if err == "expired_token" or err == "expired":
                    return jsonify({"success": False, "error": "expired", "waiting": False})
                # authorization_pending 或 slow_down 继续等
                return jsonify({"success": False, "waiting": True, "error": err})
            msa_token = r["access_token"]
            refresh_token = r.get("refresh_token", "")
            print(f"[MSA] 轮询成功，获取MSA token: {msa_token[:30]}...")
            result = full_login_flow(msa_token)
            _msa_save_account(result["name"], result["uuid"], result["access_token"], refresh_token)
            _msa_state["step"] = "done"
            return jsonify({"success": True, "name": result["name"], "uuid": result["uuid"]})
        except Exception as e:
            logger.exception("[api] msa_poll 未处理异常")
            import traceback
            traceback.print_exc()
            return jsonify({"success": False, "error": str(e), "waiting": True})

    @app.route('/api/msa/fcl_auth_url', methods=['GET'])
    def msa_fcl_auth_url():
        """返回FCL授权码流程的登录URL"""
        from core.microsoft_auth import get_fcl_auth_url
        return jsonify({"url": get_fcl_auth_url()})

    @app.route('/api/msa/fcl_device_start', methods=['POST'])
    def msa_fcl_device_start():
        """FCL设备码流程：开始登录，返回设备码和验证URL"""
        from core.microsoft_auth import fcl_get_device_code
        try:
            r = fcl_get_device_code()
            if "user_code" not in r:
                return jsonify({"success": False, "error": r.get("error_description", str(r))})
            _msa_state["step"] = "fcl_device"
            _msa_state["device_code"] = r.get("device_code", "")
            _msa_state["user_code"] = r.get("user_code", "")
            _msa_state["verification_uri"] = r.get("verification_uri", "https://www.microsoft.com/link")
            _msa_state["expires_in"] = r.get("expires_in", 900)
            print(f"[MSA] FCL设备码获取成功: {r.get('user_code')}")
            return jsonify({
                "success": True,
                "user_code": r.get("user_code"),
                "device_code": r.get("device_code"),
                "verification_uri": r.get("verification_uri", "https://www.microsoft.com/link"),
                "expires_in": r.get("expires_in", 900),
            })
        except Exception as e:
            logger.exception("[api] msa_fcl_device_start 未处理异常")
            import traceback
            traceback.print_exc()
            return jsonify({"success": False, "error": str(e)})

    @app.route('/api/msa/fcl_device_poll', methods=['GET'])
    def msa_fcl_device_poll():
        """FCL设备码流程：轮询登录状态"""
        from core.microsoft_auth import fcl_poll_device_code, full_login_flow
        device_code = _msa_state.get("device_code", "")
        if not device_code:
            return jsonify({"success": False, "error": "未开始设备码登录", "waiting": True})
        try:
            r = fcl_poll_device_code(device_code)
            if "access_token" in r:
                msa_token = r["access_token"]
                refresh_token = r.get("refresh_token", "")
                print(f"[MSA] FCL设备码轮询成功，获取MSA token: {msa_token[:30]}...")
                result = full_login_flow(msa_token)
                _msa_save_account(result["name"], result["uuid"], result["access_token"], refresh_token)
                _msa_state["step"] = "done"
                return jsonify({"success": True, "name": result["name"], "uuid": result["uuid"], "waiting": False})
            elif r.get("error") == "authorization_pending":
                return jsonify({"success": False, "waiting": True, "message": "等待用户登录..."})
            elif r.get("error") == "slow_down":
                return jsonify({"success": False, "waiting": True, "message": "请求过快，稍后重试..."})
            elif r.get("error") == "expired_token":
                _msa_state["step"] = "idle"
                return jsonify({"success": False, "waiting": False, "error": "设备码已过期，请重新开始"})
            else:
                return jsonify({"success": False, "waiting": True, "message": r.get("error_description", str(r))})
        except Exception as e:
            logger.exception("[api] msa_fcl_device_poll 未处理异常")
            import traceback
            traceback.print_exc()
            return jsonify({"success": False, "error": str(e), "waiting": True})

    @app.route('/api/msa/status', methods=['GET'])
    def msa_status():
        accounts = _msa_accounts()
        active = _msa_active_account()
        return jsonify({
            "logged_in": bool(active),
            "name": active.get("name", "") if active else "",
            "active_uuid": active.get("uuid", "") if active else "",
            "accounts": [{"name": a.get("name", ""), "uuid": a.get("uuid", "")} for a in accounts],
        })

    @app.route('/api/msa/accounts', methods=['GET'])
    def msa_list_accounts():
        """获取所有正版账户列表"""
        accounts = _msa_accounts()
        active_uuid = config.get("msa_active_uuid", "") or ""
        return jsonify({
            "accounts": [{"name": a.get("name", ""), "uuid": a.get("uuid", "")} for a in accounts],
            "active_uuid": active_uuid,
        })

    @app.route('/api/msa/active', methods=['POST'])
    def msa_set_active():
        """设置当前活跃的正版账户"""
        data = request.get_json(silent=True) or request.form
        uuid = data.get("uuid", "")
        accounts = _msa_accounts()
        if not any(a.get("uuid") == uuid for a in accounts):
            return jsonify({"success": False, "error": "账户不存在"})
        config.set("msa_active_uuid", uuid)
        # 同步更新所有字段
        for a in accounts:
            if a.get("uuid") == uuid:
                config.set("mc_access_token", a.get("access_token", ""))
                config.set("mc_uuid", a.get("uuid", ""))
                config.set("mc_name", a.get("name", ""))
                config.set("msa_access_token", a.get("access_token", ""))
                config.set("msa_uuid", a.get("uuid", ""))
                config.set("msa_name", a.get("name", ""))
                break
        try:
            config.save_config()
        except Exception:
            logger.exception("[api] msa_set_active 未处理异常")
        return jsonify({"success": True})

    @app.route('/api/msa/accounts/<uuid>', methods=['DELETE'])
    def msa_delete_account(uuid):
        """删除一个正版账户"""
        accounts = _msa_accounts()
        accounts = [a for a in accounts if a.get("uuid") != uuid]
        config.set("msa_accounts", accounts)
        # 如果删除的是活跃账户，切换到第一个
        if config.get("msa_active_uuid", "") == uuid:
            if accounts:
                config.set("msa_active_uuid", accounts[0].get("uuid", ""))
                config.set("mc_access_token", accounts[0].get("access_token", ""))
                config.set("mc_uuid", accounts[0].get("uuid", ""))
                config.set("mc_name", accounts[0].get("name", ""))
                config.set("msa_access_token", accounts[0].get("access_token", ""))
                config.set("msa_uuid", accounts[0].get("uuid", ""))
                config.set("msa_name", accounts[0].get("name", ""))
            else:
                config.set("msa_active_uuid", "")
                config.set("mc_access_token", "")
                config.set("mc_uuid", "")
                config.set("mc_name", "")
                config.set("msa_access_token", "")
                config.set("msa_uuid", "")
                config.set("msa_name", "")
        try:
            config.save_config()
        except Exception:
            logger.exception("[api] msa_delete_account 未处理异常")
        return jsonify({"success": True})

    @app.route('/api/msa/auth_url', methods=['GET'])
    def msa_auth_url():
        """PCL2方式：获取授权码登录URL，WebView直接打开"""
        from core.microsoft_auth import get_auth_url
        cid = request.args.get("client_id", "")
        url = get_auth_url(cid or None)
        return jsonify({"url": url})

    @app.route('/api/msa/exchange', methods=['POST'])
    def msa_exchange():
        """WebView拦截到code后，用code换token"""
        from core.microsoft_auth import exchange_code, full_login_flow
        code = request.form.get("code", "") or (request.get_json(silent=True) or {}).get("code", "")
        if not code:
            return jsonify({"success": False, "error": "缺少code"})
        # URL解码
        import urllib.parse as _up
        code = _up.unquote(code)
        print(f"[MSA] 收到code: {code[:30]}... (长度{len(code)})")
        try:
            r = exchange_code(code)
            if "access_token" not in r:
                return jsonify({"success": False, "error": r.get("error_description", str(r))})
            msa_token = r["access_token"]
            refresh_token = r.get("refresh_token", "")
            result = full_login_flow(msa_token)
            _msa_save_account(result["name"], result["uuid"], result["access_token"], refresh_token)
            return jsonify({"success": True, "name": result["name"]})
        except Exception as e:
            logger.exception("[api] msa_exchange 未处理异常")
            return jsonify({"success": False, "error": str(e)})

    @app.route('/api/msa/token', methods=['POST'])
    def msa_token():
        """直接用MSA access_token登录（隐式流程）"""
        from core.microsoft_auth import full_login_flow
        msa_token = request.form.get("access_token", "") or (request.get_json(silent=True) or {}).get("access_token", "")
        if not msa_token:
            return jsonify({"success": False, "error": "缺少access_token"})
        try:
            print(f"[MSA] 收到MSA token: {msa_token[:30]}...")
            result = full_login_flow(msa_token)
            _msa_save_account(result["name"], result["uuid"], result["access_token"])
            return jsonify({"success": True, "name": result["name"]})
        except Exception as e:
            logger.exception("[api] msa_token 未处理异常")
            import traceback
            traceback.print_exc()
            return jsonify({"success": False, "error": str(e)})

    @app.route('/api/msa/manual', methods=['POST'])
    def msa_manual():
        """手动粘贴Token登录（支持Minecraft access_token或MSA access_token）"""
        from core.microsoft_auth import full_login_flow, mc_profile
        data = request.get_json(silent=True) or {}
        token = data.get("token", "").strip()
        if not token:
            return jsonify({"success": False, "error": "缺少token"})
        try:
            print(f"[MSA] 手动Token登录: {token[:30]}...")
            result = None
            # 先尝试直接当Minecraft access_token用（eyJ开头的JWT）
            if token.startswith("eyJ"):
                try:
                    profile = mc_profile(token)
                    result = {"access_token": token, "uuid": profile["uuid"], "name": profile["name"]}
                    print("[MSA] 直接作为Minecraft token验证成功")
                except Exception as e:
                    print(f"[MSA] 作为Minecraft token失败: {e}，尝试走MSA流程")
            # 如果直接用失败，走MSA→Xbox→XSTS→MC流程
            if not result:
                result = full_login_flow(token)
            _msa_save_account(result["name"], result["uuid"], result["access_token"])
            return jsonify({"success": True, "name": result["name"], "uuid": result["uuid"]})
        except Exception as e:
            logger.exception("[api] msa_manual 未处理异常")
            import traceback
            traceback.print_exc()
            return jsonify({"success": False, "error": str(e)})
