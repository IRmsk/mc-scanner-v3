# -*- coding: utf-8 -*-
"""Routes: ai_bots"""
from flask import jsonify, request

import config
import logger

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


def register(app):
    _ai_bots = state._ai_bots
    def _log(msg):
        state.log_scan(msg)
    def _safe_db_path(path):
        return state.safe_db_path(path)
    def parse_ports_spec(ports_spec):
        return state.parse_ports_spec(ports_spec)

    try:
        from web.services_assistant import _handle_assistant_command
    except ImportError:
        from services_assistant import _handle_assistant_command  # type: ignore


    @app.route('/api/ai_bot/start', methods=['POST'])
    def ai_bot_start():
        if state.is_read_only():
            return jsonify({"error": "只读模式下禁止AI进服"}), 403
        if not state.capability_enabled("login_interact"):
            return jsonify({"error": "进服交互能力未启用，请在config中设置 capabilities.login_interact=true"}), 403
        data = request.json or {}
        host = data.get("host")
        port = int(data.get("port") or 25565)
        username = data.get("username", "AI助手")
        if not host:
            return jsonify({"success": False, "error": "请指定服务器地址"}), 400
        # 序号分配加锁：无锁自增会让并发请求拿到同名 session_id，旧会话被覆盖且无法 stop
        session_id = f"aibot_{state.next_ai_bot_seq()}"
        from core.ai_bot import AIBotSession
        ai_cfg = data.get("ai_config", {})
        # api_key/base_url 只取服务端配置：允许请求方指定 URL 会让服务端把 ai_api_key
        # 以 Bearer 发往任意地址（SSRF + 凭据外泄），与 routes_ai.py 同因
        ai_cfg["api_key"] = config.get("ai_api_key", "")
        ai_cfg["base_url"] = config.get("ai_base_url", "https://api.openai.com/v1")
        if not ai_cfg.get("model"):
            ai_cfg["model"] = config.get("ai_model", "gpt-3.5-turbo")
        if "reply_cooldown" not in ai_cfg or ai_cfg.get("reply_cooldown") is None:
            ai_cfg["reply_cooldown"] = config.get("ai_reply_cooldown", 2.0)
        session = AIBotSession(
            host=host, port=port, username=username,
            authme_password=data.get("authme_password"),
            timeout=float(data.get("timeout", 20.0)),
            duration=float(data.get("duration", 0) or 0),
            protocol_version=data.get("protocol_version"),
            ai_config=ai_cfg,
            use_premium=bool(data.get("use_premium", False)),
            premium_uuid=data.get("premium_uuid") or None,
        )
        session.session_id = session_id
        session.start()
        _ai_bots[session_id] = session
        return jsonify({"success": True, "session_id": session_id})

    @app.route('/api/ai_bot/stop', methods=['POST'])
    def ai_bot_stop():
        data = request.json or {}
        sid = data.get("session_id")
        if sid in _ai_bots:
            _ai_bots[sid].stop()
            del _ai_bots[sid]
            return jsonify({"success": True})
        return jsonify({"success": False, "error": "会话不存在"}), 404

    @app.route('/api/ai_bot/list')
    def ai_bot_list():
        return jsonify({"sessions": [s.get_status() for s in _ai_bots.values()]})

    @app.route('/api/ai_bot/chat')
    def ai_bot_chat():
        sid = request.args.get("session_id")
        since = _to_int(request.args.get("since"), 0)
        if sid in _ai_bots:
            return jsonify({"messages": _ai_bots[sid].get_chat(since)})
        return jsonify({"messages": []})

    @app.route('/api/ai_bot/send', methods=['POST'])
    def ai_bot_send():
        data = request.json or {}
        sid = data.get("session_id")
        msg = data.get("message", "")
        if sid in _ai_bots and msg:
            ok = _ai_bots[sid].send_message(msg)
            return jsonify({"success": ok})
        return jsonify({"success": False, "error": "会话不存在或消息为空"}), 400

    @app.route('/api/ai_multi/start', methods=['POST'])
    def ai_multi_start():
        if state.is_read_only():
            return jsonify({"error": "只读模式下禁止AI进服"}), 403
        if not state.capability_enabled("login_interact"):
            return jsonify({"error": "进服交互能力未启用，请在config中设置 capabilities.login_interact=true"}), 403
        data = request.json or {}
        host = data.get("host")
        port = int(data.get("port") or 25565)
        if not host:
            return jsonify({"success": False, "error": "请指定服务器地址"}), 400
        bot_count = int(data.get("bot_count", 3))
        bot_count = max(2, min(8, bot_count))
        from core.ai_bot import multi_ai_bot
        ai_cfg = data.get("ai_config", {})
        # api_key/base_url 只取服务端配置：允许请求方指定 URL 会让服务端把 ai_api_key
        # 以 Bearer 发往任意地址（SSRF + 凭据外泄），与 routes_ai.py 同因
        ai_cfg["api_key"] = config.get("ai_api_key", "")
        ai_cfg["base_url"] = config.get("ai_base_url", "https://api.openai.com/v1")
        if not ai_cfg.get("model"):
            ai_cfg["model"] = config.get("ai_model", "gpt-3.5-turbo")
        if "reply_cooldown" not in ai_cfg or ai_cfg.get("reply_cooldown") is None:
            ai_cfg["reply_cooldown"] = config.get("ai_reply_cooldown", 2.0)
        group_id = multi_ai_bot.start_group(
            host=host, port=port,
            bot_count=bot_count,
            topic=data.get("topic", ""),
            duration=float(data.get("duration", 0) or 0),
            authme_password=data.get("authme_password"),
            ai_config=ai_cfg,
            persona_indices=data.get("persona_indices"),
            use_premium=bool(data.get("use_premium", False)),
            premium_uuid=data.get("premium_uuid") or None,
        )
        return jsonify({"success": True, "group_id": group_id})

    @app.route('/api/ai_multi/stop', methods=['POST'])
    def ai_multi_stop():
        data = request.json or {}
        gid = data.get("group_id")
        from core.ai_bot import multi_ai_bot
        ok = multi_ai_bot.stop_group(gid)
        return jsonify({"success": ok})

    @app.route('/api/ai_multi/list')
    def ai_multi_list():
        from core.ai_bot import multi_ai_bot
        return jsonify({"groups": multi_ai_bot.list_groups()})

    @app.route('/api/ai_multi/chat')
    def ai_multi_chat():
        gid = request.args.get("group_id")
        since = _to_int(request.args.get("since"), 0)
        from core.ai_bot import multi_ai_bot
        return jsonify({"messages": multi_ai_bot.get_group_chat(gid, since)})

    @app.route('/api/ai_multi/send', methods=['POST'])
    def ai_multi_send():
        data = request.json or {}
        gid = data.get("group_id")
        msg = data.get("message", "")
        from core.ai_bot import multi_ai_bot
        ok = multi_ai_bot.send_to_all(gid, msg)
        return jsonify({"success": ok})

    @app.route('/api/ai_multi/personas')
    def ai_multi_personas():
        try:
            from core.ai_personas import PRESET_PERSONAS
        except Exception:
            logger.exception("[api] ai_multi_personas 未处理异常")
            from core.ai_bot import PRESET_PERSONAS
        out = []
        for p in PRESET_PERSONAS:
            persona = p.get("persona") or ""
            out.append({
                "name": p.get("name", ""),
                "label": p.get("label", p.get("name", "")),
                "persona": persona,
                "preview": persona[:60].replace("\n", " "),
            })
        return jsonify({"personas": out})

    @app.route('/api/ai_memory/clear', methods=['POST'])
    def ai_memory_clear():
        """清除AI长期玩家记忆。body: {player?: 名字}，不传player则清除全部"""
        data = request.json or {}
        player = (data.get("player") or "").strip()
        try:
            from core import ai_memory
            if player:
                ok = ai_memory.clear_player(player)
                return jsonify({"success": ok, "cleared_player": player})
            n = ai_memory.clear_all_memory()
            return jsonify({"success": True, "cleared_count": n})
        except Exception as e:
            logger.exception("[api] ai_memory_clear 未处理异常")
            return jsonify({"success": False, "error": str(e)}), 500

    @app.route('/api/assistant/chat', methods=['POST'])
    def assistant_chat():
        """AI助手：自然语言指令控制扫描器"""
        data = request.json or {}
        msg = (data.get("message", "") or "").strip()
        if not msg:
            return jsonify({"reply": "你说啥？"})

        reply = _handle_assistant_command(msg)
        return jsonify({"reply": reply})
