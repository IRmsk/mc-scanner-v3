# -*- coding: utf-8 -*-
"""Routes: ai"""
from flask import Response, jsonify, request

import config

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


    @app.route('/api/ai/presets')
    def ai_presets():
        from core.ai_generator import get_preset_list
        return jsonify({"presets": get_preset_list()})

    @app.route('/api/ai/personas')
    def ai_personas_list():
        """获取所有人格列表（含自定义覆盖）"""
        from core.ai_personas import get_personas
        return jsonify({"personas": get_personas()})

    @app.route('/api/ai/personas/update', methods=['POST'])
    def ai_personas_update():
        """新增或更新人格，即时生效"""
        if state.is_read_only():
            return jsonify({"error": "只读模式下禁止修改人格"}), 403
        data = request.json or {}
        name = (data.get("name") or "").strip()
        label = (data.get("label") or "").strip()
        persona_text = data.get("persona") or ""
        if not name or not persona_text:
            return jsonify({"error": "name和persona不能为空"}), 400
        from core.ai_personas import update_persona
        update_persona(name, label, persona_text)
        return jsonify({"success": True, "name": name})

    @app.route('/api/ai/personas/delete', methods=['POST'])
    def ai_personas_delete():
        """删除自定义人格（预设人格恢复原样）"""
        if state.is_read_only():
            return jsonify({"error": "只读模式下禁止修改人格"}), 403
        data = request.json or {}
        name = (data.get("name") or "").strip()
        if not name:
            return jsonify({"error": "name不能为空"}), 400
        from core.ai_personas import delete_persona
        ok = delete_persona(name)
        return jsonify({"success": ok})

    @app.route('/api/ai/get')
    def ai_get():
        """GET版本，浏览器地址栏直接调用。参数: topic, preset, prompt, format
        注意：api_key/base_url/model只能通过配置文件或POST接口设置，不通过URL传递（防泄露）"""
        topic = request.args.get("topic", "").strip()
        preset = request.args.get("preset", "novel")
        custom_prompt = request.args.get("prompt")
        if not topic and not custom_prompt:
            return jsonify({"success": False, "error": "缺少topic参数，例如: /api/ai/get?topic=李白&preset=celebrity"}), 400
        from core.ai_generator import generate_content
        result = generate_content(
            topic=topic, preset=preset,
            api_key=config.get("ai_api_key", ""),
            base_url=config.get("ai_base_url", "https://api.openai.com/v1"),
            model=config.get("ai_model", "gpt-3.5-turbo"),
            custom_prompt=custom_prompt,
        )
        # 浏览器直接访问时返回纯文本，方便阅读
        if request.args.get("format") == "text":
            text = result["text"] if result["success"] else f"错误: {result['error']}"
            return Response(text, mimetype="text/plain; charset=utf-8")
        return jsonify(result)

    @app.route('/api/ai/generate', methods=['POST'])
    def ai_generate():
        data = request.json or {}
        topic = data.get("topic", "").strip()
        preset = data.get("preset", "novel")
        custom_prompt = data.get("custom_prompt")
        custom_system = data.get("custom_system")
        if not topic and not custom_prompt:
            return jsonify({"success": False, "error": "请输入主题或自定义提示词"}), 400
        from core.ai_generator import generate_content
        # 忽略请求里的 api_key/base_url：否则服务端会把配置中的 ai_api_key 以
        # Authorization: Bearer 发往请求方指定的任意 URL（SSRF + 凭据外泄）
        result = generate_content(
            topic=topic, preset=preset,
            api_key=config.get("ai_api_key", ""),
            base_url=config.get("ai_base_url", "https://api.openai.com/v1"),
            model=data.get("model") or config.get("ai_model", "gpt-3.5-turbo"),
            custom_prompt=custom_prompt, custom_system=custom_system,
        )
        return jsonify(result)

    @app.route('/api/ai/send', methods=['POST'])
    def ai_send():
        """AI生成内容并发送到指定服务器"""
        # 与 /api/warn/single 相同的门禁：AI进服发消息属于高风险能力，不能绕过只读/能力开关
        if state.is_read_only():
            return jsonify({"success": False, "error": "只读模式下禁止AI进服发送"}), 403
        if not state.capability_enabled("login_interact"):
            return jsonify({"success": False, "error": "进服交互能力未启用，请在config中设置 capabilities.login_interact=true"}), 403
        data = request.json or {}
        ip = data.get("ip")
        try:
            port = int(data.get("port") or 25565)
        except (TypeError, ValueError):
            return jsonify({"success": False, "error": "端口格式无效"}), 400
        username = data.get("username", "StoryBot")
        authme_password = data.get("authme_password")
        if not ip:
            return jsonify({"success": False, "error": "请指定服务器地址"}), 400
        # 先生成
        from core.ai_generator import generate_content
        # 同上：api_key/base_url 只取服务端配置
        gen = generate_content(
            topic=data.get("topic", ""), preset=data.get("preset", "novel"),
            api_key=config.get("ai_api_key", ""),
            base_url=config.get("ai_base_url", "https://api.openai.com/v1"),
            model=data.get("model") or config.get("ai_model", "gpt-3.5-turbo"),
            custom_prompt=data.get("custom_prompt"),
        )
        if not gen["success"]:
            return jsonify({"success": False, "error": gen["error"]})
        # 再发送
        from core.bot import join_and_warn
        messages = gen["segments"]
        _log(f"AI生成并发送: {len(messages)}段 -> {ip}:{port}")
        r = join_and_warn(ip, port, username, messages, timeout=15.0,
                          message_delay=float(data.get("message_delay", 1.0)),
                          authme_password=authme_password,
                          use_premium=bool(data.get("use_premium", False)),
                          premium_uuid=data.get("premium_uuid") or None)
        return jsonify({
            "success": r.success, "messages_sent": r.messages_sent,
            "total_segments": len(messages), "text": gen["text"],
            "segments": gen["segments"], "error": r.error,
        })

