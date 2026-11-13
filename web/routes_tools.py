# -*- coding: utf-8 -*-
"""Routes: tools"""
import os
import sys
import time

from flask import jsonify, request

import config
import logger

# core.bot 是 1200+ 行的协议实现，只有真正进服发命令时才需要。

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


def _to_float(value, default=0.0):
    """请求参数转 float，非法值回退默认值。"""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default

# tools 目录只需加入一次 sys.path：原来每个请求都 insert，sys.path 会无限膨胀
_TOOLS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'tools')


def _ensure_tools_path():
    if _TOOLS_DIR not in sys.path:
        sys.path.insert(0, _TOOLS_DIR)


def register(app):
    def _log(msg):
        state.log_scan(msg)
    def _safe_db_path(path):
        return state.safe_db_path(path)
    def parse_ports_spec(ports_spec):
        return state.parse_ports_spec(ports_spec)
    def _check_capability(cap):
        """能力分级检查：默认关闭高风险能力（统一走state，单一真相源）"""
        return state.capability_enabled(cap)

    @app.route('/api/bot/command', methods=['POST'])
    def bot_command():
        if not _check_capability("login_interact"):
            return jsonify({"error": "Bot命令执行能力未启用，请在config中设置 capabilities.login_interact=true"}), 403
        data = request.json or {}
        ip = data.get("ip")
        port = int(data.get("port") or 25565)
        username = data.get("username", "SecurityBot")
        command = data.get("command", "")
        authme_password = data.get("authme_password")
        hold = float(data.get("hold", 6.0))
        if not ip or not command:
            return jsonify({"error": "IP 和命令不能为空"}), 400
        try:
            from core.bot import MCBot

            bot = MCBot(host=ip, port=port, username=username)
            bot.connect()
            if authme_password:
                bot.authme_login(authme_password, mode="auto")
                time.sleep(1.0)
            # 用单调序号做增量基准：chat_messages 超过 MAX_CHAT_MESSAGES 会从头部截断，
            # len() 基准的切片会错位/丢消息（core/bot.py 已提供 chat_seq/chat_since）
            before_seq = bot.chat_seq()
            bot.send_command(command)
            time.sleep(1.5)  # 等服务器处理命令
            bot.keep_alive(hold)
            auth_mode = getattr(bot, 'auth_mode', 'unknown')
            # 原来写 state = getattr(bot, 'state', ...)，遮蔽了模块级 state，
            # 函数内任何对 state 的引用都会变成 UnboundLocalError
            bot_state = getattr(bot, 'state', 'unknown')
            # 收集命令发送后收到的新聊天消息作为响应
            chat_responses, _ = bot.chat_since(before_seq)
            bot.close()
            cmd = command if command.startswith('/') else '/' + command
            return jsonify({"success": True, "command": cmd, "auth_mode": auth_mode,
                            "state": bot_state, "hold": hold, "chat": chat_responses[-10:]})
        except Exception as e:
            logger.exception("[api] bot_command 未处理异常")
            return jsonify({"success": False, "error": str(e)})

    @app.route('/api/tools/gen_packets', methods=['POST'])
    def gen_packets():
        try:
            _ensure_tools_path()
            import gen_packets as gp
            if hasattr(gp, 'main'):
                gp.main()
            return jsonify({"success": True, "message": "协议表生成完成"})
        except Exception as e:
            logger.exception("[api] gen_packets 未处理异常")
            return jsonify({"success": False, "error": str(e)}), 500

    @app.route('/api/proxy')
    def proxy_list():
        from core.proxy import ProxyManager
        manager = ProxyManager(proxy_file="proxies.txt", auto_fetch=False)
        proxies = [{"proto": p.proto, "host": p.host, "port": p.port,
                    "fail_count": p.fail_count, "last_used": p.last_used}
                   for p in getattr(manager, 'proxies', [])]
        return jsonify({"total": len(proxies), "proxies": proxies})

    @app.route('/api/proxy/fetch', methods=['POST'])
    def proxy_fetch():
        data = request.json or {}
        from core.proxy import ProxyManager
        manager = ProxyManager(proxy_file="proxies.txt", auto_fetch=False)
        count = manager.fetch_from_api(fetch_socks5=data.get("socks5", False))
        _log(f"代理获取: {count} 个")
        return jsonify({"success": True, "count": count})

    @app.route('/api/proxy/check', methods=['POST'])
    def proxy_check():
        data = request.json or {}
        test_host = data.get("test_host") or config.get("proxy_test_host", "")
        if not test_host:
            return jsonify({"success": False, "error": "未配置代理健康检查目标。请在 config.json 设置 proxy_test_host 为你自有服务器地址，或在请求中传 test_host。"}), 400
        from core.proxy import ProxyManager
        manager = ProxyManager(proxy_file="proxies.txt", auto_fetch=False)
        alive = manager.health_check(
            test_host=test_host,
            test_port=_to_int(data.get("test_port"), config.get("proxy_test_port", 25565)),
            timeout=_to_float(data.get("timeout"), 5.0))
        _log(f"代理健康检查: {alive}/{len(manager)} 可用")
        return jsonify({"success": True, "alive": alive, "total": len(manager)})

    @app.route('/api/rcon/execute', methods=['POST'])
    def rcon_execute_api():
        if not _check_capability("rcon_commands"):
            return jsonify({"error": "RCON能力未启用，请在config中设置 capabilities.rcon_commands=true"}), 403
        data = request.json or {}
        host = data.get("host")
        port = int(data.get("port", 25575))
        password = data.get("password", "")
        command = data.get("command", "")
        if not host or not command:
            return jsonify({"error": "host 和 command 不能为空"}), 400
        try:
            from core.rcon import rcon_execute
            result = rcon_execute(host, port, password, command, timeout=data.get("timeout", 10.0))
            return jsonify({"success": True, "command": command, "response": result})
        except Exception as e:
            logger.exception("[api] rcon_execute_api 未处理异常")
            return jsonify({"success": False, "error": str(e)[:200]})

    @app.route('/api/plugins/capture', methods=['POST'])
    def plugins_capture():
        if not _check_capability("login_interact"):
            return jsonify({"error": "插件扫描能力未启用，请在config中设置 capabilities.login_interact=true"}), 403
        data = request.json or {}
        host = data.get("host")
        port = int(data.get("port") or 25565)
        username = data.get("username", "PluginScanner")
        if not host:
            return jsonify({"error": "host 不能为空"}), 400
        try:
            from core.bot import MCBot
            from core.plugins import capture_plugins
            bot = MCBot(host=host, port=port, username=username)
            bot.connect()
            intel = capture_plugins(bot, wait_time=data.get("wait_time", 2.0))
            bot.close()
            return jsonify({
                "success": True,
                "server_software": intel.server_software,
                "version": intel.server_version,
                "plugins": [{"name": p.name, "version": p.version} for p in intel.plugins],
                "anti_cheat": intel.anti_cheat,
                "raw_text": str(intel.raw_responses)[:500],
            })
        except Exception as e:
            logger.exception("[api] plugins_capture 未处理异常")
            return jsonify({"success": False, "error": str(e)[:200]})

    @app.route('/api/commands/run', methods=['POST'])
    def commands_run():
        if not _check_capability("rcon_commands"):
            return jsonify({"error": "命令执行能力未启用，请在config中设置 capabilities.rcon_commands=true"}), 403
        data = request.json or {}
        host = data.get("host")
        port = int(data.get("port") or 25565)
        username = data.get("username", "CommandBot")
        commands = data.get("commands", [])
        if not host or not commands:
            return jsonify({"error": "host 和 commands 不能为空"}), 400
        try:
            from core.bot import MCBot
            from core.command_runner import CommandRunner, CommandScript
            script = CommandScript(delay=data.get("delay", 1.0))
            for cmd in commands:
                script.add(cmd)
            bot = MCBot(host=host, port=port, username=username)
            bot.connect()
            if data.get("authme_password"):
                bot.authme_login(data["authme_password"])
            runner = CommandRunner(bot, delay=data.get("delay", 1.0), timeout=data.get("timeout", 10.0))
            results = runner.run_script(script)
            bot.close()
            return jsonify({
                "success": True,
                "results": [{"command": r.command, "success": r.success,
                             "response": r.response[:300]} for r in results],
                "summary": runner.get_summary(),
            })
        except Exception as e:
            logger.exception("[api] commands_run 未处理异常")
            return jsonify({"success": False, "error": str(e)[:200]})
