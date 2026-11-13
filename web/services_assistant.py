# -*- coding: utf-8 -*-
"""AI assistant helpers."""
import os
import sqlite3
import threading
import time

import config

try:
    from web import state
    from web.observer_session import ObserverSession
except ImportError:
    import state  # type: ignore
    from observer_session import ObserverSession  # type: ignore
try:
    from web import services_scan
except ImportError:
    import services_scan  # type: ignore

_ai_bots = state._ai_bots
scan_state = state.scan_state
health_monitor = state.health_monitor
observer_lock = state.observer_lock
observer_sessions = state.observer_sessions


def _db_path():
    """Web 全局数据库路径（原实现硬编码 'mcscanner.db'，从别的目录启动会读到另一个库）。"""
    return config.get("db_path", "mcscanner.db")


def _deny_reason(tool):
    """工具级门禁：自然语言入口必须与对应 HTTP 接口用同一套只读/能力开关，
    否则一句"扫1.2.3.4"或"托管1.2.3.4:25565"就绕过了 /api/scan/start、/api/ai_bot/start 的全部校验。"""
    if tool == "scan":
        if state.is_read_only():
            return "错误：只读模式下禁止扫描"
        if not state.capability_enabled("scan"):
            return "错误：扫描能力未启用（config.capabilities.scan=false）"
    elif tool in ("ai_host", "multi_ai", "observer"):
        if state.is_read_only():
            return "错误：只读模式下禁止进服交互"
        if not state.capability_enabled("login_interact"):
            return "错误：进服交互能力未启用，请在config中设置 capabilities.login_interact=true"
    return None


def _scan_snapshot():
    """读取全局扫描视图快照。字段名与 /api/scan/status 对齐：
    原实现读的 "done"/"found" 从未被任何写入点写过，所以进度永远是 0。"""
    with state.scan_lock:
        return {
            "running": bool(scan_state.get("running")),
            "total": scan_state.get("total", 0) or 0,
            "scanned": scan_state.get("scanned", 0) or 0,
            "open_count": scan_state.get("open_count", 0) or 0,
            "task_id": scan_state.get("task_id"),
        }

def _handle_assistant_command(msg):
    """AI助手：优先用API做意图识别+工具调用+结果总结，没key时fallback关键词匹配"""
    api_key = config.get("ai_api_key", "")
    base_url = config.get("ai_base_url", "https://api.openai.com/v1")
    model = config.get("ai_model", "gpt-3.5-turbo")

    if not api_key:
        return _assistant_keyword_match(msg)

    # 第一轮：AI理解意图，返回JSON工具调用
    system_prompt = """你是一个Minecraft服务器扫描器的AI助手。用户会用自然语言下达指令，你需要理解意图并选择合适的工具执行。

【重要】只返回一个JSON对象，不要返回数组，不要返回markdown，不要解释，不要说多余的话。格式：{"tool":"工具名","args":{参数}}

可用工具：
1. {"tool":"scan","args":{"target":"1.2.3.4或1.2.3.4/24","ports":[25565,25566]}} - 启动扫描，ports可选默认[25565]
2. {"tool":"stop_scan","args":{}} - 停止当前扫描
3. {"tool":"scan_status","args":{}} - 查看扫描进度
4. {"tool":"scan_results","args":{}} - 查看扫描结果
5. {"tool":"live_servers","args":{}} - 查询数据库里有人在线的服务器
6. {"tool":"db_stats","args":{}} - 数据库统计
7. {"tool":"health_status","args":{}} - 健康监控状态
8. {"tool":"favorites","args":{}} - 收藏列表
9. {"tool":"ai_host","args":{"host":"1.2.3.4","port":25565}} - 单个AI托管进服聊天
10. {"tool":"multi_ai","args":{"host":"1.2.3.4","port":25565,"bot_count":3,"topic":"吵架"}} - 多个AI进服互相对骂/讨论，bot_count 2-8个
11. {"tool":"observer","args":{"host":"1.2.3.4","port":25565,"username":"Observer"}} - 启动观察者进服监控聊天
12. {"tool":"reply","args":{"text":"你的回复内容"}} - 不需要工具，直接回复用户

只返回JSON，不要其他内容。"""

    from core.ai_generator import generate_content
    result = generate_content(
        topic=msg, preset="custom",
        api_key=api_key, base_url=base_url, model=model,
        custom_prompt=f"用户指令：{msg}\n请返回JSON工具调用：",
        custom_system=system_prompt,
    )
    if not result.get("success"):
        # API失败，fallback关键词
        return _assistant_keyword_match(msg) + f"\n(API调用失败: {result.get('error','')})"

    # 解析AI返回的JSON
    tool_call = _parse_tool_call(result.get("text", ""))
    if not tool_call or not isinstance(tool_call, dict):
        # 解析失败，直接返回AI原文
        return result.get("text", "没听懂")

    tool = tool_call.get("tool", "reply")
    args = tool_call.get("args", {})

    # 执行工具
    tool_result = _execute_tool(tool, args)

    # 第二轮：AI用自然语言总结结果
    summary_prompt = f"""工具执行结果：
{tool_result}

请用简洁自然的中文把结果告诉用户，不要提JSON或工具名，直接说人话。如果是列表就分行列出来。"""
    summary = generate_content(
        topic=tool_result[:500], preset="custom",
        api_key=api_key, base_url=base_url, model=model,
        custom_prompt=summary_prompt,
        custom_system="你是一个简洁的助手，用中文回复，直接说结果，不要客套。",
    )
    if summary.get("success"):
        return summary.get("text", tool_result)
    return tool_result


def _parse_tool_call(text):
    """从AI返回的文本中解析JSON工具调用"""
    import json
    import re
    # 尝试直接解析
    try:
        obj = json.loads(text.strip())
        if isinstance(obj, list) and obj:
            return obj[0]
        if isinstance(obj, dict):
            return obj
    except Exception:
        pass
    # 提取JSON块
    m = re.search(r'\{.*\}', text, re.DOTALL)
    if m:
        try:
            obj = json.loads(m.group())
            if isinstance(obj, list) and obj:
                return obj[0]
            return obj
        except Exception:
            pass
    # 提取JSON数组
    m = re.search(r'\[.*\]', text, re.DOTALL)
    if m:
        try:
            arr = json.loads(m.group())
            if isinstance(arr, list) and arr:
                return arr[0]
        except Exception:
            pass
    return None


def _execute_tool(tool, args):
    """执行工具，返回结果字符串"""
    deny = _deny_reason(tool)
    if deny:
        return deny
    scan_state = state.scan_state
    health_monitor = state.health_monitor
    api_key = config.get("ai_api_key", "")
    base_url = config.get("ai_base_url", "https://api.openai.com/v1")
    model = config.get("ai_model", "gpt-3.5-turbo")

    if tool == "scan":
        target = args.get("target", "")
        ports = args.get("ports", [25565])
        if not target:
            return "错误：没有指定扫描目标"
        try:
            # 统一走 services_scan 任务队列：原实现自建线程、访问不存在的
            # scan_state["stop_event"]/["thread"]，并调用不存在的 ScanEngine(...).run()，
            # 结果恒为"启动扫描失败: 'stop_event'"，整条自然语言扫描链路从未跑起来。
            from scanner.targets import parse_targets
            port_list = state.parse_ports_spec(ports)
            if not port_list:
                return "错误：端口格式无效"
            parsed = list(parse_targets([str(target)], port_list))
            if not parsed:
                return "错误：没有解析出有效目标"
            scan_cfg = {
                "workers": 32, "timeout": 4.0,
                "scan_threads": 200, "scan_timeout": 2.5,
                "rate": 0, "auth_check": True,
                "db_path": _db_path(),
                "use_masscan": "auto", "portscan_only": False, "masscan_rate": 5000,
                "ports": port_list, "continuous": False,
                "async_mode": True, "scan_mode": "balanced",
            }
            task_id = services_scan.start_scan_task(parsed, scan_cfg, scan_type="assistant")
            return f'扫描已启动（任务#{task_id}）：目标={target}，端口={port_list}。说"进度"查看扫描状态。'
        except Exception as e:
            return f"启动扫描失败: {e}"

    elif tool == "stop_scan":
        try:
            # 原实现读 scan_state["thread"]（从未定义）→ 恒返回"停止失败: 'thread'"
            running = [t for t in services_scan.list_tasks() if t.get("running")]
            if not running:
                return "当前没有在运行的扫描"
            for t in running:
                services_scan.stop_task(t["task_id"])
            state.scan_stop_event.set()  # 兼容旧引擎
            return f"扫描已停止（任务#{running[0]['task_id']}）"
        except Exception as e:
            return f"停止失败: {e}"

    elif tool == "scan_status":
        try:
            snap = _scan_snapshot()
            total, done, found = snap["total"], snap["scanned"], snap["open_count"]
            pct = (done / total * 100) if total else 0
            if snap["running"]:
                return f"扫描中（任务#{snap['task_id']}）：{done}/{total} ({pct:.1f}%)，已发现 {found} 个MC服务器"
            elif done > 0:
                return f"扫描完成：共扫 {total} 个目标，发现 {found} 个MC服务器"
            else:
                return "当前没有在运行的扫描"
        except Exception as e:
            return f"查询失败: {e}"

    elif tool == "scan_results":
        try:
            results = scan_state.get("results", [])
            if not results:
                return "还没有扫描结果，先启动扫描"
            lines = [f"共发现 {len(results)} 个MC服务器："]
            for r in results[:20]:
                players = r.get('players_online', 0)
                ver = (r.get('version') or '未知')[:20]
                lines.append(f"- {r['ip']}:{r['port']} | {players}人在线 | {ver}")
            if len(results) > 20:
                lines.append(f"...还有 {len(results)-20} 个，去结果页查看完整列表")
            return "\n".join(lines)
        except Exception as e:
            return f"查询失败: {e}"

    elif tool == "live_servers":
        try:
            conn = sqlite3.connect(_db_path())
            rows = conn.execute(
                "SELECT ip, port, players_online, version FROM servers WHERE players_online > 0 ORDER BY players_online DESC LIMIT 20"
            ).fetchall()
            conn.close()
            if not rows:
                return "数据库里没有当前有人在线的服务器"
            lines = [f"找到 {len(rows)} 个有人的服务器："]
            for ip, port, players, ver in rows:
                lines.append(f"- {ip}:{port} | {players}人在线 | {ver or '未知版本'}")
            return "\n".join(lines)
        except Exception as e:
            return f"查询失败: {e}"

    elif tool == "db_stats":
        try:
            conn = sqlite3.connect(_db_path())
            total = conn.execute("SELECT COUNT(*) FROM servers").fetchone()[0]
            online = conn.execute("SELECT COUNT(*) FROM servers WHERE players_online > 0").fetchone()[0]
            cracked = conn.execute("SELECT COUNT(*) FROM servers WHERE auth_mode='offline'").fetchone()[0]
            conn.close()
            return f"数据库统计：共 {total} 个服务器，{online} 个当前有人在线，{cracked} 个离线服（cracked）"
        except Exception as e:
            return f"查询失败: {e}"

    elif tool == "health_status":
        try:
            hm = health_monitor
            running = hm.get("running", False)
            status = hm.get("status", {})
            events = hm.get("events", [])
            lines = [f"健康监控：{'运行中' if running else '未启动'}"]
            lines.append(f"监控 {len(status)} 个服务器，最近检查时间：{hm.get('last_check', '从未')}")
            if events:
                e = events[0]
                lines.append(f"最近事件：{e.get('time','')} {e.get('ip','')}:{e.get('port','')} 人数 {e.get('from','')}→{e.get('to','')}")
            return "\n".join(lines)
        except Exception as e:
            return f"查询失败: {e}"

    elif tool == "favorites":
        try:
            from storage.favorites import filter_favorites
            favs = filter_favorites()
            if not favs:
                return "收藏夹是空的"
            lines = [f"共收藏 {len(favs)} 个服务器："]
            for f in favs[:20]:
                lines.append(f"- {f['ip']}:{f['port']}")
            return "\n".join(lines)
        except Exception as e:
            return f"查询失败: {e}"

    elif tool == "ai_host":
        host = args.get("host", "")
        port = int(args.get("port", 25565))
        if not host:
            return "错误：没有指定服务器地址"
        try:
            from core.ai_bot import AIBotSession
            sid = f"assistant_{state.next_ai_bot_seq()}"
            session = AIBotSession(
                host=host, port=port, username="AssistantBot",
                authme_password=config.get("authme_password", ""), timeout=20, duration=0,
                ai_config={
                    "api_key": api_key, "base_url": base_url, "model": model,
                    "persona": "你是一个MC玩家，喜欢和人聊天，说话简短有趣，不超过30字。",
                    "reply_enabled": True, "reply_cooldown": config.get("ai_reply_cooldown", 2.0),
                    "trigger_keywords": [], "auto_talk_enabled": False,
                }
            )
            session.session_id = sid
            session.start()
            _ai_bots[sid] = session
            return f"AI托管已启动：{host}:{port}，用户名 AssistantBot，自动回复已开启"
        except Exception as e:
            return f"启动AI托管失败: {e}"

    elif tool == "multi_ai":
        host = args.get("host", "")
        port = int(args.get("port", 25565))
        bot_count = int(args.get("bot_count", 3))
        bot_count = max(2, min(8, bot_count))
        topic = args.get("topic", "随机话题吵架")
        if not host:
            return "错误：没有指定服务器地址"
        if not api_key:
            return "错误：未配置API Key，在设置里填写 ai_api_key"
        try:
            from core.ai_bot import multi_ai_bot
            ai_cfg = {"api_key": api_key, "base_url": base_url, "model": model}
            group_id = multi_ai_bot.start_group(
                host=host, port=port, bot_count=bot_count,
                topic=topic, duration=0,
                authme_password=config.get("authme_password", ""),
                ai_config=ai_cfg,
            )
            return f"多AI群聊已启动：{host}:{port}，{bot_count}个AI互喷，话题：{topic}，群ID：{group_id}"
        except Exception as e:
            return f"启动多AI群聊失败: {e}"

    elif tool == "observer":
        host = args.get("host", "")
        port = int(args.get("port", 25565))
        username = args.get("username", "Observer")
        if not host:
            return "错误：没有指定服务器地址"
        try:
            session = ObserverSession(host, port, username, authme_password=config.get("authme_password", ""), timeout=20, duration=0)
            session.session_id = f"{int(time.time()*1000)}-{os.getpid()}-observer"
            session.thread = threading.Thread(target=session.run, daemon=True)
            with observer_lock:
                observer_sessions[session.session_id] = session
            session.thread.start()
            return f"观察者已启动：{username} -> {host}:{port}，会话ID：{session.session_id[-6:]}"
        except Exception as e:
            return f"启动观察者失败: {e}"

    elif tool == "reply":
        return args.get("text", "好的")

    else:
        return f"未知工具: {tool}"


def _assistant_keyword_match(msg):
    """无API key时的关键词匹配fallback"""
    low = msg.lower()
    import re

    if any(k in msg for k in ["帮助", "能干嘛", "会什么", "怎么用", "help"]):
        return """我能帮你干这些：
📡 扫描：说"扫1.2.3.4"或"扫1.2.3.4端口25565,25566"
⏹ 停止：说"停"或"停止扫描"
📊 进度：说"扫得怎么样"或"进度"
📋 结果：说"结果"或"扫到什么了"
👥 有人的服：说"有人的服务器"
🗄 数据库：说"数据库统计"
💚 健康监控：说"监控状态"
⭐ 收藏：说"收藏列表"
🤖 AI托管：说"托管1.2.3.4:25565"
（配置API key后我能更聪明地理解你的话）"""

    if low in ["停", "stop"] or any(k in msg for k in ["停止", "停下", "别扫了", "停一下"]):
        try:
            # scan_state 从来没有 "thread"/"stop_event" 键，原来这段要么 AttributeError 要么永远"没在扫啊"
            running = [t for t in services_scan.list_tasks() if t.get("running")]
            if not running:
                return "没在扫啊"
            for t in running:
                services_scan.stop_task(t["task_id"])
            state.scan_stop_event.set()  # 兼容旧引擎
            return "好，已停止扫描"
        except Exception as e:
            return f"停止失败: {e}"

    if any(k in msg for k in ["进度", "怎么样", "状态", "扫完没"]):
        try:
            snap = _scan_snapshot()
            total, done, found = snap["total"], snap["scanned"], snap["open_count"]
            pct = (done / total * 100) if total else 0
            if snap["running"]:
                return f"扫描中... {done}/{total} ({pct:.1f}%)，已发现 {found} 个MC服"
            elif done > 0:
                return f"扫描完成！共扫 {total} 个目标，发现 {found} 个MC服"
            else:
                return '没在扫描，说"扫IP"开始'
        except Exception as e:
            return f"查询失败: {e}"

    if any(k in msg for k in ["结果", "扫到什么", "有哪些服"]):
        try:
            results = scan_state.get("results", [])
            if not results:
                return "还没结果呢，先去扫"
            lines = [f"共发现 {len(results)} 个MC服："]
            for r in results[:15]:
                players = r.get('players_online', 0)
                ver = r.get('version', '')[:20]
                lines.append(f"  {r['ip']}:{r['port']} | {players}人 | {ver}")
            if len(results) > 15:
                lines.append(f"  ...还有 {len(results)-15} 个")
            return "\n".join(lines)
        except Exception as e:
            return f"查询失败: {e}"

    if any(k in msg for k in ["有人", "活人", "玩家多的"]):
        try:
            conn = sqlite3.connect(_db_path())
            rows = conn.execute("SELECT ip, port, players_online, version FROM servers WHERE players_online > 0 ORDER BY players_online DESC LIMIT 15").fetchall()
            conn.close()
            if not rows:
                return "数据库里没人在线的服务器"
            lines = [f"找到 {len(rows)} 个有人的服："]
            for ip, port, players, ver in rows:
                lines.append(f"  {ip}:{port} | {players}人 | {ver or '未知'}")
            return "\n".join(lines)
        except Exception as e:
            return f"查询失败: {e}"

    if any(k in msg for k in ["数据库", "多少个服", "统计"]):
        try:
            conn = sqlite3.connect(_db_path())
            total = conn.execute("SELECT COUNT(*) FROM servers").fetchone()[0]
            online = conn.execute("SELECT COUNT(*) FROM servers WHERE players_online > 0").fetchone()[0]
            cracked = conn.execute("SELECT COUNT(*) FROM servers WHERE auth_mode='offline'").fetchone()[0]
            conn.close()
            return f"数据库共 {total} 个服务器，{online} 个当前有人，{cracked} 个离线服"
        except Exception as e:
            return f"查询失败: {e}"

    if any(k in msg for k in ["监控", "健康", "推送"]):
        try:
            hm = health_monitor
            return f"健康监控: {'运行中' if hm.get('running') else '未启动'}，监控 {len(hm.get('status',{}))} 个服，最近检查: {hm.get('last_check','从未')}"
        except Exception as e:
            return f"查询失败: {e}"

    if any(k in msg for k in ["收藏", "favorites"]):
        try:
            from storage.favorites import filter_favorites
            favs = filter_favorites()
            if not favs:
                return "收藏夹是空的"
            lines = [f"共收藏 {len(favs)} 个："]
            for f in favs[:15]:
                lines.append(f"  {f['ip']}:{f['port']}")
            return "\n".join(lines)
        except Exception as e:
            return f"查询失败: {e}"

    scan_match = re.search(r'扫[一一下]?\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(?:/[0-9]+)?)\s*(?:端口\s*([0-9, ]+))?', msg)
    if scan_match or ("扫" in msg and re.search(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', msg)):
        try:
            ip_match = re.search(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(?:/[0-9]+)?', msg)
            target = ip_match.group()
            port_match = re.search(r'端口\s*([0-9, ]+)', msg)
            ports = [int(p.strip()) for p in port_match.group(1).split(',') if p.strip()] if port_match else [25565]
            # 统一走 _execute_tool：只读/能力门禁与任务队列都在那里
            result = _execute_tool("scan", {"target": target, "ports": ports})
            if result.startswith("错误") or result.startswith("启动扫描失败"):
                return result
            return f'好，开始扫 {target} 端口 {",".join(map(str,ports))}，说"进度"查看'
        except Exception as e:
            return f"启动失败: {e}"

    if any(k in msg for k in ["托管", "ai进", "bot进"]) and re.search(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', msg):
        deny = _deny_reason("ai_host")
        if deny:
            return deny
        try:
            ip_match = re.search(r'([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}):([0-9]+)', msg)
            if not ip_match:
                return "格式：托管1.2.3.4:25565"
            host, port = ip_match.group(1), int(ip_match.group(2))
            from core.ai_bot import AIBotSession
            sid = f"assistant_{state.next_ai_bot_seq()}"
            session = AIBotSession(host=host, port=port, username="AssistantBot",
                authme_password=config.get("authme_password", ""), timeout=20, duration=0,
                ai_config={"api_key": config.get("ai_api_key",""), "base_url": config.get("ai_base_url","https://api.openai.com/v1"),
                    "model": config.get("ai_model","gpt-3.5-turbo"), "persona": "你是一个MC玩家，喜欢和人聊天，说话简短有趣。",
                    "reply_enabled": True, "reply_cooldown": config.get("ai_reply_cooldown", 2.0), "trigger_keywords": [], "auto_talk_enabled": False})
            session.session_id = sid
            session.start()
            _ai_bots[sid] = session
            return f"好，AI已进 {host}:{port}"
        except Exception as e:
            return f"启动失败: {e}"

    return '没听懂。说"帮助"看看能干嘛，或者在设置里配API key让我更聪明。'


