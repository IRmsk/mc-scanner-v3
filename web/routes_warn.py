# -*- coding: utf-8 -*-
"""Routes: warn —— 进服发送警告（/api/warn/*、/api/db/warn）

前端三套 UI（单机 / 批量 / 多目标×多机器人）早就写好了，后端此前一条对应路由
都没有，点下去全是 404。这里按 /api/ai/send 的同一套门禁补齐，并对入参设上限：
进服发消息是不可撤销的对外动作，不能靠前端自觉。

门禁（与 /api/ai/send、/api/ai_bot/start 一致）：
  - 只读模式 → 403
  - capabilities.login_interact 未启用 → 403

上限：
  - 单次最多 200 台服务器、每条服务器最多 20 个机器人
  - 每条警告最多 50 段、每段截到 256 字符（Minecraft 聊天包上限）
"""
import concurrent.futures
import threading

from flask import jsonify, request

import logger
from web import state

_MAX_TARGETS = 200
_MAX_BOTS_PER_SERVER = 20
_MAX_TOTAL_JOBS = 500
_MAX_MESSAGES = 50
_MAX_MSG_LEN = 256
_MAX_WORKERS = 64
# 同时在跑的批次数：每个批次都会占住一个请求线程若干秒，
# 不限制的话几个并发请求就能把 Flask 的线程池吃光
_MAX_CONCURRENT_BATCHES = 2
_DEFAULT_MESSAGES = ["请遵守服务器规则，违规行为已被记录。"]


def _deny():
    """门禁：返回 (response, status) 表示拒绝，None 表示放行。"""
    if state.is_read_only():
        return jsonify({"success": False, "error": "只读模式下禁止进服发送警告"}), 403
    if not state.capability_enabled("login_interact"):
        return jsonify({
            "success": False,
            "error": "进服交互能力未启用，请在config中设置 capabilities.login_interact=true",
        }), 403
    return None


def _norm_messages(raw):
    """规整消息列表。返回 (messages, error)。"""
    if isinstance(raw, str):
        raw = raw.split("\n")
    if raw is None:
        return list(_DEFAULT_MESSAGES), None
    if not isinstance(raw, list):
        return None, "messages 必须是字符串数组"
    msgs = []
    for item in raw:
        text = str(item).strip()
        if not text:
            continue
        if len(text) > _MAX_MSG_LEN:
            text = text[:_MAX_MSG_LEN]
        msgs.append(text)
        if len(msgs) >= _MAX_MESSAGES:
            break
    if not msgs:
        return None, "请至少提供一条警告消息"
    return msgs, None


def _norm_targets(raw):
    """规整目标列表。返回 (targets, error)。

    去重按 (ip, port)，端口非法或缺失的整条拒绝——进服动作宁可少发也不能发错。
    """
    if not isinstance(raw, list) or not raw:
        return None, "请至少选择一台服务器"
    if len(raw) > _MAX_TARGETS:
        return None, f"一次最多警告 {_MAX_TARGETS} 台服务器（当前 {len(raw)} 台）"
    seen, targets = set(), []
    for item in raw:
        if not isinstance(item, dict):
            return None, "targets 的元素必须是 {ip, port} 对象"
        ip = str(item.get("ip") or "").strip()
        if not ip or len(ip) > 255:
            return None, "存在无效的服务器地址"
        try:
            port = int(item.get("port") or 25565)
        except (TypeError, ValueError):
            return None, f"{ip} 的端口格式无效"
        if not (1 <= port <= 65535):
            return None, f"{ip} 的端口超出范围"
        key = (ip, port)
        if key in seen:
            continue
        seen.add(key)
        targets.append({"ip": ip, "port": port})
    if not targets:
        return None, "请至少选择一台服务器"
    return targets, None


def _norm_delay(value, default=0.6):
    """前端 message_delay 单位是秒（输入框 parseFloat，默认 0.5）。"""
    try:
        d = float(value)
    except (TypeError, ValueError):
        return default
    return max(0.0, min(10.0, d))


def _norm_int(value, default, lo, hi):
    try:
        n = int(value)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, n))


def _warn_one(target, username, messages, **kwargs):
    """对单台服务器执行一次完整进服警告，任何异常都收敛成结果对象。"""
    from core.bot import join_and_warn

    ip, port = target["ip"], target["port"]
    try:
        r = join_and_warn(ip, port, username, messages, **kwargs)
        return {
            "ip": ip, "port": port, "name": username,
            "success": bool(r.success), "messages_sent": int(r.messages_sent or 0),
            "auth_mode": getattr(r, "auth_mode", None) or "unknown",
            "error": (r.error or "")[:200],
        }
    except Exception as e:
        logger.exception("[api] _warn_one 未处理异常")
        return {
            "ip": ip, "port": port, "name": username, "success": False,
            "messages_sent": 0, "auth_mode": "unknown", "error": str(e)[:200],
        }


def _run_batch(jobs, workers, messages, delay, timeout):
    """并发执行一批进服任务。jobs: [(target, username, extra_kwargs), ...]"""
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {
            ex.submit(_warn_one, target, username, messages,
                      message_delay=delay, timeout=timeout, **extra): target
            for target, username, extra in jobs
        }
        for fut in concurrent.futures.as_completed(futures):
            try:
                results.append(fut.result())
            except Exception as e:      # _warn_one 已兜底，这里是双保险
                logger.exception("[api] warn 批处理未处理异常")
                t = futures[fut]
                results.append({"ip": t["ip"], "port": t["port"], "name": "?",
                                "success": False, "messages_sent": 0,
                                "auth_mode": "unknown", "error": str(e)[:200]})
    return results


# 批次闸门：拿不到就直说忙，而不是把请求线程堆满
_batch_sem = threading.BoundedSemaphore(_MAX_CONCURRENT_BATCHES)


def register(app):
    def _log(msg):
        state.log_scan(msg)

    @app.route('/api/warn/single', methods=['POST'])
    def warn_single():
        deny = _deny()
        if deny:
            return deny
        data = request.json or {}
        targets, err = _norm_targets([{"ip": data.get("ip"), "port": data.get("port")}])
        if err:
            return jsonify({"success": False, "error": err}), 400
        messages, err = _norm_messages(data.get("messages"))
        if err:
            return jsonify({"success": False, "error": err}), 400

        username = str(data.get("username") or "SecurityBot")[:16]
        delay = _norm_delay(data.get("message_delay"))
        _log(f"进服警告: {targets[0]['ip']}:{targets[0]['port']} / {len(messages)} 段消息")

        r = _warn_one(
            targets[0], username, messages,
            message_delay=delay, timeout=15.0,
            authme_password=data.get("authme_password") or None,
            use_premium=bool(data.get("use_premium", False)),
            premium_uuid=data.get("premium_uuid") or None,
        )
        return jsonify({
            "success": r["success"],
            "auth_mode": r["auth_mode"],
            "messages_sent": r["messages_sent"],
            "error": r["error"],
        })

    def _warn_many(source_label):
        deny = _deny()
        if deny:
            return deny
        data = request.json or {}
        targets, err = _norm_targets(data.get("targets"))
        if err:
            return jsonify({"success": False, "error": err}), 400
        messages, err = _norm_messages(data.get("messages"))
        if err:
            return jsonify({"success": False, "error": err}), 400

        username = str(data.get("username") or "SecurityBot")[:16]
        workers = _norm_int(data.get("workers"), 8, 1, _MAX_WORKERS)
        delay = _norm_delay(data.get("message_delay"))
        extra = {
            "authme_password": data.get("authme_password") or None,
            "use_premium": bool(data.get("use_premium", False)),
            "premium_uuid": data.get("premium_uuid") or None,
        }
        jobs = [(t, username, dict(extra)) for t in targets]

        if not _batch_sem.acquire(blocking=False):
            return jsonify({"success": False, "error": "已有警告任务在跑，请稍后再试"}), 429
        try:
            _log(f"{source_label}: {len(targets)} 台服务器 / {len(messages)} 段消息 / {workers} 并发")
            results = _run_batch(jobs, workers, messages, delay, 15.0)
        finally:
            _batch_sem.release()

        ok = sum(1 for r in results if r["success"])
        sent = sum(r["messages_sent"] for r in results)
        _log(f"{source_label}完成: {ok}/{len(results)} 台成功，共 {sent} 条消息")
        return jsonify({
            "success": ok, "total": len(results), "messages_sent": sent, "results": results,
        })

    @app.route('/api/warn/batch', methods=['POST'])
    def warn_batch():
        """结果页/收藏页勾选后批量警告。"""
        return _warn_many("批量警告")

    @app.route('/api/db/warn', methods=['POST'])
    def db_warn():
        """数据库页勾选后批量警告：targets 与 batch 同构，只是来源不同。"""
        return _warn_many("数据库批量警告")

    @app.route('/api/warn/multi', methods=['POST'])
    def warn_multi():
        """多服务器 × 每台多机器人。前端按服务器分组展示每个机器人的结果。"""
        deny = _deny()
        if deny:
            return deny
        data = request.json or {}
        targets, err = _norm_targets(data.get("targets"))
        if err:
            return jsonify({"success": False, "error": err}), 400
        messages, err = _norm_messages(data.get("messages"))
        if err:
            return jsonify({"success": False, "error": err}), 400

        bots = _norm_int(data.get("bot_count"), 1, 1, _MAX_BOTS_PER_SERVER)
        if len(targets) * bots > _MAX_TOTAL_JOBS:
            return jsonify({
                "success": False,
                "error": f"任务总数超过上限 {_MAX_TOTAL_JOBS}（{len(targets)} 台 × {bots} 机器人）",
            }), 400
        workers = _norm_int(data.get("workers"), 8, 1, _MAX_WORKERS)
        delay = _norm_delay(data.get("message_delay"))
        prefix = str(data.get("name_prefix") or "Bot")[:10]
        extra = {
            "authme_password": data.get("authme_password") or None,
            "use_premium": bool(data.get("use_premium", False)),
            "premium_uuid": data.get("premium_uuid") or None,
        }
        # 每台服务器起 bots 个机器人，名字加序号方便在服务端玩家列表里区分
        jobs = [
            (t, f"{prefix}{i}"[:16], dict(extra))
            for t in targets for i in range(1, bots + 1)
        ]

        if not _batch_sem.acquire(blocking=False):
            return jsonify({"success": False, "error": "已有警告任务在跑，请稍后再试"}), 429
        try:
            _log(f"多机器人警告: {len(targets)} 台 × {bots} 机器人")
            results = _run_batch(jobs, workers, messages, delay, 15.0)
        finally:
            _batch_sem.release()

        ok = sum(1 for r in results if r["success"])
        sent = sum(r["messages_sent"] for r in results)
        _log(f"多机器人警告完成: {ok}/{len(results)} 个机器人成功，共 {sent} 条消息")
        return jsonify({
            "servers": len(targets), "bot_per_server": bots,
            "success": ok, "total": len(results), "messages_sent": sent,
            "results": results,
        })
