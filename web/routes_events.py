# -*- coding: utf-8 -*-
"""Routes: events —— SSE 状态推送

面板原来靠两条 1Hz 轮询（/api/scan/status + /api/scan/tasks）刷新，
api_rate_limit 每分钟 600 次有一大半被它们吃掉，而且每次都要重建
JSON、走一遍鉴权、过一次 Flask 完整请求栈。

改成一条 SSE 长连接，服务端做 diff：内容没变就不发，变了立刻推。

鉴权：EventSource 不能设请求头，所以 token 走 ?token=（_extract_token 已支持
header > query > body 的顺序）。注意 query 里的 token 可能被反代访问日志记下，
部署时如需避免，请把 /api/events 放在 header 鉴权的反代之后或改用内网监听。

锁：state.scan_lock 是非重入锁，而 services_scan.list_tasks() 内部也会拿它，
所以两个 payload 必须各自独立持锁、串行调用，不能嵌套。
"""
import json
import time

from flask import Response, stream_with_context

import logger
from web import services_scan, state

# 中间层（nginx / 手机热点 / 运营商 NAT）会把长时间静默的连接掐掉，
# 所以即使没有数据变化也要定期发一行注释当心跳。
_KEEPALIVE_EVERY = 15


def _scan_payload():
    """与 /api/scan/status 完全同构，前端可以复用同一套渲染函数。"""
    with state.scan_lock:
        st = state.scan_state
        return {
            "running": st["running"],
            "progress": st["progress"],
            "total": st["total"],
            "scanned": st.get("scanned", 0),
            "open_count": st.get("open_count", 0),
            "results_count": len(st["results"]),
            "logs": st["logs"][-100:],
            "start_time": st["start_time"],
            "task_id": st["task_id"],
            "elapsed": time.time() - st["start_time"] if st["start_time"] else 0,
            "error": st.get("error", ""),
        }


def _tasks_payload():
    """与 /api/scan/tasks 同构。list_tasks 自己会持 state.scan_lock。"""
    return {"tasks": services_scan.list_tasks()}


def register(app):
    @app.route('/api/events')
    def events():
        # 不校验 Accept 头：EventSource 会带 text/event-stream，curl 调试时不带也放行

        def gen():
            last = {}
            idle = 0
            while True:
                for name, build in (("scan", _scan_payload), ("tasks", _tasks_payload)):
                    try:
                        text = json.dumps(build(), ensure_ascii=False, sort_keys=True)
                    except Exception:
                        # 单个负载构建失败不能拖垮整条流
                        logger.exception("[api] SSE 负载构建失败")
                        continue
                    if last.get(name) != text:
                        last[name] = text
                        idle = 0
                        yield f"event: {name}\ndata: {text}\n\n"
                idle += 1
                if idle >= _KEEPALIVE_EVERY:
                    idle = 0
                    yield ": keep-alive\n\n"
                # 客户端断开时下一次 yield 会抛 GeneratorExit，线程随即释放
                time.sleep(1)

        resp = Response(stream_with_context(gen()), mimetype="text/event-stream")
        resp.headers["Cache-Control"] = "no-store"
        # nginx 默认会缓冲 SSE，这两个头是让它别攒
        resp.headers["X-Accel-Buffering"] = "no"
        return resp
