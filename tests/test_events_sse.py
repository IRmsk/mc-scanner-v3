# -*- coding: utf-8 -*-
"""SSE 状态推送（/api/events）。

面板原来是两条 1Hz 轮询，现在改成一条长连接 + 服务端 diff。
这组测试守住：鉴权、事件格式、以及「内容没变就不发」这个核心承诺。
"""
import json

import pytest

from web import app as web_app
from web import auth as auth_mod
from web import routes_events, state


@pytest.fixture()
def client():
    web_app.app.config.update(TESTING=True)
    with web_app.app.test_client() as c:
        yield c


@pytest.fixture()
def token(monkeypatch):
    monkeypatch.setattr(auth_mod, "must_change_pending", lambda: False)
    monkeypatch.setattr(auth_mod, "fixed_token", lambda: "")
    t = auth_mod.create_session("admin")
    yield t
    auth_mod.destroy_session(t)


def _open(client, token):
    return client.get(f"/api/events?token={token}", buffered=False)


def _parse(chunk):
    """把 'event: x\\ndata: {...}\\n\\n' 解析成 (名字, 负载)。"""
    text = chunk.decode() if isinstance(chunk, bytes) else chunk
    lines = [ln for ln in text.strip().split("\n") if ln.strip()]
    name, data = None, None
    for ln in lines:
        if ln.startswith("event: "):
            name = ln[7:]
        elif ln.startswith("data: "):
            data = json.loads(ln[6:])
    return name, data


def test_requires_auth(client):
    """EventSource 不能设请求头，但也不能免鉴权。"""
    assert client.get("/api/events").status_code == 401


def test_content_type_and_no_buffering_headers(client, token):
    r = _open(client, token)
    try:
        assert r.status_code == 200
        assert r.headers["Content-Type"].startswith("text/event-stream")
        assert r.headers["Cache-Control"] == "no-store"
        # nginx 不加这个头会把 SSE 攒起来不发
        assert r.headers["X-Accel-Buffering"] == "no"
    finally:
        r.close()


def test_first_two_frames_are_scan_and_tasks(client, token):
    r = _open(client, token)
    try:
        it = iter(r.response)
        name1, payload1 = _parse(next(it))
        name2, payload2 = _parse(next(it))
    finally:
        r.close()
    assert name1 == "scan"
    assert name2 == "tasks"
    # 与 /api/scan/status、/api/scan/tasks 同构，前端才能复用渲染函数
    for key in ("running", "progress", "total", "scanned", "open_count",
                "results_count", "logs", "elapsed", "error"):
        assert key in payload1
    assert "tasks" in payload2


def test_push_only_on_change(client, token):
    """进度不变就不发——这是把轮询换成推送的全部意义。"""
    r = _open(client, token)
    try:
        it = iter(r.response)
        _parse(next(it))            # scan 首帧
        _parse(next(it))            # tasks 首帧
        with state.scan_lock:
            state.scan_state["progress"] = 42
        name, payload = _parse(next(it))
        assert name == "scan"
        assert payload["progress"] == 42
    finally:
        with state.scan_lock:
            state.scan_state["progress"] = 0
        r.close()


def test_keepalive_when_idle(client, token, monkeypatch):
    """长时间没数据变化时要发心跳，否则中间层会掐断连接。"""
    monkeypatch.setattr(routes_events, "_KEEPALIVE_EVERY", 1)
    r = _open(client, token)
    try:
        it = iter(r.response)
        _parse(next(it))            # scan
        _parse(next(it))            # tasks
        chunk = next(it).decode()
        assert chunk.startswith(":") and "keep-alive" in chunk
    finally:
        r.close()


def test_broken_payload_does_not_kill_stream(client, token, monkeypatch):
    """单个负载构建抛异常时，流要继续活着（只丢这一帧）。"""
    calls = {"n": 0}
    real = routes_events._tasks_payload

    def boom():
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("boom")
        return real()

    monkeypatch.setattr(routes_events, "_tasks_payload", boom)
    monkeypatch.setattr(routes_events, "_KEEPALIVE_EVERY", 1)
    r = _open(client, token)
    try:
        it = iter(r.response)
        name, _ = _parse(next(it))
        assert name == "scan"
        # 第二次 tasks 构建抛错，但流仍在：后续还能拿到心跳
        chunk = None
        for _ in range(3):
            chunk = next(it).decode()
            if chunk.startswith(":"):
                break
        assert chunk is not None and chunk.startswith(":")
    finally:
        r.close()


def test_frontend_prefers_sse_and_keeps_polling_as_fallback():
    """前端必须优先走 SSE，轮询只作为兜底保留一处。

    同时守住那个容易被改回去的细节：扫描「刚结束」的副作用（跳结果页）
    只能由 running 的下降沿触发一次，不能每帧都跳。
    """
    import pathlib

    root = pathlib.Path(__file__).resolve().parent.parent
    html = (root / "web" / "index.html").read_text(encoding="utf-8")

    assert "/api/events" in html
    assert "new EventSource(" in html, "前端没有建立 SSE 连接"
    assert html.count("setInterval(pollStatus") == 1, "轮询只应保留 startPolling 里这一处兜底"
    # 下降沿守卫
    assert "_wasRunning" in html, "缺少 running 下降沿标记，扫描结束会重复触发跳转"
    assert "if (_wasRunning && !data.running)" in html
