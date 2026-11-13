# -*- coding: utf-8 -*-
"""进服警告 API（/api/warn/*、/api/db/warn）。

前端三套警告 UI 早就画好了，后端此前一条路由都没有 —— 点下去 404。
这组测试守三件事：门禁拦得住、入参校验不放过脏数据、结果聚合对得上前端契约。
"""
from types import SimpleNamespace

import pytest

from web import app as web_app
from web import auth as auth_mod
from web import state as state_mod


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setattr(auth_mod, "must_change_pending", lambda: False)
    monkeypatch.setattr(auth_mod, "fixed_token", lambda: "")
    web_app.app.config.update(TESTING=True)
    with web_app.app.test_client() as c:
        yield c


@pytest.fixture()
def token():
    t = auth_mod.create_session("admin")
    yield t
    auth_mod.destroy_session(t)


@pytest.fixture()
def allowed(monkeypatch):
    """放行门禁：非只读 + 进服交互已启用。"""
    monkeypatch.setattr(state_mod, "is_read_only", lambda: False)
    monkeypatch.setattr(state_mod, "capability_enabled", lambda cap: True)


@pytest.fixture()
def fake_bot(monkeypatch):
    """把 join_and_warn 换成可控桩，记录每次调用的参数。"""
    calls = []

    def _fake(host, port, username="x", messages=None, **kwargs):
        calls.append({"host": host, "port": port, "username": username,
                      "messages": list(messages or []), **kwargs})
        # 45565 这个端口号约定为「必失败」，其余统统成功
        if port == 45565:
            return SimpleNamespace(success=False, messages_sent=0,
                                   error="connection refused", auth_mode="offline")
        return SimpleNamespace(success=True, messages_sent=len(messages or []),
                               error="", auth_mode="cracked")

    import core.bot as bot_mod
    monkeypatch.setattr(bot_mod, "join_and_warn", _fake)
    return calls


def _post(client, token, path, payload):
    return client.post(path, json=payload, headers={"X-API-Token": token})


# ---------- 门禁 ----------

@pytest.mark.parametrize("path", ["/api/warn/single", "/api/warn/multi",
                                  "/api/warn/batch", "/api/db/warn"])
def test_read_only_blocks_every_warn_endpoint(client, token, monkeypatch, path):
    monkeypatch.setattr(state_mod, "is_read_only", lambda: True)
    monkeypatch.setattr(state_mod, "capability_enabled", lambda cap: True)
    r = _post(client, token, path, {"targets": [{"ip": "1.1.1.1", "port": 25565}]})
    assert r.status_code == 403
    assert "只读" in r.get_json()["error"]


@pytest.mark.parametrize("path", ["/api/warn/single", "/api/warn/multi",
                                  "/api/warn/batch", "/api/db/warn"])
def test_login_interact_capability_required(client, token, monkeypatch, path):
    """默认 capabilities.login_interact=false：进服发消息必须显式开启。"""
    monkeypatch.setattr(state_mod, "is_read_only", lambda: False)
    monkeypatch.setattr(state_mod, "capability_enabled", lambda cap: cap != "login_interact")
    r = _post(client, token, path, {"targets": [{"ip": "1.1.1.1", "port": 25565}]})
    assert r.status_code == 403
    assert "login_interact" in r.get_json()["error"]


# ---------- 入参校验 ----------

def test_single_requires_ip(client, token, allowed, fake_bot):
    r = _post(client, token, "/api/warn/single", {"messages": ["hi"]})
    assert r.status_code == 400
    assert not fake_bot, "参数不合法时不能真的进服"


def test_invalid_port_rejected(client, token, allowed, fake_bot):
    r = _post(client, token, "/api/warn/single", {"ip": "1.1.1.1", "port": "abc"})
    assert r.status_code == 400
    assert not fake_bot


def test_out_of_range_port_rejected(client, token, allowed, fake_bot):
    r = _post(client, token, "/api/warn/batch",
              {"targets": [{"ip": "1.1.1.1", "port": 99999}], "messages": ["hi"]})
    assert r.status_code == 400
    assert not fake_bot


def test_empty_messages_rejected(client, token, allowed, fake_bot):
    r = _post(client, token, "/api/warn/single", {"ip": "1.1.1.1", "messages": ["  ", ""]})
    assert r.status_code == 400
    assert not fake_bot


def test_too_many_targets_rejected(client, token, allowed, fake_bot):
    targets = [{"ip": f"10.0.0.{i}", "port": 25565} for i in range(201)]
    r = _post(client, token, "/api/warn/batch", {"targets": targets, "messages": ["hi"]})
    assert r.status_code == 400
    assert "最多" in r.get_json()["error"]
    assert not fake_bot


def test_duplicate_targets_deduped(client, token, allowed, fake_bot):
    r = _post(client, token, "/api/warn/batch", {
        "targets": [{"ip": "1.1.1.1", "port": 25565},
                    {"ip": "1.1.1.1", "port": 25565}],
        "messages": ["hi"], "workers": 1,
    })
    assert r.status_code == 200
    assert len(fake_bot) == 1, "重复目标只应进服一次"


def test_long_message_truncated(client, token, allowed, fake_bot):
    _post(client, token, "/api/warn/single", {"ip": "1.1.1.1", "messages": ["x" * 400]})
    assert len(fake_bot[0]["messages"][0]) == 256


# ---------- 单机 ----------

def test_single_success_contract(client, token, allowed, fake_bot):
    r = _post(client, token, "/api/warn/single", {
        "ip": "1.1.1.1", "port": 25565, "username": "Tester",
        "messages": ["a", "b"], "message_delay": 0.5,
    })
    body = r.get_json()
    assert r.status_code == 200
    assert body == {"success": True, "auth_mode": "cracked",
                    "messages_sent": 2, "error": ""}
    assert fake_bot[0]["username"] == "Tester"
    # message_delay 前端传的是秒，不能再被 /100
    assert fake_bot[0]["message_delay"] == 0.5


def test_single_failure_reported(client, token, allowed, fake_bot):
    r = _post(client, token, "/api/warn/single",
              {"ip": "1.1.1.1", "port": 45565, "messages": ["a"]})
    body = r.get_json()
    assert body["success"] is False
    assert "connection refused" in body["error"]


# ---------- 批量 ----------

def test_batch_aggregates_success_and_failure(client, token, allowed, fake_bot):
    r = _post(client, token, "/api/warn/batch", {
        "targets": [{"ip": "1.1.1.1", "port": 25565},
                    {"ip": "2.2.2.2", "port": 45565}],
        "messages": ["hi"], "workers": 2, "username": "Tester",
    })
    body = r.get_json()
    assert body["total"] == 2
    assert body["success"] == 1
    assert body["messages_sent"] == 1
    assert all("ip" in x and "port" in x and "messages_sent" in x for x in body["results"])


def test_db_warn_shares_batch_contract(client, token, allowed, fake_bot):
    """数据库页走 /api/db/warn，返回契约与 batch 一致（前端同一套渲染）。"""
    r = _post(client, token, "/api/db/warn", {
        "targets": [{"ip": "1.1.1.1", "port": 25565}], "messages": ["hi"],
    })
    body = r.get_json()
    assert body["total"] == 1 and body["success"] == 1
    assert isinstance(body["results"], list)


# ---------- 多机器人 ----------

def test_multi_spawns_named_bots_per_server(client, token, allowed, fake_bot):
    r = _post(client, token, "/api/warn/multi", {
        "targets": [{"ip": "1.1.1.1", "port": 25565},
                    {"ip": "2.2.2.2", "port": 25565}],
        "bot_count": 3, "name_prefix": "Sec", "messages": ["hi"],
        "message_delay": 0.5, "workers": 4,
    })
    body = r.get_json()
    assert body["servers"] == 2
    assert body["bot_per_server"] == 3
    assert body["total"] == 6
    names = sorted(c["username"] for c in fake_bot)
    assert names == ["Sec1", "Sec1", "Sec2", "Sec2", "Sec3", "Sec3"]


def test_multi_rejects_oversized_job(client, token, allowed, fake_bot):
    targets = [{"ip": f"10.0.0.{i}", "port": 25565} for i in range(100)]
    r = _post(client, token, "/api/warn/multi", {
        "targets": targets, "bot_count": 20, "messages": ["hi"],
    })
    assert r.status_code == 400
    assert "上限" in r.get_json()["error"]
    assert not fake_bot


# ---------- 真实链路冒烟 ----------

def test_real_join_and_warn_against_mock_server(client, token, allowed, monkeypatch):
    """不打桩，真进一次 mock 服务器：端点 → core.bot → 协议栈整条链路。"""
    from tests.mock_server import MockMCServer

    srv = MockMCServer(port=0, mode="cracked")
    srv.start()
    try:
        r = _post(client, token, "/api/warn/single", {
            "ip": "127.0.0.1", "port": srv.port, "username": "E2EBot",
            "messages": ["e2e-hello"], "message_delay": 0.05,
        })
        body = r.get_json()
        assert r.status_code == 200
        assert body["success"] is True, body
        assert body["messages_sent"] == 1
    finally:
        srv.stop()
