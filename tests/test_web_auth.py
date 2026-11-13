# -*- coding: utf-8 -*-
"""Web 面板 token 鉴权。

之前 app.py 的 _check_auth 直接 return None，于是 70 个 /api/ 端点全部裸奔：
auth.py 的 PBKDF2 登录、前端登录框、__WEB_TOKEN__ 注入全成了摆设。
这组测试守住三件事：拦得住、放得对、强制改密是真强制。
"""
import pytest

from web import app as web_app
from web import auth as auth_mod


@pytest.fixture()
def client(monkeypatch):
    """默认账号状态下的测试客户端：视为已改密、未配置固定 token。"""
    monkeypatch.setattr(auth_mod, "must_change_pending", lambda: False)
    monkeypatch.setattr(auth_mod, "fixed_token", lambda: "")
    web_app.app.config.update(TESTING=True)
    with web_app.app.test_client() as c:
        yield c


@pytest.fixture()
def session_token():
    token = auth_mod.create_session("admin")
    yield token
    auth_mod.destroy_session(token)


def test_page_shell_is_public(client):
    """页面与静态资源放行：壳里没有数据，数据全在 /api/ 后面。"""
    assert client.get("/manifest.json").status_code == 200


def test_api_rejects_missing_token(client):
    r = client.get("/api/scan/status")
    assert r.status_code == 401
    assert r.get_json().get("need_login") is True


def test_api_rejects_bogus_token(client):
    r = client.get("/api/scan/status", headers={"X-API-Token": "deadbeef"})
    assert r.status_code == 401


def test_api_accepts_session_token(client, session_token):
    r = client.get("/api/scan/status", headers={"X-API-Token": session_token})
    assert r.status_code != 401


def test_api_accepts_token_via_query_param(client, session_token):
    """curl / 脚本友好：?token= 也要能用。"""
    r = client.get(f"/api/scan/status?token={session_token}")
    assert r.status_code != 401


def test_api_accepts_fixed_token(client, monkeypatch):
    """config.web_token / MC_WEB_TOKEN 的固定 token 通道。"""
    monkeypatch.setattr(auth_mod, "fixed_token", lambda: "s3cret-token")
    r = client.get("/api/scan/status", headers={"X-API-Token": "s3cret-token"})
    assert r.status_code != 401


def test_must_change_blocks_non_auth_api(client, session_token, monkeypatch):
    """默认账号没改密时，后端必须拒绝非 auth 接口——否则"强制改密"只是前端弹窗。"""
    monkeypatch.setattr(auth_mod, "must_change_pending", lambda: True)
    r = client.get("/api/scan/status", headers={"X-API-Token": session_token})
    assert r.status_code == 403
    assert r.get_json().get("must_change") is True


def test_auth_status_stays_public_so_frontend_can_ask(client):
    """前端靠 /api/auth/status 的 401 决定是否弹登录框，它必须始终可达。"""
    r = client.get("/api/auth/status")
    assert r.status_code == 401
    assert r.get_json().get("logged_in") is False
