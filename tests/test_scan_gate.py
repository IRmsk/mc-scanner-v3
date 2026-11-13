# -*- coding: utf-8 -*-
"""公网扫描门禁。

README 第 155 行写着「未授权全网扫描 🚫 禁止」，但这条约束原先只在
CLI 的 random-scan / distributed 两个子命令里生效（return 4），Web 端
/api/scan/random 与 /api/scan/start(+use_masscan) 只查了 capabilities.scan
（默认 true），capability_enabled("public_scan") 全仓零调用。
这组测试守住：公网要开关、内网不受限。
"""
import pytest

from web import app as web_app
from web import auth as auth_mod
from web import state as state_mod
from web.routes_scan import _targets_all_private

_FIXED = "test-fixed-token"
_H = {"X-API-Token": _FIXED}


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setattr(auth_mod, "must_change_pending", lambda: False)
    monkeypatch.setattr(auth_mod, "fixed_token", lambda: _FIXED)
    web_app.app.config.update(TESTING=True)
    with web_app.app.test_client() as c:
        yield c


@pytest.fixture()
def only_scan_enabled(monkeypatch):
    """模拟默认配置：scan=true，public_scan=false。"""
    monkeypatch.setattr(state_mod, "capability_enabled", lambda cap: cap == "scan")


# ------------------------------------------------------------ 目标分类

@pytest.mark.parametrize("targets", [
    ["10.0.0.0/8"],
    ["192.168.1.0/24", "127.0.0.1"],
    ["172.16.0.0/12", "169.254.1.1"],
    ["10.1.2.3"],
])
def test_private_targets_are_allowed(targets):
    assert _targets_all_private(targets) is True


@pytest.mark.parametrize("targets", [
    ["0.0.0.0/0"],
    ["8.8.8.8"],
    ["1.2.3.0/24", "10.0.0.0/8"],   # 混合：只要有一个公网就算公网
    ["mc.example.com"],             # 主机名无法自证私有
])
def test_public_targets_are_not_private(targets):
    assert _targets_all_private(targets) is False


# ------------------------------------------------------------ 接口门禁

def test_random_scan_blocked_without_public_scan(client, only_scan_enabled):
    r = client.post("/api/scan/random", json={"count": 10, "ports": "25565"}, headers=_H)
    assert r.status_code == 403
    assert "public_scan" in r.get_json()["error"]


def test_public_masscan_blocked_without_public_scan(client, only_scan_enabled):
    r = client.post("/api/scan/start", json={
        "targets": "0.0.0.0/0", "ports": [25565], "use_masscan": True}, headers=_H)
    assert r.status_code == 403
    assert "public_scan" in r.get_json()["error"]


def test_private_masscan_not_blocked_by_public_scan(client, only_scan_enabled):
    """内网巡检不该被 public_scan 卡住：用非法端口把请求推过门禁，看它走到 400。"""
    r = client.post("/api/scan/start", json={
        "targets": "10.0.0.0/24", "ports": "not-a-port", "use_masscan": True}, headers=_H)
    assert r.status_code == 400, r.get_json()


def test_public_scan_without_token_is_401(client, only_scan_enabled):
    """门禁归门禁，鉴权归鉴权：先过 token，才轮得到能力开关说话。"""
    r = client.post("/api/scan/random", json={"count": 10})
    assert r.status_code == 401
