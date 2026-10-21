# -*- coding: utf-8 -*-
"""安全相关的测试：默认值、拦截条件、门禁。"""
import pytest
import config as config_mod
import web.state as state_mod


@pytest.fixture(autouse=True)
def _restore_capabilities():
    """每个测试跑完后还原 capabilities，防止测试之间互相污染。"""
    before = config_mod.get("capabilities")
    yield
    config_mod.set("capabilities", before if before is not None else {})


def test_health_monitor_db_extra_default_false():
    """health_monitor_db_extra 默认必须是 False（避免无授权探测第三方）。"""
    cfg = config_mod.DEFAULT_CONFIG
    assert cfg.get("health_monitor_db_extra") is False


def test_capability_scan_default_true():
    """capability_enabled('scan') 默认必须是 True（基础扫描允许扫自己的服务器）。"""
    config_mod.set("capabilities", {})
    assert state_mod.capability_enabled("scan") is True


def test_capability_public_scan_default_false():
    """capability_enabled('public_scan') 默认必须是 False（禁止全网随机扫描）。"""
    config_mod.set("capabilities", {})
    assert state_mod.capability_enabled("public_scan") is False


def test_capability_public_scan_can_be_enabled():
    """capability_enabled('public_scan') 显式开启后应该返回 True。"""
    config_mod.set("capabilities", {"public_scan": True})
    assert state_mod.capability_enabled("public_scan") is True


def test_public_bind_requires_flag(monkeypatch):
    """绑定 0.0.0.0 时没设 ALLOW_PUBLIC_BIND 应该抛 SystemExit。"""
    from web import app as web_app
    monkeypatch.delenv("ALLOW_PUBLIC_BIND", raising=False)
    import pytest
    with pytest.raises(SystemExit):
        web_app._guard_public_bind("0.0.0.0")
    # 设了 flag 就不抛
    monkeypatch.setenv("ALLOW_PUBLIC_BIND", "1")
    web_app._guard_public_bind("0.0.0.0")
