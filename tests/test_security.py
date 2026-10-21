# -*- coding: utf-8 -*-
"""安全相关的测试：默认值、拦截条件、门禁。"""
import config as config_mod
import web.state as state_mod


def test_health_monitor_db_extra_default_false():
    """health_monitor_db_extra 默认必须是 False（避免无授权探测第三方）。"""
    cfg = config_mod.DEFAULT_CONFIG
    assert cfg.get("health_monitor_db_extra") is False


def test_capability_scan_default_true(monkeypatch):
    """capability_enabled('scan') 默认必须是 True（基础扫描允许扫自己的服务器）。"""
    config_mod.set("capabilities", {})
    assert state_mod.capability_enabled("scan") is True


def test_capability_public_scan_default_false(monkeypatch):
    """capability_enabled('public_scan') 默认必须是 False（禁止全网随机扫描）。"""
    config_mod.set("capabilities", {})
    assert state_mod.capability_enabled("public_scan") is False


def test_capability_public_scan_can_be_enabled(monkeypatch):
    """capability_enabled('public_scan') 显式开启后应该返回 True。"""
    config_mod.set("capabilities", {"public_scan": True})
    assert state_mod.capability_enabled("public_scan") is True
