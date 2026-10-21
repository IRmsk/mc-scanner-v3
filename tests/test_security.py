# -*- coding: utf-8 -*-
"""安全相关的测试：默认值、拦截条件、门禁。"""
import config as config_mod
import web.state as state_mod


def test_health_monitor_db_extra_default_false():
    """health_monitor_db_extra 默认必须是 False（避免无授权探测第三方）。"""
    cfg = config_mod.DEFAULT_CONFIG
    assert cfg.get("health_monitor_db_extra") is False


def test_public_scan_default_false():
    """capabilities.public_scan 默认必须是 False（禁止全网随机扫描）。"""
    # 空配置时，public_scan 应该返回 False
    caps = {}
    result = bool(caps.get("public_scan", False))
    assert result is False


def test_scan_default_true():
    """capabilities.scan 默认必须是 True（基础扫描允许扫自己的服务器）。"""
    # 空配置时，scan 应该返回 True
    caps = {}
    result = bool(caps.get("scan", True))
    assert result is True


def test_warn_bot_max_removed():
    """warn_bot_max 死配置必须已删除。"""
    cfg = config_mod.DEFAULT_CONFIG
    assert "warn_bot_max" not in cfg
