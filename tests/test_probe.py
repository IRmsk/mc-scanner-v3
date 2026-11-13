#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SLP 探测 + 认证检测单元测试。
使用 Mock 服务器验证协议正确性。
"""
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.probe import auth_probe, slp_probe
from tests.mock_server import MockMCServer


class TestProbe(unittest.TestCase):
    """探测功能测试"""

    @classmethod
    def setUpClass(cls):
        cls.cracked_server = MockMCServer(mode="cracked", protocol=767, version_name="1.21.1").start()
        cls.online_server = MockMCServer(mode="online", protocol=767).start()
        cls.whitelist_server = MockMCServer(mode="whitelist", protocol=767).start()
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        cls.cracked_server.stop()
        cls.online_server.stop()
        cls.whitelist_server.stop()

    def test_slp_probe_cracked(self):
        """测试 SLP 探测离线服"""
        result = slp_probe("127.0.0.1", self.cracked_server.port, timeout=3.0)
        self.assertEqual(result["state"], "up")
        self.assertEqual(result["proto"], 767)
        self.assertEqual(result["version"], "1.21.1")
        self.assertEqual(result["online"], 5)
        self.assertEqual(result["max"], 100)

    def test_slp_probe_invalid(self):
        """测试 SLP 探测不可达地址"""
        result = slp_probe("127.0.0.1", 19999, timeout=1.0, retries=0)
        self.assertIn(result["state"], ["offline", "error"])

    def test_auth_probe_cracked(self):
        """测试认证检测 - 离线/破解服"""
        result = auth_probe("127.0.0.1", self.cracked_server.port, 767, timeout=3.0)
        self.assertEqual(result["state"], "cracked")
        self.assertEqual(result["detected_proto"], 767)

    def test_auth_probe_online(self):
        """测试认证检测 - 正版验证服"""
        result = auth_probe("127.0.0.1", self.online_server.port, 767, timeout=3.0)
        self.assertEqual(result["state"], "online")

    def test_auth_probe_whitelist(self):
        """测试认证检测 - 白名单服"""
        result = auth_probe("127.0.0.1", self.whitelist_server.port, 767, timeout=3.0)
        self.assertIn(result["state"], ["whitelist", "rejected"])

    def test_auth_probe_no_reported_proto_fallback(self):
        """无报告协议时走跨时代回退列表，不抛NameError，返回有效结果"""
        # reported_proto=0 触发 _FALLBACK 列表（775/767/763/761/754/340）
        # 关键验证：get_play_packets 已 import，回退路径不炸
        result = auth_probe("127.0.0.1", self.cracked_server.port, reported_proto=0, timeout=5.0)
        self.assertEqual(result["state"], "cracked")
        self.assertIn(result["detected_proto"], (775, 767, 763, 761, 754, 340))
        self.assertIn("plugin_channels", result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
