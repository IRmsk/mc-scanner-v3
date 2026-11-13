#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模组服（Forge/Fabric）支持测试。
验证机器人能响应登录阶段插件消息，从而进入模组服：
- Forge FML2/FML3 登录握手（LoginPluginRequest → LoginPluginResponse declined）
- 配置阶段插件消息（minecraft:brand 品牌回送）
- auth_probe 在模组服上也能正确检测认证模式
"""
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.bot import MCBot, join_and_warn
from core.probe import auth_probe
from tests.mock_server import MockMCServer


class TestModded(unittest.TestCase):
    """模组服支持测试"""

    @classmethod
    def setUpClass(cls):
        # forge 模式：登录阶段必须收到客户端插件响应才放行
        cls.forge = MockMCServer(mode="forge", protocol=767, version_name="1.21.1 (Forge)").start()
        # cracked 模式：配置阶段回送 brand 插件消息，验证品牌回送
        cls.vanilla = MockMCServer(mode="cracked", protocol=767, version_name="1.21.1").start()
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        cls.forge.stop()
        cls.vanilla.stop()

    def test_bot_joins_forge_server(self):
        """机器人应能进入发送登录插件消息的 Forge 模组服"""
        bot = MCBot("127.0.0.1", self.forge.port, protocol_version=767,
                    username="TestBot", timeout=5.0)
        try:
            bot.connect()
            self.assertEqual(bot.state, "play")
            # 登录阶段应观察到 Forge 插件频道
            self.assertTrue(any("fml" in c for c in bot.modded_channels),
                            f"应识别到 fml 频道, got {bot.modded_channels}")
        finally:
            bot.close()

    def test_join_and_warn_on_forge(self):
        """在 Forge 模组服上执行 join_and_warn 应能发消息"""
        result = join_and_warn("127.0.0.1", self.forge.port,
                               username="SecurityBot", messages=["Test warn"],
                               timeout=5.0, message_delay=0.1, connect_delay=0)
        self.assertTrue(result.success, f"失败: {result.error}")
        self.assertEqual(result.auth_mode, "offline")
        self.assertGreaterEqual(result.messages_sent, 1)
        self.assertTrue(any("fml" in c for c in result.modded_channels or []))

    def test_auth_probe_on_forge(self):
        """认证检测应能穿过 Forge 插件消息，正确识别为 cracked"""
        res = auth_probe("127.0.0.1", self.forge.port, 767, timeout=5.0)
        self.assertEqual(res["state"], "cracked", f"detail: {res.get('detail')}")

    def test_config_brand_received(self):
        """配置阶段应回送 minecraft:brand，满足等待品牌的模组服/反作弊"""
        bot = MCBot("127.0.0.1", self.vanilla.port, protocol_version=767,
                    username="TestBot", timeout=5.0)
        try:
            bot.connect()
            self.assertEqual(bot.state, "play")
        finally:
            bot.close()
        time.sleep(0.3)
        self.assertTrue(len(self.vanilla.received_brands) >= 1,
                        "服务端应收到客户端品牌插件消息")
        # 品牌内容应为 vanilla
        raw = self.vanilla.received_brands[-1]
        self.assertIn(b"vanilla", raw)


if __name__ == "__main__":
    unittest.main(verbosity=2)
