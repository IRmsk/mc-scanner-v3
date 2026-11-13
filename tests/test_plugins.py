#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
v3.3 新增：插件抓取测试。
测试插件列表解析、版本解析、反作弊检测（不实际连接服务器）。
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.plugins import PluginInfo, ServerIntel, _parse_plugins, _parse_version, plugins_to_text


class TestPluginParsing(unittest.TestCase):
    """插件解析测试"""

    def test_parse_plugins_standard(self):
        text = "Plugins (3): Essentials v2.19, WorldEdit v7.2, Vault v1.7"
        plugins = _parse_plugins(text)
        self.assertEqual(len(plugins), 3)
        self.assertEqual(plugins[0].name, "Essentials")
        self.assertEqual(plugins[0].version, "2.19")

    def test_parse_plugins_no_count(self):
        text = "Plugins: PluginA, PluginB, PluginC"
        plugins = _parse_plugins(text)
        self.assertEqual(len(plugins), 3)

    def test_parse_plugins_empty(self):
        plugins = _parse_plugins("")
        self.assertEqual(len(plugins), 0)

    def test_parse_plugins_no_version(self):
        text = "Plugins (2): AuthMe, LuckPerms"
        plugins = _parse_plugins(text)
        self.assertEqual(len(plugins), 2)
        self.assertEqual(plugins[0].name, "AuthMe")
        self.assertEqual(plugins[0].version, "")

    def test_parse_version_paper(self):
        text = "This server is running Paper version git-Paper-218 (MC: 1.20.1)"
        software, version = _parse_version(text)
        self.assertIn("Paper", software)

    def test_parse_version_spigot(self):
        text = "This server is running CraftBukkit version git-Spigot-abc (MC: 1.8.8)"
        software, version = _parse_version(text)
        self.assertIsNotNone(software)

    def test_plugin_info_repr(self):
        p = PluginInfo("Essentials", "2.19")
        self.assertIn("Essentials", repr(p))
        self.assertIn("2.19", repr(p))

    def test_plugin_info_no_version(self):
        p = PluginInfo("AuthMe")
        self.assertEqual(repr(p), "AuthMe")

    def test_plugins_to_text(self):
        plugins = [PluginInfo("A", "1.0"), PluginInfo("B", "2.0")]
        text = plugins_to_text(plugins)
        self.assertIn("A", text)
        self.assertIn("B", text)

    def test_anti_cheat_detection_in_capture(self):
        """反作弊检测是行为而非源码文本：用假 bot 喂 /plugins 响应来验证"""
        from core.plugins import capture_plugins

        class FakeBot:
            """只实现 capture_plugins 需要的最小接口"""

            def __init__(self, responses):
                self.chat_messages = []
                self._responses = responses

            def send_command(self, command):
                for text in self._responses.get(command, []):
                    self.chat_messages.append(text)

        bot = FakeBot({"plugins": ["Plugins (2): NoCheatPlus v1.1, Vault v1.7"]})
        intel = capture_plugins(bot, wait_time=0)
        self.assertEqual(intel.anti_cheat, "ncp")
        self.assertTrue(intel.has_vault)
        self.assertIn("NoCheatPlus", {p.name for p in intel.plugins})

        # 没有任何插件时应判定为 none
        intel_none = capture_plugins(FakeBot({}), wait_time=0)
        self.assertEqual(intel_none.anti_cheat, "none")


class TestServerIntel(unittest.TestCase):
    """服务器情报数据类测试"""

    def test_server_intel_init(self):
        intel = ServerIntel()
        self.assertEqual(intel.plugins, [])
        self.assertEqual(intel.server_software, "")
        self.assertEqual(intel.server_version, "")
        self.assertEqual(intel.anti_cheat, "")

    def test_server_intel_with_plugins(self):
        intel = ServerIntel(
            plugins=[PluginInfo("Essentials", "2.0")],
            server_software="Paper",
            server_version="1.20.1",
            anti_cheat="ncp",
        )
        self.assertEqual(len(intel.plugins), 1)
        self.assertEqual(intel.server_software, "Paper")
        self.assertEqual(intel.anti_cheat, "ncp")


if __name__ == "__main__":
    unittest.main()
