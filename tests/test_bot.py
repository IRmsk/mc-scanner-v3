#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
机器人登录测试。
验证完整登录流程（握手 → Login → Configuration → Play）。
"""
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.bot import MCBot, join_and_warn
from tests.mock_server import MockMCServer


class TestBot(unittest.TestCase):
    """机器人功能测试"""

    @classmethod
    def setUpClass(cls):
        cls.server = MockMCServer(mode="cracked", protocol=767, version_name="1.21.1").start()
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()

    def test_bot_connect(self):
        """测试机器人连接登录"""
        bot = MCBot("127.0.0.1", self.server.port, protocol_version=767,
                    username="TestBot", timeout=5.0)
        try:
            bot.connect()
            self.assertEqual(bot.state, "play")
            self.assertEqual(bot.protocol_version, 767)
        finally:
            bot.close()

    def test_bot_send_chat(self):
        """测试发送聊天消息：必须真的通过协议层发出携带该消息的聊天包"""
        bot = MCBot("127.0.0.1", self.server.port, protocol_version=767,
                    username="TestBot", timeout=5.0)
        try:
            bot.connect()
            chat_id = bot.play_packets.get("sb_chat")
            self.assertIsNotNone(chat_id, "协议 767 缺少 sb_chat 包ID")
            sent = []
            orig = bot.conn.send_packet
            # 拦截底层发送：断言「消息确实被编码进聊天包」，而不是「没抛异常」
            bot.conn.send_packet = lambda pid, payload=b"": sent.append((pid, payload))
            try:
                bot.send_chat("Hello from test")
            finally:
                bot.conn.send_packet = orig
            chat_pkts = [(pid, payload) for pid, payload in sent if pid == chat_id]
            self.assertEqual(len(chat_pkts), 1, f"应只发出一个聊天包，实际 {sent!r}")
            self.assertIn(b"Hello from test", chat_pkts[0][1], "聊天包载荷不含所发消息")
        finally:
            bot.close()

    def test_join_and_warn(self):
        """测试 join_and_warn 完整流程"""
        result = join_and_warn("127.0.0.1", self.server.port,
                               username="TestBot", messages=["Test message"],
                               timeout=5.0, message_delay=0.1, connect_delay=0)
        self.assertTrue(result.success)
        self.assertTrue(result.is_offline)
        self.assertEqual(result.auth_mode, "offline")
        self.assertGreaterEqual(result.messages_sent, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
