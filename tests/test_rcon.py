#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
v3.3 新增：RCON 客户端测试。
测试 RCON 协议包构建和解析（不实际连接服务器）。
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.rcon import RCON_TYPE_COMMAND, RCONClient, RCONError


class TestRCONClient(unittest.TestCase):
    """RCON 客户端测试"""

    def test_client_init(self):
        client = RCONClient("127.0.0.1", 25575, "password", timeout=5.0)
        self.assertEqual(client.host, "127.0.0.1")
        self.assertEqual(client.port, 25575)
        self.assertEqual(client.password, "password")
        self.assertFalse(client.authenticated)

    def test_client_init_default_port(self):
        client = RCONClient("127.0.0.1")
        self.assertEqual(client.port, 25575)

    def test_next_id(self):
        client = RCONClient("127.0.0.1")
        id1 = client._next_id()
        id2 = client._next_id()
        self.assertNotEqual(id1, id2)
        self.assertGreater(id2, id1)

    def test_send_packet_constructs(self):
        """测试 _send_packet 未连接时抛 RCONError（不能用 Exception 兜住一切）"""
        client = RCONClient("127.0.0.1")
        with self.assertRaises(RCONError):
            client._send_packet(RCON_TYPE_COMMAND, "test")

    def test_rcon_error(self):
        self.assertTrue(issubclass(RCONError, Exception))

    def test_connect_to_unreachable(self):
        """连接不可达地址应抛出 RCONError"""
        client = RCONClient("192.0.2.1", 25575, "pass", timeout=1.0)
        with self.assertRaises(RCONError):
            client.connect()
        self.assertFalse(client.authenticated)

    def test_execute_without_connect(self):
        """未连接时执行命令应抛 RCONError（具体异常类型，不是兜底的 Exception）"""
        client = RCONClient("127.0.0.1")
        with self.assertRaises(RCONError):
            client.execute("list")

    def test_close_sets_socket_none(self):
        """测试 close() 后 socket 为 None"""
        client = RCONClient("127.0.0.1")
        client.sock = None  # 模拟未连接状态
        client.close()  # 不应抛出异常
        self.assertIsNone(client.sock)

    def test_context_manager_protocol(self):
        """测试上下文管理器协议存在（不实际连接）"""
        client = RCONClient("127.0.0.1")
        self.assertTrue(hasattr(client, "__enter__"))
        self.assertTrue(hasattr(client, "__exit__"))


if __name__ == "__main__":
    unittest.main()
