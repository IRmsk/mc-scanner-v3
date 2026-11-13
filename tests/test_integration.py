#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
集成测试：目标解析、排除列表、端口扫描等模块的组合测试。
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.buffer import offline_uuid, read_string, read_varint, write_string, write_varint
from core.protocol import get_chat_format, get_version_name
from scanner.exclude import Excluder
from scanner.portscan import check_port
from scanner.targets import count_targets, deduplicate_targets, parse_port_spec, parse_targets


class TestIntegration(unittest.TestCase):
    """集成测试"""

    def test_parse_port_spec(self):
        """测试端口规格解析"""
        self.assertEqual(parse_port_spec("25565"), [25565])
        self.assertEqual(parse_port_spec("25565,25566"), [25565, 25566])
        self.assertEqual(parse_port_spec("25565-25567"), [25565, 25566, 25567])
        self.assertEqual(parse_port_spec("25565,25570-25572"), [25565, 25570, 25571, 25572])

    def test_parse_targets_ip(self):
        """测试目标解析 - 单个 IP"""
        targets = list(parse_targets(["1.2.3.4"], [25565]))
        self.assertEqual(targets, [("1.2.3.4", 25565)])

    def test_parse_targets_cidr(self):
        """测试目标解析 - CIDR 网段"""
        targets = list(parse_targets(["192.168.1.0/30"], [25565]))
        self.assertEqual(len(targets), 2)  # /30 = 2 个可用地址

    def test_parse_targets_with_port(self):
        """测试目标解析 - 带端口"""
        targets = list(parse_targets(["1.2.3.4:25566"], [25565]))
        self.assertEqual(targets, [("1.2.3.4", 25566)])

    def test_count_targets(self):
        """测试目标计数"""
        count = count_targets(["1.2.3.0/24"], [25565])
        self.assertEqual(count, 254)

    def test_deduplicate(self):
        """测试去重"""
        targets = [("1.1.1.1", 25565), ("1.1.1.1", 25565), ("2.2.2.2", 25565)]
        result = deduplicate_targets(targets)
        self.assertEqual(len(result), 2)

    def test_excluder(self):
        """测试排除列表"""
        ex = Excluder(None)
        ex._load_defaults()
        self.assertTrue(ex.is_excluded("192.168.1.1"))
        self.assertTrue(ex.is_excluded("10.0.0.1"))
        self.assertFalse(ex.is_excluded("127.0.0.1"))
        self.assertFalse(ex.is_excluded("8.8.8.8"))

    def test_excluder_filter(self):
        """测试排除过滤"""
        ex = Excluder(None)
        ex._load_defaults()
        targets = [("192.168.1.1", 25565), ("8.8.8.8", 25565), ("10.0.0.1", 25565)]
        filtered = list(ex.filter_targets(iter(targets)))
        self.assertEqual(filtered, [("8.8.8.8", 25565)])

    def test_varint_roundtrip(self):
        """测试 VarInt 编解码往返"""
        for value in [0, 1, 127, 128, 255, 25565, 2147483647]:
            encoded = write_varint(value)
            decoded, offset = read_varint(encoded, 0)
            self.assertEqual(decoded, value)
            self.assertEqual(offset, len(encoded))

    def test_string_roundtrip(self):
        """测试字符串编解码往返"""
        for s in ["", "hello", "中文测试", "a" * 100]:
            encoded = write_string(s)
            decoded, offset = read_string(encoded, 0)
            self.assertEqual(decoded, s)

    def test_offline_uuid(self):
        """测试离线 UUID 生成"""
        uuid1 = offline_uuid("TestPlayer")
        uuid2 = offline_uuid("TestPlayer")
        self.assertEqual(uuid1, uuid2)  # 确定性
        self.assertNotEqual(uuid1, offline_uuid("OtherPlayer"))

    def test_version_name(self):
        """测试协议号转版本名"""
        self.assertEqual(get_version_name(340), "1.12.2")
        self.assertEqual(get_version_name(767), "1.21/1.21.1")
        self.assertEqual(get_version_name(774), "1.21.11")

    def test_chat_format(self):
        """测试聊天格式判断"""
        self.assertEqual(get_chat_format(774), "new")
        self.assertEqual(get_chat_format(766), "new")
        self.assertEqual(get_chat_format(765), "old_signed_761")
        self.assertEqual(get_chat_format(760), "old_signed_760")
        self.assertEqual(get_chat_format(759), "old_signed_759")
        self.assertEqual(get_chat_format(340), "simple")

    def test_check_port_closed(self):
        """测试端口检测 - 关闭的端口"""
        result = check_port("127.0.0.1", 19999, timeout=1.0)
        self.assertFalse(result.is_open)


if __name__ == "__main__":
    unittest.main(verbosity=2)
