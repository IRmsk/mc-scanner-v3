#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
v3.3 新增：代理管理器测试。
测试代理解析、管理器基本功能（不实际连接代理）。
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.proxy import Proxy, ProxyManager, parse_proxy_line


class TestProxy(unittest.TestCase):
    """代理条目测试"""

    def test_parse_host_port(self):
        p = parse_proxy_line("127.0.0.1:8080")
        self.assertIsNotNone(p)
        self.assertEqual(p.host, "127.0.0.1")
        self.assertEqual(p.port, 8080)
        self.assertEqual(p.proto, "http")

    def test_parse_socks5(self):
        p = parse_proxy_line("socks5://127.0.0.1:1080")
        self.assertIsNotNone(p)
        self.assertEqual(p.proto, "socks5")
        self.assertEqual(p.port, 1080)

    def test_parse_http_with_auth(self):
        p = parse_proxy_line("http://user:pass@127.0.0.1:8080")
        self.assertIsNotNone(p)
        self.assertEqual(p.username, "user")
        self.assertEqual(p.password, "pass")

    def test_parse_host_port_auth(self):
        p = parse_proxy_line("127.0.0.1:8080:user:pass")
        self.assertIsNotNone(p)
        self.assertEqual(p.username, "user")
        self.assertEqual(p.password, "pass")

    def test_parse_empty(self):
        self.assertIsNone(parse_proxy_line(""))
        self.assertIsNone(parse_proxy_line("   "))

    def test_proxy_key(self):
        p = Proxy("127.0.0.1", 8080, "http")
        self.assertEqual(p.key(), "http://127.0.0.1:8080")


class TestProxyManager(unittest.TestCase):
    """代理管理器测试"""

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode='w')
        self.tmp.write("127.0.0.1:8080\n127.0.0.2:3128\nsocks5://127.0.0.3:1080\n")
        self.tmp.close()
        # auto_fetch=False 避免从 API 拉取，proxies 初始为空
        self.manager = ProxyManager(proxy_file=self.tmp.name, auto_fetch=False)

    def tearDown(self):
        if os.path.exists(self.tmp.name):
            os.unlink(self.tmp.name)

    def test_load_from_file(self):
        # __init__ 已自动 load 一次，这里清空后重新加载验证
        self.manager.proxies = []
        count = self.manager.load_from_file()
        self.assertEqual(count, 3)
        self.assertEqual(len(self.manager), 3)

    def test_get_proxy(self):
        # __init__ 已自动加载
        p = self.manager.get_proxy()
        self.assertIsNotNone(p)
        self.assertIn(p.proto, ("http", "socks5"))

    def test_add_proxy(self):
        # __init__ 已自动加载3个
        self.manager.add_proxy("10.0.0.1:8080")
        self.assertEqual(len(self.manager), 4)

    def test_mark_failed(self):
        self.manager.load_from_file()
        p = self.manager.get_proxy()
        before = p.fail_count
        self.manager.mark_failed()
        # mark_failed 会自增当前代理的 fail_count（p 即当前代理对象，不受轮换影响）
        self.assertEqual(p.fail_count, before + 1)
        current = self.manager.get_proxy()
        self.assertIsNotNone(current)

    def test_empty_manager(self):
        # 用一次性临时目录，避免硬编码路径被上一次运行的残留文件污染。
        # auto_fetch=False：构造函数默认会从 ProxyScrape 拉代理并写进 proxy_file，
        # 有网环境下会把“不存在的文件”直接创建出几百条代理，断言必然失败。
        with tempfile.TemporaryDirectory() as d:
            missing = os.path.join(d, "proxies.txt")
            empty = ProxyManager(proxy_file=missing, auto_fetch=False)
            count = empty.load_from_file()
            self.assertEqual(count, 0)
            self.assertIsNone(empty.get_proxy())


if __name__ == "__main__":
    unittest.main()
