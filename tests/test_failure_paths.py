#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
失败路径测试：超时、断连、协议回退全失败、扫描中强制停止。
验证系统在异常情况下的健壮性。
"""
import os
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.bot import MCBot
from core.probe import auth_probe, slp_probe
from scanner.engine import ScanEngine


class TestFailurePaths(unittest.TestCase):
    """失败路径测试"""

    def test_slp_probe_timeout(self):
        """测试SLP探测超时（不可达端口）"""
        result = slp_probe("127.0.0.1", 19999, timeout=1.0)
        self.assertIsNotNone(result)
        self.assertEqual(result.get("state"), "offline")

    def test_slp_probe_connection_refused(self):
        """测试连接被拒绝（端口无服务）"""
        result = slp_probe("127.0.0.1", 19998, timeout=1.0)
        self.assertIsNotNone(result)
        self.assertEqual(result.get("state"), "offline")

    def test_auth_probe_offline(self):
        """测试离线服务器的认证探测"""
        result = auth_probe("127.0.0.1", 19997, reported_proto=767, timeout=1.0)
        # 离线服务器可能返回None或offline/error状态
        if result is not None:
            self.assertIn(result.get("state"), ["offline", "error", "unknown"])

    def test_bot_connect_timeout(self):
        """测试Bot连接超时：所有协议尝试失败必须抛 ConnectionError，不能静默通过"""
        bot = MCBot(host="127.0.0.1", port=19996, timeout=1.0, use_premium=False)
        try:
            with self.assertRaises(ConnectionError):
                bot.connect()
        finally:
            bot.close()

    def test_bot_connect_refused(self):
        """测试Bot连接被拒绝：同上，失败必须显式抛出"""
        bot = MCBot(host="127.0.0.1", port=19995, timeout=1.0, use_premium=False)
        try:
            with self.assertRaises(ConnectionError):
                bot.connect()
        finally:
            bot.close()

    def test_scan_engine_with_offline_targets(self):
        """测试扫描引擎处理全离线目标"""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            engine = ScanEngine(db_path=db_path, workers=2, timeout=1.0, auth_check=False)
            targets = [
                ("127.0.0.1", 19994),
                ("127.0.0.1", 19993),
                ("127.0.0.1", 19992),
            ]
            results = engine.scan_targets(iter(targets))
            # 离线目标可能返回空列表或offline结果
            self.assertIsNotNone(results)
            for r in results:
                self.assertIn(r.get("state"), ["offline", "unknown"])
        finally:
            os.unlink(db_path)

    def test_scan_engine_stop_event(self):
        """测试扫描中强制停止（stop_event）"""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            stop_event = threading.Event()
            engine = ScanEngine(db_path=db_path, workers=2, timeout=1.0,
                                auth_check=False, stop_event=stop_event)
            # 启动后立即停止
            stop_event.set()
            targets = [("127.0.0.1", p) for p in range(19990, 19900, -1)]
            results = engine.scan_targets(iter(targets))
            # 停止后应该快速返回，结果可能不完整
            self.assertIsNotNone(results)
        finally:
            os.unlink(db_path)

    def test_probe_list_with_progress(self):
        """测试probe_list的progress_callback"""
        progress_calls = []
        def on_progress(done, total, open_count=0):
            progress_calls.append((done, total))

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            engine = ScanEngine(db_path=db_path, workers=2, timeout=1.0)
            targets = [("127.0.0.1", 19989), ("127.0.0.1", 19988)]
            results = engine.probe_list(targets, progress_callback=on_progress)
            self.assertIsNotNone(results)
            # progress_callback应该被调用至少一次
            self.assertGreater(len(progress_calls), 0)
        finally:
            os.unlink(db_path)

    def test_invalid_host(self):
        """测试无效主机名"""
        result = slp_probe("invalid.host.name.xyz", 25565, timeout=1.0)
        self.assertIsNotNone(result)
        self.assertIn(result.get("state"), ["offline", "error"])

    def test_bot_close_without_connect(self):
        """测试未连接就close不崩溃"""
        bot = MCBot(host="127.0.0.1", port=25565, use_premium=False)
        # 不调用connect直接close
        try:
            bot.close()
        except Exception as e:
            self.fail(f"close() without connect raised: {e}")

    def test_bot_send_chat_without_connect(self):
        """未进入 play 就发消息必须抛 RuntimeError（而不是悄悄丢弃）"""
        bot = MCBot(host="127.0.0.1", port=25565, use_premium=False)
        try:
            with self.assertRaises(RuntimeError):
                bot.send_chat("test")
        finally:
            bot.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
