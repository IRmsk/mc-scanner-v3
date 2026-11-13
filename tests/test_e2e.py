#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
端到端测试：Mock 服务器 + 扫描引擎 + 数据库。
验证完整扫描流程的正确性。
"""
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.engine import ScanEngine
from storage import db
from tests.mock_server import MockMCServer


class TestEndToEnd(unittest.TestCase):
    """端到端测试"""

    @classmethod
    def setUpClass(cls):
        cls.cracked = MockMCServer(mode="cracked", protocol=767, port=0).start()
        cls.online = MockMCServer(mode="online", protocol=767, port=0).start()
        cls.whitelist = MockMCServer(mode="whitelist", protocol=767, port=0).start()
        cls.tmpdir = tempfile.mkdtemp()
        cls.db_path = os.path.join(cls.tmpdir, "test.db")
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        cls.cracked.stop()
        cls.online.stop()
        cls.whitelist.stop()
        import shutil
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_full_scan(self):
        """测试完整扫描流程"""
        engine = ScanEngine(db_path=self.db_path, workers=3, timeout=3.0, auth_check=True)
        targets = [
            ("127.0.0.1", self.cracked.port),
            ("127.0.0.1", self.online.port),
            ("127.0.0.1", self.whitelist.port),
        ]
        results = engine.scan_targets(iter(targets))
        self.assertEqual(len(results), 3)

        # 验证各服务器认证状态
        auths = {r["port"]: r["auth"] for r in results}
        self.assertEqual(auths.get(self.cracked.port), "cracked")
        self.assertEqual(auths.get(self.online.port), "online")
        # whitelist 可能被识别为 whitelist 或 rejected
        self.assertIn(auths.get(self.whitelist.port), ["whitelist", "rejected"])

    def test_database_persistence(self):
        """测试数据库持久化"""
        db.init_db(self.db_path)
        test_rec = {
            "ip": "1.2.3.4", "port": 25565,
            "version": "1.21.1", "proto": 767,
            "motd": "Test Server", "is_modded": 0,
            "players_online": 10, "players_max": 100,
            "favicon": "", "auth": "cracked",
            "ping_ms": 50, "json": None,
        }
        db.upsert_server(self.db_path, test_rec)

        # 查询验证
        rows = db.query(self.db_path, auth="cracked")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["ip"], "1.2.3.4")
        self.assertEqual(rows[0]["port"], 25565)

        # 统计验证
        stats = db.stats(self.db_path)
        self.assertGreaterEqual(stats["total"], 1)
        self.assertIn("cracked", stats["by_auth"])

    def test_upsert_dedup(self):
        """测试 UPSERT 去重更新"""
        db.init_db(self.db_path)
        rec1 = {"ip": "5.6.7.8", "port": 25565, "version": "1.20.4",
                "proto": 765, "motd": "Old", "is_modded": 0,
                "players_online": 1, "players_max": 10, "favicon": "",
                "auth": "unknown", "ping_ms": 100, "json": None}
        rec2 = {"ip": "5.6.7.8", "port": 25565, "version": "1.21.1",
                "proto": 767, "motd": "New", "is_modded": 0,
                "players_online": 5, "players_max": 100, "favicon": "",
                "auth": "cracked", "ping_ms": 30, "json": None}
        db.upsert_server(self.db_path, rec1)
        db.upsert_server(self.db_path, rec2)

        rows = db.query(self.db_path, search="5.6.7.8")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["version"], "1.21.1")
        self.assertEqual(rows[0]["auth"], "cracked")


if __name__ == "__main__":
    unittest.main(verbosity=2)
