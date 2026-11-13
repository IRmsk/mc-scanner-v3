#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
v3.2.1 新增：智能重扫队列测试。
验证重扫策略、到期检测、队列管理功能。
"""
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from storage import db as storage_db
from storage import rescan as rescan_db


class TestRescanQueue(unittest.TestCase):
    """智能重扫队列测试"""

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.db_path = self.tmp.name
        rescan_db.init_rescan_queue(self.db_path)

    def tearDown(self):
        # 先关闭连接池里的连接再删文件，否则会残留 *.db-wal/*.db-shm
        storage_db.close_conn(self.db_path)
        if os.path.exists(self.db_path):
            os.unlink(self.db_path)

    def test_init_creates_table(self):
        # 二次初始化不应报错
        rescan_db.init_rescan_queue(self.db_path)

    def test_add_rescan(self):
        result = {"ip": "192.168.1.1", "port": 25565, "players_online": 5,
                  "players_max": 20, "auth": "cracked", "version": "1.20.4", "state": "up"}
        rescan_db.update_rescan(self.db_path, "192.168.1.1", 25565, result)
        all_items = rescan_db.get_all_rescans(self.db_path)
        self.assertEqual(len(all_items), 1)
        self.assertEqual(all_items[0]["ip"], "192.168.1.1")
        self.assertEqual(all_items[0]["scan_count"], 1)

    def test_first_scan_uses_new_strategy(self):
        # 新发现服务器第一次扫描使用 "new" 策略（快速确认）
        result = {"ip": "192.168.1.1", "port": 25565, "players_online": 10,
                  "players_max": 20, "auth": "cracked", "version": "1.20.4", "state": "up"}
        strategy = rescan_db.update_rescan(self.db_path, "192.168.1.1", 25565, result)
        self.assertEqual(strategy, "new")
        item = rescan_db.get_all_rescans(self.db_path)[0]
        self.assertEqual(item["strategy"], "new")

    def test_second_scan_uses_has_players_strategy(self):
        # 第二次扫描（有人在线）使用 "has_players" 策略
        result = {"ip": "192.168.1.1", "port": 25565, "players_online": 10,
                  "players_max": 20, "auth": "cracked", "version": "1.20.4", "state": "up"}
        rescan_db.update_rescan(self.db_path, "192.168.1.1", 25565, result)
        strategy = rescan_db.update_rescan(self.db_path, "192.168.1.1", 25565, result)
        self.assertEqual(strategy, "has_players")

    def test_second_scan_uses_cracked_strategy(self):
        # 第二次扫描（无人在线的破解服）使用 "cracked" 策略
        result = {"ip": "192.168.1.2", "port": 25565, "players_online": 0,
                  "players_max": 20, "auth": "cracked", "version": "1.20.4", "state": "up"}
        rescan_db.update_rescan(self.db_path, "192.168.1.2", 25565, result)
        strategy = rescan_db.update_rescan(self.db_path, "192.168.1.2", 25565, result)
        self.assertEqual(strategy, "cracked")

    def test_second_scan_uses_online_strategy(self):
        # 第二次扫描（正版服，无人在线）使用 "online" 策略
        # 注意：有人在线时优先使用 has_players 策略
        result = {"ip": "192.168.1.3", "port": 25565, "players_online": 0,
                  "players_max": 20, "auth": "online", "version": "1.20.4", "state": "up"}
        rescan_db.update_rescan(self.db_path, "192.168.1.3", 25565, result)
        strategy = rescan_db.update_rescan(self.db_path, "192.168.1.3", 25565, result)
        self.assertEqual(strategy, "online")

    def test_second_scan_uses_whitelist_strategy(self):
        result = {"ip": "192.168.1.4", "port": 25565, "players_online": 0,
                  "players_max": 20, "auth": "whitelist", "version": "1.20.4", "state": "up"}
        rescan_db.update_rescan(self.db_path, "192.168.1.4", 25565, result)
        strategy = rescan_db.update_rescan(self.db_path, "192.168.1.4", 25565, result)
        self.assertEqual(strategy, "whitelist")

    def test_get_due_rescans(self):
        # 添加一个 next_scan 在过去的记录
        import sqlite3
        conn = sqlite3.connect(self.db_path)
        conn.execute("""INSERT OR REPLACE INTO rescan_queue
                        (ip, port, strategy, next_scan, scan_count, last_state, last_auth, last_online, last_scan)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                     ("10.0.0.1", 25565, "has_players", int(time.time()) - 100, 1, "up", "cracked", 5, int(time.time())))
        conn.commit()
        conn.close()
        due = rescan_db.get_due_rescans(self.db_path)
        self.assertEqual(len(due), 1)
        self.assertEqual(due[0]["ip"], "10.0.0.1")

    def test_get_due_excludes_future(self):
        # next_scan 在未来的不应到期
        import sqlite3
        conn = sqlite3.connect(self.db_path)
        conn.execute("""INSERT OR REPLACE INTO rescan_queue
                        (ip, port, strategy, next_scan, scan_count, last_state, last_auth, last_online, last_scan)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                     ("10.0.0.2", 25565, "has_players", int(time.time()) + 3600, 1, "up", "cracked", 5, int(time.time())))
        conn.commit()
        conn.close()
        due = rescan_db.get_due_rescans(self.db_path)
        self.assertEqual(len(due), 0)

    def test_remove_rescan(self):
        result = {"ip": "192.168.1.1", "port": 25565, "players_online": 5,
                  "players_max": 20, "auth": "cracked", "version": "1.20.4", "state": "up"}
        rescan_db.update_rescan(self.db_path, "192.168.1.1", 25565, result)
        rescan_db.remove_rescan(self.db_path, "192.168.1.1", 25565)
        all_items = rescan_db.get_all_rescans(self.db_path)
        self.assertEqual(len(all_items), 0)

    def test_clear_rescan(self):
        for i in range(5):
            result = {"ip": f"192.168.1.{i}", "port": 25565, "players_online": 0,
                      "players_max": 20, "auth": "cracked", "version": "1.20.4", "state": "up"}
            rescan_db.update_rescan(self.db_path, f"192.168.1.{i}", 25565, result)
        rescan_db.clear_rescan(self.db_path)
        all_items = rescan_db.get_all_rescans(self.db_path)
        self.assertEqual(len(all_items), 0)

    def test_get_stats(self):
        result1 = {"ip": "192.168.1.1", "port": 25565, "players_online": 10,
                   "players_max": 20, "auth": "cracked", "version": "1.20.4", "state": "up"}
        result2 = {"ip": "192.168.1.2", "port": 25565, "players_online": 0,
                   "players_max": 20, "auth": "cracked", "version": "1.20.4", "state": "up"}
        rescan_db.update_rescan(self.db_path, "192.168.1.1", 25565, result1)
        rescan_db.update_rescan(self.db_path, "192.168.1.2", 25565, result2)
        stats = rescan_db.get_stats(self.db_path)
        self.assertEqual(stats["total"], 2)
        self.assertIn("new", stats["by_strategy"])
        self.assertIn("due_now", stats)

    def test_custom_strategies_missing_new_key(self):
        # 只给 default 的自定义策略表不应再抛 KeyError: 'new'
        result = {"state": "up", "players_online": 5, "auth": "cracked"}
        strategy = rescan_db.update_rescan(self.db_path, "10.1.1.1", 25565, result,
                                           strategies={"default": {"interval": 77}})
        self.assertEqual(strategy, "new")
        self.assertEqual(rescan_db.get_all_rescans(self.db_path)[0]["strategy"], "new")
        # 连 default 都没有时给出明确 ValueError，而不是 KeyError
        with self.assertRaises(ValueError):
            rescan_db.update_rescan(self.db_path, "10.1.1.2", 25565, result,
                                    strategies={"cracked": {"interval": 120}})

    def test_claim_due_marks_claimed(self):
        import sqlite3
        rescan_db.update_rescan(self.db_path, "10.0.0.9", 25565,
                                {"state": "up", "players_online": 0, "auth": "cracked"})
        conn = sqlite3.connect(self.db_path)
        conn.execute("UPDATE rescan_queue SET next_scan=? WHERE ip=?",
                     (int(time.time()) - 10, "10.0.0.9"))
        conn.commit()
        conn.close()
        first = rescan_db.claim_due(self.db_path)
        self.assertEqual([r["ip"] for r in first], ["10.0.0.9"])
        # 领取后 next_scan 已顺延，不会被重复领取
        self.assertEqual(rescan_db.claim_due(self.db_path), [])

    def test_scan_count_increments(self):
        result = {"ip": "192.168.1.1", "port": 25565, "players_online": 5,
                  "players_max": 20, "auth": "cracked", "version": "1.20.4", "state": "up"}
        rescan_db.update_rescan(self.db_path, "192.168.1.1", 25565, result)
        rescan_db.update_rescan(self.db_path, "192.168.1.1", 25565, result)
        rescan_db.update_rescan(self.db_path, "192.168.1.1", 25565, result)
        item = rescan_db.get_all_rescans(self.db_path)[0]
        self.assertEqual(item["scan_count"], 3)


if __name__ == "__main__":
    unittest.main()
