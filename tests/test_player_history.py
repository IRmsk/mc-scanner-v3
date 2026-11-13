#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
v3.2.1 新增：玩家历史追踪测试。
验证玩家历史记录的增删改查和统计功能。
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from storage import db as storage_db
from storage import player_history as ph


class TestPlayerHistory(unittest.TestCase):
    """玩家历史追踪测试"""

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.db_path = self.tmp.name
        ph.init_player_history(self.db_path)

    def tearDown(self):
        # 先关闭连接池里的连接再删文件，否则会残留 *.db-wal/*.db-shm
        storage_db.close_conn(self.db_path)
        if os.path.exists(self.db_path):
            os.unlink(self.db_path)

    def test_init_creates_table(self):
        # 二次初始化不应报错
        ph.init_player_history(self.db_path)

    def test_update_players(self):
        players = ["Player1", "Player2", "Player3"]
        ph.update_players(self.db_path, "192.168.1.1", 25565, players)
        history = ph.get_player_history(self.db_path, ip="192.168.1.1", port=25565)
        self.assertEqual(len(history), 3)
        names = {h["player_name"] for h in history}
        self.assertEqual(names, set(players))

    def test_update_players_dedup(self):
        # 同一玩家多次出现应只记录一次
        players = ["Player1", "Player1", "Player2"]
        ph.update_players(self.db_path, "192.168.1.1", 25565, players)
        history = ph.get_player_history(self.db_path, ip="192.168.1.1", port=25565)
        self.assertEqual(len(history), 2)
        # 同一批内的重复出现只算一次，seen_count 不应虚高
        p1 = [h for h in history if h["player_name"] == "Player1"][0]
        self.assertEqual(p1["seen_count"], 1)

    def test_get_by_player_name(self):
        ph.update_players(self.db_path, "192.168.1.1", 25565, ["Alice", "Bob"])
        ph.update_players(self.db_path, "192.168.1.2", 25565, ["Alice", "Charlie"])
        history = ph.get_player_history(self.db_path, player_name="Alice")
        self.assertEqual(len(history), 2)

    def test_get_unique_players(self):
        ph.update_players(self.db_path, "192.168.1.1", 25565, ["Alice", "Bob"])
        ph.update_players(self.db_path, "192.168.1.2", 25565, ["Alice", "Charlie"])
        count = ph.get_unique_players(self.db_path)
        self.assertEqual(count, 3)

    def test_get_player_servers(self):
        ph.update_players(self.db_path, "192.168.1.1", 25565, ["Alice"])
        ph.update_players(self.db_path, "192.168.1.2", 25565, ["Alice"])
        servers = ph.get_player_servers(self.db_path, "Alice")
        self.assertEqual(len(servers), 2)

    def test_get_server_players(self):
        ph.update_players(self.db_path, "192.168.1.1", 25565, ["Alice", "Bob", "Charlie"])
        players = ph.get_server_players(self.db_path, "192.168.1.1", 25565)
        self.assertEqual(len(players), 3)

    def test_get_stats(self):
        ph.update_players(self.db_path, "192.168.1.1", 25565, ["Alice", "Bob"])
        ph.update_players(self.db_path, "192.168.1.2", 25565, ["Charlie"])
        stats = ph.get_stats(self.db_path)
        self.assertEqual(stats["unique_players"], 3)
        self.assertEqual(stats["unique_servers"], 2)
        self.assertEqual(stats["total_records"], 3)

    def test_empty_player_list(self):
        ph.update_players(self.db_path, "192.168.1.1", 25565, [])
        history = ph.get_player_history(self.db_path, ip="192.168.1.1", port=25565)
        self.assertEqual(len(history), 0)


if __name__ == "__main__":
    unittest.main()
