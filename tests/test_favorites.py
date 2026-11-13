#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""收藏模块回归测试：并发原子更新、坏行导入、rescan_all 不持锁做网络 I/O。"""
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from storage import favorites


class TestFavoritesRobustness(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "favorites.json")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_update_favorite_no_lost_update(self):
        favorites.add_favorite("1.1.1.1", 25565, path=self.path)
        favorites.add_favorite("2.2.2.2", 25565, path=self.path)
        # 模拟健康监控只改一项：不能吞掉其它项
        favorites.update_favorite("1.1.1.1", 25565,
                                  lambda f: {**f, "note": "x"}, path=self.path)
        ips = {f["ip"] for f in favorites.load_favorites(self.path)}
        self.assertEqual(ips, {"1.1.1.1", "2.2.2.2"})

    def test_concurrent_add_no_lost_update(self):
        def worker(i):
            for j in range(15):
                favorites.add_favorite(f"10.{i}.0.{j}", 25565, path=self.path)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(favorites.load_favorites(self.path)), 6 * 15)

    def test_import_skips_bad_lines(self):
        src = os.path.join(self.tmp, "import.txt")
        with open(src, "w", encoding="utf-8") as f:
            f.write("1.2.3.4:25565\n5.6.7.8:notaport\n9.9.9.9:70000\n# 注释\n8.8.8.8\n")
        count, failed = favorites.import_favorites(src, path=self.path)
        self.assertEqual(count, 2)          # 1.2.3.4 与 8.8.8.8（默认端口）
        self.assertEqual(len(failed), 2)    # 端口非数字 / 越界
        # 兼容旧签名：仍然返回 int
        self.assertEqual(favorites.import_from_file(src, path=self.path), 2)
        self.assertEqual(len(favorites.load_favorites(self.path)), 2)

    def test_import_json_restores_full_fields(self):
        """JSON 导入恢复完整字段：tags/note/last_info/last_good_info 不丢"""
        src = os.path.join(self.tmp, "fav_export.json")
        export_data = {
            "total": 2,
            "exported_at": "2026-10-13 12:00:00",
            "favorites": [
                {
                    "ip": "1.2.3.4", "port": 25565,
                    "tags": ["生存", "推荐"], "note": "好友服务器",
                    "added_at": "2026-10-01T10:00:00",
                    "last_check": "2026-10-12T08:00:00",
                    "last_info": {"state": "up", "version": "1.21.1", "players_online": 5, "auth": "offline"},
                    "last_good_info": {"state": "up", "version": "1.21.1", "players_online": 10},
                },
                {
                    "ip": "5.6.7.8", "port": 25566,
                    "tags": [], "note": "",
                    "added_at": "2026-10-02T10:00:00",
                    "last_check": None, "last_info": None, "last_good_info": None,
                },
            ],
        }
        with open(src, "w", encoding="utf-8") as f:
            json.dump(export_data, f)

        count, failed = favorites.import_favorites(src, path=self.path)
        self.assertEqual(count, 2)
        self.assertEqual(len(failed), 0)

        favs = favorites.load_favorites(self.path)
        self.assertEqual(len(favs), 2)

        # 验证第一条完整字段
        f1 = next(f for f in favs if f["ip"] == "1.2.3.4")
        self.assertEqual(f1["port"], 25565)
        self.assertEqual(f1["tags"], ["生存", "推荐"])
        self.assertEqual(f1["note"], "好友服务器")
        self.assertEqual(f1["added_at"], "2026-10-01T10:00:00")
        self.assertEqual(f1["last_check"], "2026-10-12T08:00:00")
        self.assertEqual(f1["last_info"]["version"], "1.21.1")
        self.assertEqual(f1["last_info"]["auth"], "offline")
        self.assertEqual(f1["last_good_info"]["players_online"], 10)

        # 验证第二条空字段
        f2 = next(f for f in favs if f["ip"] == "5.6.7.8")
        self.assertEqual(f2["port"], 25566)
        self.assertEqual(f2["tags"], [])
        self.assertEqual(f2["note"], "")

    def test_import_json_raw_array(self):
        """JSON 裸数组格式也能导入"""
        src = os.path.join(self.tmp, "raw.json")
        with open(src, "w", encoding="utf-8") as f:
            json.dump([{"ip": "9.9.9.9", "port": 25565, "tags": ["test"], "note": "raw"}], f)
        count, _ = favorites.import_favorites(src, path=self.path)
        self.assertEqual(count, 1)
        favs = favorites.load_favorites(self.path)
        self.assertEqual(favs[0]["tags"], ["test"])
        self.assertEqual(favs[0]["note"], "raw")

    def test_import_json_duplicate_skipped(self):
        """已存在的收藏导入时跳过，不覆盖原有标签"""
        favorites.add_favorite("1.1.1.1", 25565, tags=["原有标签"], note="原有备注", path=self.path)
        src = os.path.join(self.tmp, "dup.json")
        with open(src, "w", encoding="utf-8") as f:
            json.dump([{"ip": "1.1.1.1", "port": 25565, "tags": ["新标签"], "note": "新备注"}], f)
        count, _ = favorites.import_favorites(src, path=self.path)
        self.assertEqual(count, 1)  # 解析成功1条
        favs = favorites.load_favorites(self.path)
        self.assertEqual(len(favs), 1)  # 不重复添加
        self.assertEqual(favs[0]["tags"], ["原有标签"])  # 不覆盖
        self.assertEqual(favs[0]["note"], "原有备注")

    def test_non_serializable_save_does_not_escape(self):
        favorites.add_favorite("1.1.1.1", 25565, path=self.path)
        # 集合不可 JSON 序列化：不能把异常抛给调用方，文件也要保持合法 JSON
        favorites.update_favorite("1.1.1.1", 25565,
                                  lambda f: {**f, "bad": {1, 2}}, path=self.path)
        with open(self.path, encoding="utf-8") as f:
            self.assertIsInstance(json.load(f), list)

    def test_rescan_all_does_not_hold_lock_during_io(self):
        favorites.add_favorite("1.1.1.1", 25565, path=self.path)

        def slow_probe(ip, port, timeout=5.0):
            time.sleep(0.6)
            return {"state": "up", "version": "1.20"}

        # probe 已改成函数内延迟导入，桩要打在源头 core.probe 上
        from core import probe as probe_mod
        with patch.object(probe_mod, "slp_probe", slow_probe), \
             patch.object(probe_mod, "auth_probe", lambda *a, **k: None):
            t = threading.Thread(
                target=lambda: favorites.rescan_all(timeout=0.1, workers=1, path=self.path))
            t.start()
            time.sleep(0.15)    # 让 rescan_all 进入网络探测阶段
            start = time.time()
            favorites.add_favorite("2.2.2.2", 25565, path=self.path)
            elapsed = time.time() - start
            t.join()
        # 网络 I/O 已移出锁：写操作不应等到 0.6s 的探测结束
        self.assertLess(elapsed, 0.4, f"add_favorite 被 rescan_all 阻塞了 {elapsed:.2f}s")
        ips = {f["ip"] for f in favorites.load_favorites(self.path)}
        self.assertEqual(ips, {"1.1.1.1", "2.2.2.2"})


if __name__ == "__main__":
    unittest.main()
