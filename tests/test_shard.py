#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
v3.2.1 新增：分布式任务分片测试。
验证 CIDR 分片、任务领取、状态管理功能。
"""
import os
import shutil
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from distributed.shard import ShardManager, shard_cidr


class TestShardCidr(unittest.TestCase):
    """CIDR 分片测试"""

    def test_shard_basic(self):
        shards = shard_cidr("192.168.0.0/24", num_shards=4, ports=[25565])
        self.assertEqual(len(shards), 4)
        for s in shards:
            self.assertIn("shard_id", s)
            self.assertIn("targets", s)
            self.assertIn("estimated_hosts", s)

    def test_shard_total_hosts(self):
        shards = shard_cidr("10.0.0.0/24", num_shards=2, ports=[25565])
        total = sum(s["estimated_hosts"] for s in shards)
        # /24 有 256 个地址
        self.assertEqual(total, 256)

    def test_shard_single(self):
        shards = shard_cidr("192.168.1.0/24", num_shards=1, ports=[25565])
        self.assertEqual(len(shards), 1)
        self.assertEqual(shards[0]["estimated_hosts"], 256)

    def test_shard_multiple_ports(self):
        shards = shard_cidr("192.168.0.0/24", num_shards=2, ports=[25565, 25566])
        total = sum(s["estimated_hosts"] for s in shards)
        # estimated_hosts 是 IP 地址数，不乘端口数
        self.assertEqual(total, 256)
        # 但每个分片都应包含两个端口
        for s in shards:
            self.assertEqual(s["ports"], [25565, 25566])

    def test_shard_large_cidr(self):
        shards = shard_cidr("172.16.0.0/16", num_shards=8, ports=[25565])
        self.assertEqual(len(shards), 8)
        total = sum(s["estimated_hosts"] for s in shards)
        self.assertEqual(total, 65536)

    def test_shard_ids_sequential(self):
        shards = shard_cidr("192.168.0.0/24", num_shards=4, ports=[25565])
        ids = [s["shard_id"] for s in shards]
        self.assertEqual(ids, [0, 1, 2, 3])


class TestShardManager(unittest.TestCase):
    """分片任务管理器测试"""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.manager = ShardManager(state_dir=self.tmp_dir)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_create_job(self):
        self.manager.create_job("test_job", "192.168.0.0/24", 4, [25565])
        status = self.manager.get_job_status("test_job")
        self.assertIsNotNone(status)
        self.assertEqual(status["total_shards"], 4)
        self.assertEqual(status["completed_shards"], 0)
        self.assertEqual(status["progress"], 0)

    def test_claim_shard(self):
        self.manager.create_job("test_job", "192.168.0.0/24", 4, [25565])
        shard = self.manager.claim_shard("test_job", "worker_1")
        self.assertIsNotNone(shard)
        self.assertEqual(shard["shard_id"], 0)
        status = self.manager.get_job_status("test_job")
        self.assertEqual(status["shards"]["0"]["status"], "running")

    def test_claim_all_shards(self):
        self.manager.create_job("test_job", "192.168.0.0/24", 3, [25565])
        for i in range(3):
            shard = self.manager.claim_shard("test_job", f"worker_{i}")
            self.assertIsNotNone(shard)
        # 第4次领取应返回 None
        shard = self.manager.claim_shard("test_job", "worker_4")
        self.assertIsNone(shard)

    def test_complete_shard(self):
        self.manager.create_job("test_job", "192.168.0.0/24", 4, [25565])
        shard = self.manager.claim_shard("test_job", "worker_1")
        self.manager.complete_shard("test_job", shard["shard_id"], {"found": 5})
        status = self.manager.get_job_status("test_job")
        self.assertEqual(status["completed_shards"], 1)
        self.assertEqual(status["progress"], 25)
        self.assertEqual(status["shards"]["0"]["status"], "completed")

    def test_complete_all_shards(self):
        self.manager.create_job("test_job", "192.168.0.0/24", 2, [25565])
        for i in range(2):
            shard = self.manager.claim_shard("test_job", f"worker_{i}")
            self.manager.complete_shard("test_job", shard["shard_id"], {"found": i})
        status = self.manager.get_job_status("test_job")
        self.assertEqual(status["completed_shards"], 2)
        self.assertEqual(status["progress"], 100)

    def test_nonexistent_job(self):
        # 不存在的任务返回空 dict
        status = self.manager.get_job_status("nonexistent")
        self.assertEqual(status, {})
        # 领取不存在的任务返回 None
        shard = self.manager.claim_shard("nonexistent", "worker_1")
        self.assertIsNone(shard)

    def test_job_persistence(self):
        self.manager.create_job("persist_job", "10.0.0.0/24", 2, [25565])
        # 创建新的 manager 实例，应能读取已保存的任务
        manager2 = ShardManager(state_dir=self.tmp_dir)
        status = manager2.get_job_status("persist_job")
        self.assertIsNotNone(status)
        self.assertEqual(status["total_shards"], 2)


class TestShardRobustness(unittest.TestCase):
    """针对审计发现的边界/并发缺陷的回归测试"""

    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.manager = ShardManager(state_dir=self.tmp_dir)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_zero_shards_raises(self):
        with self.assertRaises(ValueError):
            shard_cidr("10.0.0.0/24", 0)

    def test_negative_shards_raises(self):
        with self.assertRaises(ValueError):
            shard_cidr("10.0.0.0/24", -1)

    def test_invalid_cidr_raises_value_error(self):
        with self.assertRaises(ValueError):
            shard_cidr("not-a-cidr/x", 2)

    def test_complete_shard_is_idempotent(self):
        self.manager.create_job("idem", "10.0.0.0/24", 2, [25565])
        self.manager.claim_shard("idem", "w1")
        self.manager.complete_shard("idem", 0, {"found": 1})
        self.manager.complete_shard("idem", 0, {"found": 1})   # 重复上报
        status = self.manager.get_job_status("idem")
        self.assertEqual(status["completed_shards"], 1)
        self.assertEqual(status["progress"], 50.0)

    def test_job_id_path_traversal_rejected(self):
        for bad in ("../evil", "a/b", "", "x" * 65):
            with self.assertRaises(ValueError):
                self.manager.create_job(bad, "1.2.3.4", 1)

    def test_single_target_is_list(self):
        self.manager.create_job("single", "1.2.3.4", 1)
        job = self.manager._load_job("single")
        self.assertEqual(job["shards"]["0"]["targets"], ["1.2.3.4"])

    def test_concurrent_claim_no_duplicate(self):
        self.manager.create_job("race", "10.0.0.0/24", 4, [25565])
        claimed, lock = [], threading.Lock()

        def worker(i):
            while True:
                s = self.manager.claim_shard("race", f"w{i}")
                if not s:
                    break
                with lock:
                    claimed.append(s["shard_id"])

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sorted(claimed), [0, 1, 2, 3])
        self.assertEqual(len(claimed), len(set(claimed)), f"分片被重复领取: {claimed}")


if __name__ == "__main__":
    unittest.main()
