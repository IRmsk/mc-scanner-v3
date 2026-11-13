#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
v3.2.1 新增：重复服务器检测测试。
验证精确指纹和软指纹的重复检测逻辑。
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.duplicate import DuplicateDetector, compute_server_fingerprint, compute_soft_fingerprint


class TestDuplicateDetection(unittest.TestCase):
    """重复服务器检测测试"""

    def test_compute_exact_fingerprint(self):
        result = {"ip": "1.2.3.4", "port": 25565, "version": "Paper 1.20.4",
                  "motd": "My Server", "players_max": 100, "proto": 765}
        fp = compute_server_fingerprint(result)
        self.assertIsInstance(fp, str)
        self.assertGreater(len(fp), 0)

    def test_exact_fingerprint_different_ips_same_content(self):
        # 不同 IP 但相同内容 -> 相同精确指纹
        r1 = {"ip": "1.2.3.4", "port": 25565, "version": "Paper 1.20.4",
              "motd": "Same MOTD", "players_max": 100, "proto": 765}
        r2 = {"ip": "5.6.7.8", "port": 25565, "version": "Paper 1.20.4",
              "motd": "Same MOTD", "players_max": 100, "proto": 765}
        self.assertEqual(compute_server_fingerprint(r1), compute_server_fingerprint(r2))

    def test_exact_fingerprint_different_content(self):
        r1 = {"ip": "1.2.3.4", "port": 25565, "version": "Paper 1.20.4",
              "motd": "Server A", "players_max": 100, "proto": 765}
        r2 = {"ip": "1.2.3.4", "port": 25565, "version": "Spigot 1.8.8",
              "motd": "Server B", "players_max": 50, "proto": 47}
        self.assertNotEqual(compute_server_fingerprint(r1), compute_server_fingerprint(r2))

    def test_soft_fingerprint(self):
        result = {"version": "Paper 1.20.4", "motd": "  My Server  ", "players_max": 100}
        fp = compute_soft_fingerprint(result)
        self.assertIsInstance(fp, str)
        self.assertGreater(len(fp), 0)

    def test_soft_fingerprint_case_insensitive(self):
        r1 = {"version": "PAPER 1.20.4", "motd": "MY SERVER", "players_max": 100}
        r2 = {"version": "paper 1.20.4", "motd": "my server", "players_max": 100}
        self.assertEqual(compute_soft_fingerprint(r1), compute_soft_fingerprint(r2))

    def test_detector_exact_duplicate(self):
        detector = DuplicateDetector()
        r1 = {"ip": "1.2.3.4", "port": 25565, "version": "Paper 1.20.4",
              "motd": "Same", "players_max": 100, "proto": 765, "state": "up"}
        r2 = {"ip": "5.6.7.8", "port": 25565, "version": "Paper 1.20.4",
              "motd": "Same", "players_max": 100, "proto": 765, "state": "up"}
        detector.add(r1)
        detector.add(r2)
        dups = detector.get_duplicates()
        self.assertEqual(len(dups), 1)
        self.assertEqual(len(dups[0]["servers"]), 2)

    def test_detector_no_duplicate(self):
        detector = DuplicateDetector()
        r1 = {"ip": "1.2.3.4", "port": 25565, "version": "Paper 1.20.4",
              "motd": "Server A", "players_max": 100, "proto": 765, "state": "up"}
        r2 = {"ip": "5.6.7.8", "port": 25565, "version": "Spigot 1.8.8",
              "motd": "Server B", "players_max": 50, "proto": 47, "state": "up"}
        detector.add(r1)
        detector.add(r2)
        dups = detector.get_duplicates()
        self.assertEqual(len(dups), 0)

    def test_detector_skips_offline(self):
        detector = DuplicateDetector()
        r1 = {"ip": "1.2.3.4", "port": 25565, "version": "Paper",
              "motd": "Same", "players_max": 100, "proto": 765, "state": "offline"}
        detector.add(r1)
        self.assertEqual(len(detector.get_duplicates()), 0)

    def test_detector_stats(self):
        detector = DuplicateDetector()
        for i in range(3):
            r = {"ip": f"10.0.0.{i}", "port": 25565, "version": "Paper 1.20.4",
                 "motd": "Dup", "players_max": 100, "proto": 765, "state": "up"}
            detector.add(r)
        stats = detector.stats()
        self.assertEqual(stats["total_servers"], 3)
        self.assertEqual(stats["duplicate_groups"], 1)


if __name__ == "__main__":
    unittest.main()
