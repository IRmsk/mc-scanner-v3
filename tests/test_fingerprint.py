#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
v3.2.1 新增：扩展服务端指纹识别测试。
验证 bungeecord/velocity/node-minecraft-protocol/catserver/mohist 等指纹检测。
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.fingerprint import KNOWN_SERVER_TYPES, SERVER_TYPE_PATTERNS, fingerprint_server


def _make_slp(version_name="", motd="", sample=None, modinfo=False):
    """构造标准 SLP 响应格式。"""
    slp = {
        "version": {"name": version_name, "protocol": 765},
        "description": motd,
        "players": {"online": 0, "max": 20, "sample": sample or []},
    }
    if modinfo:
        slp["modinfo"] = {"type": "FML", "modList": []}
    return slp


class TestFingerprint(unittest.TestCase):
    """扩展指纹识别测试"""

    def test_detect_bungeecord(self):
        slp = _make_slp(version_name="BungeeCord 1.20")
        result = fingerprint_server(slp)
        self.assertEqual(result["type"], "bungeecord")
        self.assertEqual(result["source"], "extended")

    def test_detect_velocity(self):
        slp = _make_slp(version_name="Velocity 3.3.0")
        result = fingerprint_server(slp)
        self.assertEqual(result["type"], "velocity")

    def test_detect_waterfall(self):
        # Waterfall 是 BungeeCord 的分支
        slp = _make_slp(version_name="Waterfall 1.20")
        result = fingerprint_server(slp)
        self.assertEqual(result["type"], "bungeecord")

    def test_detect_catserver(self):
        slp = _make_slp(version_name="CatServer 1.12.2")
        result = fingerprint_server(slp)
        self.assertEqual(result["type"], "catserver")

    def test_detect_mohist(self):
        slp = _make_slp(version_name="Mohist 1.20.1")
        result = fingerprint_server(slp)
        self.assertEqual(result["type"], "mohist")

    def test_detect_arclight(self):
        slp = _make_slp(version_name="Arclight 1.16.5")
        result = fingerprint_server(slp)
        self.assertEqual(result["type"], "arclight")

    def test_detect_paper(self):
        slp = _make_slp(version_name="Paper 1.20.4")
        result = fingerprint_server(slp)
        self.assertEqual(result["type"], "paper")

    def test_detect_spigot(self):
        slp = _make_slp(version_name="Spigot 1.8.8")
        result = fingerprint_server(slp)
        self.assertEqual(result["type"], "spigot")

    def test_detect_forge_via_modinfo(self):
        slp = _make_slp(version_name="1.12.2", modinfo=True)
        result = fingerprint_server(slp)
        self.assertEqual(result["type"], "forge")
        self.assertGreaterEqual(result["confidence"], 0.9)

    def test_detect_forge_via_version(self):
        slp = _make_slp(version_name="Forge 1.12.2")
        result = fingerprint_server(slp)
        self.assertEqual(result["type"], "forge")

    def test_detect_fabric(self):
        slp = _make_slp(version_name="Fabric 1.20.1")
        result = fingerprint_server(slp)
        self.assertEqual(result["type"], "fabric")

    def test_detect_fabric_via_sample(self):
        slp = _make_slp(version_name="1.20.1", sample=[{"name": "FabricLoader"}])
        result = fingerprint_server(slp)
        self.assertEqual(result["type"], "fabric")

    def test_detect_vanilla(self):
        slp = _make_slp(version_name="1.20.4")
        result = fingerprint_server(slp)
        self.assertEqual(result["type"], "vanilla")

    def test_existing_core_type_priority(self):
        slp = _make_slp(version_name="Paper 1.20.4")
        result = fingerprint_server(slp, existing_core_type="paper")
        self.assertEqual(result["type"], "paper")
        self.assertEqual(result["source"], "core_type")

    def test_empty_input(self):
        result = fingerprint_server({})
        self.assertEqual(result["type"], "unknown")

    def test_none_input(self):
        result = fingerprint_server(None)
        self.assertEqual(result["type"], "unknown")

    def test_patterns_exist(self):
        self.assertIsInstance(SERVER_TYPE_PATTERNS, dict)
        self.assertGreater(len(SERVER_TYPE_PATTERNS), 10)

    def test_known_types_exist(self):
        self.assertIn("bungeecord", KNOWN_SERVER_TYPES)
        self.assertIn("velocity", KNOWN_SERVER_TYPES)
        self.assertIn("paper", KNOWN_SERVER_TYPES)
        self.assertIn("forge", KNOWN_SERVER_TYPES)


if __name__ == "__main__":
    unittest.main()
