# -*- coding: utf-8 -*-
"""ScanProgressStore 断点续扫与版本兼容测试。"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.safe import PROGRESS_VERSION, ScanProgressStore


def _targets(n=5):
    return [("10.0.0.%d" % i, 25565) for i in range(n)]


def test_new_task_writes_version(tmp_path):
    pf = str(tmp_path / "prog.json")
    store = ScanProgressStore(pf)
    remaining, resumed = store.begin(_targets())
    store.finish()
    assert resumed is False
    with open(pf, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data.get("version") == PROGRESS_VERSION
    assert data.get("remaining_count") == 5


def test_resume_compatible(tmp_path):
    pf = str(tmp_path / "prog.json")
    s1 = ScanProgressStore(pf)
    s1.begin(_targets())
    s1.done(("10.0.0.0", 25565))
    s1.finish()
    # 第二次：应resume且剩余4个
    s2 = ScanProgressStore(pf)
    remaining, resumed = s2.begin(_targets())
    assert resumed is True
    assert len(remaining) == 4
    assert ("10.0.0.0", 25565) not in remaining


def test_resume_incompatible_version(tmp_path, capsys):
    pf = str(tmp_path / "prog.json")
    # 写入一个高版本（未来格式）
    with open(pf, "w", encoding="utf-8") as f:
        json.dump({"version": PROGRESS_VERSION + 99, "remaining": [["1.2.3.4", 25565]]}, f)
    store = ScanProgressStore(pf)
    remaining, resumed = store.begin(_targets())
    out = capsys.readouterr().out
    assert resumed is False
    assert "版本不兼容" in out
    assert len(remaining) == 5  # 退回全新任务


def test_resume_legacy_no_version(tmp_path, capsys):
    pf = str(tmp_path / "prog.json")
    # 旧格式：无version字段
    with open(pf, "w", encoding="utf-8") as f:
        json.dump({"remaining": [["1.2.3.4", 25565]]}, f)
    store = ScanProgressStore(pf)
    remaining, resumed = store.begin(_targets())
    out = capsys.readouterr().out
    assert resumed is False
    assert "版本不兼容" in out


def test_atomic_write_no_tmp_left(tmp_path):
    pf = str(tmp_path / "prog.json")
    store = ScanProgressStore(pf)
    store.begin(_targets())
    store.finish()
    assert not os.path.exists(pf + ".tmp")
