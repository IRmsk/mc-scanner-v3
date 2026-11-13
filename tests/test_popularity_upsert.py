# -*- coding: utf-8 -*-
"""人数趋势表的写入健壮性。

server_popularity 主键是 (ip, port, recorded_at)，而 recorded_at 只精确到秒。
同一秒内重复 upsert 同一台服务器（批量导入、多线程引擎回写、健康监控轮询）
一定会撞主键：裸 INSERT 下 executemany 整体失败，一次冲突丢掉整批趋势数据。
"""
import os
import sqlite3

import pytest

from storage import db


@pytest.fixture()
def db_path(tmp_path):
    p = str(tmp_path / "pop.db")
    db.init_db(p)
    yield p
    db.close_conn(p)


def _pop_rows(path):
    conn = sqlite3.connect(path)
    try:
        return conn.execute(
            "SELECT ip, port, players_online, recorded_at FROM server_popularity").fetchall()
    finally:
        conn.close()


def test_same_second_duplicate_does_not_lose_batch(db_path):
    """同秒重复写同一台服务器：不能抛错，也不能丢掉同批里的其他服务器。"""
    recs = [
        {"ip": "1.1.1.1", "port": 25565, "players_online": 5, "players_max": 20},
        {"ip": "2.2.2.2", "port": 25565, "players_online": 7, "players_max": 20},
    ]
    db.upsert_many(db_path, recs)
    db.upsert_many(db_path, recs)          # 同一秒再来一次

    rows = _pop_rows(db_path)
    ips = {r[0] for r in rows}
    assert ips == {"1.1.1.1", "2.2.2.2"}, f"趋势数据丢了：{rows}"


def test_duplicate_in_single_batch_keeps_all_other_rows(db_path):
    """同一批里出现重复的 ip:port，其余行不能被连带丢弃。"""
    recs = [
        {"ip": "3.3.3.3", "port": 25565, "players_online": 1, "players_max": 10},
        {"ip": "3.3.3.3", "port": 25565, "players_online": 2, "players_max": 10},
        {"ip": "4.4.4.4", "port": 25565, "players_online": 3, "players_max": 10},
    ]
    db.upsert_many(db_path, recs)

    rows = _pop_rows(db_path)
    assert {r[0] for r in rows} == {"3.3.3.3", "4.4.4.4"}
    # 同秒重复时保留最后写入的值（REPLACE 语义）
    val = [r[2] for r in rows if r[0] == "3.3.3.3"][0]
    assert val == 2


def test_zero_players_not_recorded(db_path):
    """players_online 为 0 时不写趋势（原本的过滤条件不能被改坏）。"""
    db.upsert_many(db_path, [{"ip": "5.5.5.5", "port": 25565,
                              "players_online": 0, "players_max": 10}])
    assert _pop_rows(db_path) == []


def test_timestamp_format_matches_query_window(db_path):
    """写库时间戳必须是空格分隔，查询侧靠字符串比较算 24 小时窗口。

    isoformat() 产生 'T' 分隔（0x54），比空格（0x20）大，
    会让同日更早的记录被错误算进窗口。
    """
    db.upsert_many(db_path, [{"ip": "6.6.6.6", "port": 25565,
                              "players_online": 1, "players_max": 10}])
    recorded = _pop_rows(db_path)[0][3]
    assert "T" not in recorded, f"时间戳格式回退了：{recorded}"
    assert len(recorded) == 19
