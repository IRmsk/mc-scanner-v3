# -*- coding: utf-8 -*-
"""示例配置的完整性守卫：重复键、与 DEFAULT_CONFIG 的漂移。

这两类问题都不会让程序崩，只会让用户照着示例改配置时踩空——
属于最容易被 review 漏掉的一类（示例里 `capabilities` 曾写了两遍，
json.loads 静默取后者；另有 4 个 ai_* 默认项示例里根本没写）。
"""
import json
import os

import config as config_mod

_EXAMPLE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config.example.json")


def _load_strict(path):
    """按出现顺序加载并收集重复键，而不是让后者静默覆盖前者。"""
    dups = []

    def hook(pairs):
        seen = set()
        for k, _ in pairs:
            if k in seen:
                dups.append(k)
            seen.add(k)
        return dict(pairs)

    with open(path, encoding="utf-8") as f:
        return json.load(f, object_pairs_hook=hook), dups


def test_example_json_has_no_duplicate_keys():
    _, dups = _load_strict(_EXAMPLE)
    assert dups == [], f"config.example.json 存在重复键（后者会静默覆盖前者）: {dups}"


def test_example_declares_all_capabilities():
    data, _ = _load_strict(_EXAMPLE)
    caps = data.get("capabilities")
    assert isinstance(caps, dict), "示例必须包含 capabilities 块"
    for key in ("scan", "public_scan", "login_interact", "rcon_commands"):
        assert key in caps, f"capabilities 缺少 {key}"


def test_example_covers_every_default_key():
    data, _ = _load_strict(_EXAMPLE)
    missing = sorted(set(config_mod.DEFAULT_CONFIG) - set(data))
    assert missing == [], f"有默认值但示例没写，用户不会知道能配: {missing}"


def test_example_values_match_defaults():
    data, _ = _load_strict(_EXAMPLE)
    drift = {k: (data[k], v) for k, v in config_mod.DEFAULT_CONFIG.items()
             if k in data and data[k] != v}
    assert drift == {}, f"示例值与代码默认值不一致（示例会误导用户）: {drift}"
