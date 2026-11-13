# -*- coding: utf-8 -*-
"""文档与代码的一致性守卫。

README 自己写着「版本号唯一来源是 config.__version__」，但徽章上的测试数
（215）和协议版本数（41）都是手写的，早就跟实际（249 / 40）漂开了。
这类数字人肉维护必然漂，所以要么交给 CI 徽章，要么让测试盯着。
"""
import json
import os
import re

import config

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(name):
    with open(os.path.join(_ROOT, name), encoding="utf-8") as f:
        return f.read()


def _protocol_count():
    with open(os.path.join(_ROOT, "core", "packets_auto.json"), encoding="utf-8") as f:
        return len(json.load(f))


def test_version_banner_matches_config():
    """README 标题里的版本号必须等于 config.__version__。"""
    for name in ("README.md", "README.en.md"):
        m = re.search(r"MC Scanner v([0-9][0-9A-Za-z.\-]*)", _read(name))
        assert m, f"{name} 找不到版本标题"
        assert m.group(1) == config.__version__, (
            f"{name} 写成 v{m.group(1)}，而 config.__version__ 是 {config.__version__}")


def test_protocol_badge_matches_data():
    """协议表徽章的数字必须等于 packets_auto.json 里实际版本数。"""
    expected = _protocol_count()
    cases = (
        ("README.md", r"协议表-(\d+)%20版本"),
        ("README.en.md", r"Protocol-(\d+)%20versions"),
    )
    for name, pattern in cases:
        m = re.search(pattern, _read(name))
        assert m, f"{name} 找不到协议表徽章"
        assert int(m.group(1)) == expected, (
            f"{name} 徽章写 {m.group(1)} 个版本，实际数据是 {expected} 个")


def test_inline_protocol_count_matches_data():
    """正文里的协议版本数也要跟上，别只改徽章。"""
    expected = _protocol_count()
    for name, pattern in (("README.md", r"（(\d+) 个协议版本）"), ("README.en.md", r"\((\d+) versions\)")):
        text = _read(name)
        m = re.search(pattern, text)
        if not m:
            continue
        assert int(m.group(1)) == expected, f"{name} 正文写 {m.group(1)} 个版本，实际 {expected} 个"


def test_no_hardcoded_test_count():
    """测试数量用 CI 徽章表达；手写的数字一定会漂。"""
    for name, pattern in (("README.md", r"测试-\d+%20通过|(\d+) 个测试全部通过"),
                          ("README.en.md", r"Tests-\d+%20passing|(\d+) tests all passing")):
        assert not re.search(pattern, _read(name)), (
            f"{name} 里还有硬编码的测试数量，改成 CI 徽章或删掉")
