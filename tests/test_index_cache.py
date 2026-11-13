# -*- coding: utf-8 -*-
"""首页出站优化：ETag 协商 + gzip。

index.html 是 276KB 单文件，原来 serve_index 手写构造 Response，
绕过了 send_file 自带的 Last-Modified/ETag，也没有任何压缩——
每次刷新全量裸传。这组测试守住三个行为：带 ETag、能 304、能压缩。
"""
import gzip

import pytest

from web import app as web_app


@pytest.fixture()
def client():
    web_app.app.config.update(TESTING=True)
    with web_app.app.test_client() as c:
        yield c


def test_index_has_etag_and_cache_control(client):
    r = client.get("/")
    assert r.status_code == 200
    assert r.headers.get("ETag"), "首页必须带 ETag，否则无法协商缓存"
    assert r.headers.get("Cache-Control") == "no-cache"


def test_index_returns_304_on_matching_etag(client):
    first = client.get("/")
    etag = first.headers["ETag"]
    again = client.get("/", headers={"If-None-Match": etag})
    assert again.status_code == 304
    assert again.get_data() == b""


def test_index_changes_etag_after_edit(client, tmp_path, monkeypatch):
    """ETag 必须跟着内容走，不能是常量——否则改完页面用户永远看到旧的。"""
    r1 = client.get("/")
    etag1 = r1.headers["ETag"]
    # 伪造一次 mtime 变化：缓存键里含 mtime，换个值就该换 ETag
    import web.ui_inject as ui
    monkeypatch.setattr(ui.os.path, "getmtime", lambda p: 1234567890.0 if p.endswith("index.html") else 1.0)
    ui._index_cache["key"] = None
    r2 = client.get("/")
    assert r2.headers["ETag"] != etag1


def test_index_gzip_when_client_accepts(client):
    r = client.get("/", headers={"Accept-Encoding": "gzip"})
    assert r.headers.get("Content-Encoding") == "gzip"
    assert r.headers.get("Vary") == "Accept-Encoding"
    body = gzip.decompress(r.get_data()).decode("utf-8")
    assert "<html" in body.lower()
    # 压缩必须真的变小，否则这层白加
    assert len(r.get_data()) < 276549


def test_index_plain_when_client_rejects_gzip(client):
    r = client.get("/", headers={"Accept-Encoding": "identity"})
    assert r.headers.get("Content-Encoding") is None
    assert b"<html" in r.get_data().lower()


def test_index_never_embeds_web_token(client, monkeypatch):
    """页面壳是免鉴权的，绝不能把固定 token 写进 HTML。

    原实现在 </head> 前注入 window.__WEB_TOKEN__，一旦绑定 0.0.0.0，
    任何人 GET / 就能读到固定 token 并接管面板。
    """
    import config as cfg
    secret = "tok-should-not-appear-9f3a"
    monkeypatch.setattr(cfg, "get", lambda k, d=None: secret if k == "web_token" else d)
    body = client.get("/").get_data()
    assert secret.encode() not in body


def test_boot_auth_asks_backend_instead_of_assuming_login():
    """首屏必须真去问 /api/auth/status。

    鉴权恢复之后，页面里还留着「鉴权已移除，不再检查登录状态」的启动逻辑，
    无条件 hideAuthOverlay()：未登录用户直接看到空面板，靠后续 API 挨个 401
    才把登录框弹出来（还会闪一下）。这条断言防止它被改回去。
    """
    import pathlib
    import re

    root = pathlib.Path(__file__).resolve().parent.parent
    html = (root / "web" / "index.html").read_text(encoding="utf-8")
    m = re.search(r"bootAuth[\s\S]{0,900}", html)
    assert m, "找不到 bootAuth 启动逻辑"
    body = m.group(0)
    assert "/api/auth/status" in body, "bootAuth 没有询问后端登录状态"
    assert "logged_in" in body, "bootAuth 没有依据 logged_in 决定显示登录框"
    # 用完整原句，避免把解释性注释里的引用也算成残留
    assert "鉴权已移除：本地工具，不再检查登录状态" not in html, "残留过期的「鉴权已移除」注释"
