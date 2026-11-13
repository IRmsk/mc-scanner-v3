# -*- coding: utf-8 -*-
"""Login Start 字节构造测试：覆盖关键分界点。"""
from core.buffer import offline_uuid, write_string, write_uuid
from core.probe import build_login_start_payload


class TestLoginStartPayload:
    def test_763_has_flag(self):
        """1.20.1 (763): username + \\x01(hasUUID) + UUID"""
        p = build_login_start_payload("Test", 763)
        expected = write_string("Test") + b'\x01' + write_uuid(offline_uuid("Test"))
        assert p == expected

    def test_764_no_flag(self):
        """1.20.2 (764): username + UUID（无 0x01 标志位）"""
        p = build_login_start_payload("Test", 764)
        expected = write_string("Test") + write_uuid(offline_uuid("Test"))
        assert p == expected

    def test_766_no_flag(self):
        """1.20.5 (766): 同 764，无标志位"""
        p = build_login_start_payload("Test", 766)
        expected = write_string("Test") + write_uuid(offline_uuid("Test"))
        assert p == expected

    def test_760_has_flag(self):
        """1.19.2 (760): username + \\x01 + UUID"""
        p = build_login_start_payload("Test", 760)
        expected = write_string("Test") + b'\x01' + write_uuid(offline_uuid("Test"))
        assert p == expected

    def test_759_username_only(self):
        """1.19 (759): 只发 username"""
        p = build_login_start_payload("Test", 759)
        assert p == write_string("Test")

    def test_old_versions_username_only(self):
        """老版本（1.12.2-1.18.2，协议340-758）：只发 username"""
        for proto in [340, 477, 575, 735, 751, 758]:
            p = build_login_start_payload("Test", proto)
            assert p == write_string("Test"), f"协议 {proto} 应该只发 username"
