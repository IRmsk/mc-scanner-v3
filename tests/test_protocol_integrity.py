# -*- coding: utf-8 -*-
"""协议表与版本映射完整性测试，防止回退和静默残缺"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.packets import get_play_packets
from core.protocol import COMMON_PROTOCOLS, PROTOCOL_TO_VERSION


class TestProtocolMapping:
    """版本映射锁死，防止被意外覆盖"""

    def test_769_is_1214(self):
        assert PROTOCOL_TO_VERSION[769] == "1.21.4"

    def test_770_is_1215(self):
        assert PROTOCOL_TO_VERSION[770] == "1.21.5"

    def test_768_is_1212_1213(self):
        assert PROTOCOL_TO_VERSION[768] == "1.21.2/1.21.3"

    def test_772_is_1217_1218(self):
        assert PROTOCOL_TO_VERSION[772] == "1.21.7/1.21.8"

    def test_773_is_1219_12110(self):
        assert PROTOCOL_TO_VERSION[773] == "1.21.9/1.21.10"

    def test_latest_protocol(self):
        from core.protocol import LATEST_PROTOCOL
        assert LATEST_PROTOCOL == 776

    def test_767_is_121(self):
        assert "1.21" in PROTOCOL_TO_VERSION[767]

    def test_common_protocols_have_mapping(self):
        for p in COMMON_PROTOCOLS:
            assert p in PROTOCOL_TO_VERSION, f"协议 {p} 缺少版本映射"


class TestPacketTableIntegrity:
    """协议表完整性检查，防止静默残缺"""

    REQUIRED_FIELDS = ("sb_chat", "cb_keep_alive", "sb_keep_alive", "cb_disconnect")
    RECOMMENDED_FIELDS = ("cb_teleport", "sb_confirm_teleport")

    def test_auto_table_not_empty(self):
        from core.packets import _load_auto_tables
        tables = _load_auto_tables()
        assert tables is not None and len(tables) > 0, "自动协议表为空"

    def test_common_protocols_have_table(self):
        for p in COMMON_PROTOCOLS:
            pkts = get_play_packets(p)
            assert pkts is not None, f"常用协议 {p} 无包表"

    def test_common_protocols_required_fields(self):
        for p in COMMON_PROTOCOLS:
            pkts = get_play_packets(p)
            # 原来这里 if pkts is None: continue —— 协议表整表缺失反而“通过”，
            # 必须让缺失本身失败。
            assert pkts is not None, f"常用协议 {p} 无包表"
            missing = [f for f in self.REQUIRED_FIELDS if pkts.get(f) is None]
            assert not missing, f"协议 {p} 缺少必需字段 {missing}"

    def test_high_versions_complete(self):
        """高版本（764+）应该全部字段齐全"""
        for p in [764, 765, 766, 767, 768, 769, 770, 771, 772, 773, 774, 775, 776]:
            pkts = get_play_packets(p)
            assert pkts is not None, f"高版本协议 {p} 无包表"
            all_fields = self.REQUIRED_FIELDS + self.RECOMMENDED_FIELDS
            missing = [f for f in all_fields if pkts.get(f) is None]
            assert not missing, f"高版本协议 {p} 缺少字段 {missing}"
