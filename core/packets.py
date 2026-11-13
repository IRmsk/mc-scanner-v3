# -*- coding: utf-8 -*-
"""
多版本 Play 阶段包 ID 表管理。
支持自动生成表（packets_auto.py）优先，回退到手写表。
"""
import threading

from .protocol import get_chat_format

# 手写 Play 包 ID 表（按协议版本范围）
# 包含: 聊天/保持连接/登录/传送/断开/插件消息/玩家信息 等常用包
_PLAY_TABLES = [
    # 767: 1.21-1.21.1
    {"min_proto": 767, "max_proto": 767, "sb_chat": 0x06, "sb_chat_command": 0x04,
     "cb_keep_alive": 0x26, "sb_keep_alive": 0x18, "cb_ping": 0x35, "sb_pong": 0x27,
     "cb_login": 0x2B, "cb_teleport": 0x40, "sb_confirm_teleport": 0x00, "cb_disconnect": 0x1D,
     "cb_plugin_message": 0x19, "sb_plugin_message": 0x12, "cb_player_info": 0x3E,
     "cb_player_remove": 0x3D, "cb_chat_message": 0x39, "cb_system_chat": 0x6C,
     "cb_profileless_chat": 0x1E},
    # 766: 1.20.5-1.20.6
    {"min_proto": 766, "max_proto": 766, "sb_chat": 0x06, "sb_chat_command": 0x04,
     "cb_keep_alive": 0x26, "sb_keep_alive": 0x18, "cb_ping": 0x35, "sb_pong": 0x27,
     "cb_login": 0x2B, "cb_teleport": 0x40, "sb_confirm_teleport": 0x00, "cb_disconnect": 0x1D,
     "cb_plugin_message": 0x19, "sb_plugin_message": 0x12, "cb_player_info": 0x3E,
     "cb_player_remove": 0x3D, "cb_chat_message": 0x39, "cb_system_chat": 0x6C,
     "cb_profileless_chat": 0x1E},
    # 765: 1.20.3-1.20.4
    {"min_proto": 765, "max_proto": 765, "sb_chat": 0x05, "sb_chat_command": 0x04,
     "cb_keep_alive": 0x24, "sb_keep_alive": 0x15, "cb_ping": 0x33, "sb_pong": 0x24,
     "cb_login": 0x29, "cb_teleport": 0x3E, "sb_confirm_teleport": 0x00, "cb_disconnect": 0x1B,
     "cb_plugin_message": 0x18, "sb_plugin_message": 0x10, "cb_player_info": 0x3C,
     "cb_player_remove": 0x3B, "cb_chat_message": 0x37, "cb_system_chat": 0x69,
     "cb_profileless_chat": 0x1C},
    # 764: 1.20.2
    {"min_proto": 764, "max_proto": 764, "sb_chat": 0x05, "sb_chat_command": 0x04,
     "cb_keep_alive": 0x24, "sb_keep_alive": 0x14, "cb_ping": 0x33, "sb_pong": 0x23,
     "cb_login": 0x29, "cb_teleport": 0x3E, "sb_confirm_teleport": 0x00, "cb_disconnect": 0x1B,
     "cb_plugin_message": 0x18, "sb_plugin_message": 0x0F, "cb_player_info": 0x3C,
     "cb_player_remove": 0x3B, "cb_chat_message": 0x37, "cb_system_chat": 0x67,
     "cb_profileless_chat": 0x1C},
    # 768-769: 1.21.2-1.21.4
    {"min_proto": 768, "max_proto": 769, "sb_chat": 0x07, "sb_chat_command": 0x05,
     "cb_keep_alive": 0x27, "sb_keep_alive": 0x1A, "cb_ping": 0x37, "sb_pong": 0x29,
     "cb_login": 0x2C, "cb_teleport": 0x42, "sb_confirm_teleport": 0x00, "cb_disconnect": 0x1D,
     "cb_plugin_message": 0x19, "sb_plugin_message": 0x14, "cb_player_info": 0x40,
     "cb_player_remove": 0x3F, "cb_chat_message": 0x3B, "cb_system_chat": 0x73,
     "cb_profileless_chat": 0x1E},
    # 770: 1.21.5（只覆盖 770！）
    # 771/772(1.21.6~1.21.8) 的包 ID 已经整体后移：chat_message 8(非7)、chat_command 6(非5)、
    # keep_alive 27(非26)、custom_payload 21(非20)、pong 44(非43)。
    # 原来这一行写成 770-772，等于用 1.21.5 的 ID 覆盖了 1.21.6+，会导致保活回错包被踢、指令发错包。
    # 771/772 现在交给自动表（字段完整），不要在这里加范围。
    {"min_proto": 770, "max_proto": 770, "sb_chat": 0x07, "sb_chat_command": 0x05,
     "cb_keep_alive": 0x26, "sb_keep_alive": 0x1A, "cb_ping": 0x36, "sb_pong": 0x2B,
     "cb_login": 0x2B, "cb_teleport": 0x41, "sb_confirm_teleport": 0x00, "cb_disconnect": 0x1C,
     "cb_plugin_message": 0x18, "sb_plugin_message": 0x14, "cb_player_info": 0x3F,
     "cb_player_remove": 0x3E, "cb_chat_message": 0x3A, "cb_system_chat": 0x72,
     "cb_profileless_chat": 0x1D},
    # 773-774: 1.21.9-1.21.11
    {"min_proto": 773, "max_proto": 774, "sb_chat": 0x08, "sb_chat_command": 0x06,
     "cb_keep_alive": 0x2B, "sb_keep_alive": 0x1B, "cb_ping": 0x3B, "sb_pong": 0x2C,
     "cb_login": 0x30, "cb_teleport": 0x46, "sb_confirm_teleport": 0x00, "cb_disconnect": 0x20,
     "cb_plugin_message": 0x18, "sb_plugin_message": 0x15, "cb_player_info": 0x44,
     "cb_player_remove": 0x43, "cb_chat_message": 0x3F, "cb_system_chat": 0x77,
     "cb_profileless_chat": 0x21},
    # 775+: 26.1+ (Minecraft 26.1/26.2)
    {"min_proto": 775, "max_proto": 9999, "sb_chat": 0x09, "sb_chat_command": 0x07,
     "cb_keep_alive": 0x2C, "sb_keep_alive": 0x1C, "cb_ping": 0x3D, "sb_pong": 0x2D,
     "cb_login": 0x31, "cb_teleport": 0x48, "sb_confirm_teleport": 0x00, "cb_disconnect": 0x20,
     "cb_plugin_message": 0x18, "sb_plugin_message": 0x16, "cb_player_info": 0x46,
     "cb_player_remove": 0x45, "cb_chat_message": 0x41, "cb_system_chat": 0x79,
     "cb_profileless_chat": 0x21},
    # 761: 1.19.3
    {"min_proto": 761, "max_proto": 761, "sb_chat": 0x05, "sb_chat_command": 0x04,
     "cb_keep_alive": 0x1F, "sb_keep_alive": 0x11, "cb_ping": 0x2E, "sb_pong": 0x1F,
     "cb_login": 0x25, "cb_teleport": 0x38, "sb_confirm_teleport": 0x00, "cb_disconnect": 0x17,
     "cb_plugin_message": 0x15, "sb_plugin_message": 0x0C, "cb_player_info": 0x36,
     "cb_player_remove": 0x35, "cb_chat_message": 0x31, "cb_system_chat": 0x60,
     "cb_profileless_chat": 0x18},
    # 762-763: 1.19.4-1.20.1
    {"min_proto": 762, "max_proto": 763, "sb_chat": 0x05, "sb_chat_command": 0x04,
     "cb_keep_alive": 0x23, "sb_keep_alive": 0x12, "cb_ping": 0x32, "sb_pong": 0x20,
     "cb_login": 0x25, "cb_teleport": 0x3C, "sb_confirm_teleport": 0x00, "cb_disconnect": 0x1A,
     "cb_plugin_message": 0x17, "sb_plugin_message": 0x0D, "cb_player_info": 0x3A,
     "cb_player_remove": 0x39, "cb_chat_message": 0x35, "cb_system_chat": 0x64,
     "cb_profileless_chat": 0x1B},
    # 753-754: 1.16.4-1.16.5 (准确包ID，来自minecraft-data)
    {"min_proto": 753, "max_proto": 754, "sb_chat": 0x03, "sb_chat_command": None,
     "cb_keep_alive": 0x1F, "sb_keep_alive": 0x10, "cb_ping": None, "sb_pong": None,
     "cb_login": 0x24, "cb_teleport": 0x34, "sb_confirm_teleport": 0x00, "cb_disconnect": 0x19,
     "cb_plugin_message": 0x17, "sb_plugin_message": 0x0B, "cb_player_info": 0x32,
     "cb_chat_message": 0x0E, "cb_system_chat": None,
     "sb_player_position_look": 0x12, "sb_player_position": 0x11, "sb_player_movement": 0x14},
    # 340 (1.12.2): HOTFIX — Chat Message = 0x02（0x03 是 Client Status，搞混会导致服务器 ArrayIndexOutOfBounds）
    {"min_proto": 340, "max_proto": 340, "sb_chat": 0x02},
    # 旧版本兜底 sb_chat=0x03（自动表未覆盖的中间版本回退到340会得到错误的0x02）。
    # 但必须避开 1.13/1.13.1/1.13.2（393/401/404）：它们的 Chat Message 是 0x02，
    # 被 0x03（Client Status）覆盖会让服务器报 ArrayIndexOutOfBounds。
    # 这三个版本改由自动表提供正确值，所以把兜底区间拆成两段绕开它们。
    {"min_proto": 341, "max_proto": 392, "sb_chat": 0x03},
    {"min_proto": 405, "max_proto": 753, "sb_chat": 0x03},
]

_auto_tables = None
_auto_loaded = False
_auto_lock = threading.Lock()


def _load_auto_tables():
    """尝试加载 packets_auto.py 生成的协议表。
    双检锁：原实现先把 _auto_loaded 置 True 再加载，并发扫描时其他线程会在
    窗口期看到 _auto_loaded=True 但 _auto_tables 仍是 None，从而误判"该版本不可用"。"""
    global _auto_tables, _auto_loaded
    if _auto_loaded:
        return _auto_tables
    with _auto_lock:
        if _auto_loaded:          # 另一个线程已经加载完
            return _auto_tables
        _load_auto_tables_locked()
        _auto_loaded = True
        return _auto_tables


def _load_auto_tables_locked():
    """真正的加载逻辑，调用方必须已持有 _auto_lock。"""
    global _auto_tables
    try:
        from .packets_auto import PACKET_TABLES_AUTO
        auto_play = {}
        for proto_str, stages in PACKET_TABLES_AUTO.items():
            try:
                proto = int(proto_str)
            except (ValueError, TypeError):
                continue
            # 生成物里混进了 "1073741839" 这种伪造键（packets_auto.py:7933）。
            # 它会让"回退到 <= proto 的最大版本"逻辑把一个垃圾表当成正常版本使用，
            # 所以这里只接受合理范围内的协议号（MC 协议号现在是 340~776）。
            if not (1 <= proto <= 9999):
                print(f"[packets] 忽略非法协议号条目: {proto_str}")
                continue
            play = stages.get("play", {})
            sb = play.get("toServer", {})
            cb = play.get("toClient", {})
            auto_play[proto] = {
                "min_proto": proto, "max_proto": proto,
                "sb_chat": sb.get("chat", sb.get("chat_message")),
                "sb_chat_command": sb.get("chat_command", sb.get("chat_command_signed")),
                "cb_keep_alive": cb.get("keep_alive"),
                "sb_keep_alive": sb.get("keep_alive"),
                "cb_ping": cb.get("ping", cb.get("ping_pong")),
                "sb_pong": sb.get("pong", sb.get("ping_pong")),
                "cb_login": cb.get("login", cb.get("join_game")),
                "cb_disconnect": cb.get("kick_disconnect", cb.get("disconnect")),
                "cb_plugin_message": cb.get("custom_payload", cb.get("plugin_message")),
                "sb_plugin_message": sb.get("custom_payload", sb.get("plugin_message")),
                "cb_player_info": cb.get("player_info_update", cb.get("player_info")),
                "cb_player_remove": cb.get("player_info_remove", cb.get("player_remove")),
                "cb_profileless_chat": cb.get("profileless_chat"),
                "cb_chat_message": cb.get("player_chat", cb.get("chat_message", cb.get("chat"))),
                "cb_system_chat": cb.get("system_chat"),
                "cb_teleport": cb.get("position", cb.get("player_position", cb.get("synchronize_player_position"))),
                "sb_confirm_teleport": sb.get("teleport_confirm", sb.get("confirm_teleport", sb.get("confirm_synchronization"))),
                "sb_player_position_look": sb.get("position_look", sb.get("player_position_and_look")),
                "sb_player_position": sb.get("position", sb.get("player_position")),
                "sb_player_movement": sb.get("movement", sb.get("player_movement", sb.get("flying", sb.get("player")))),
                "sb_player_flying": sb.get("flying", sb.get("player")),
                "sb_client_info": sb.get("settings", sb.get("client_information")),
                "chat_format": get_chat_format(proto),
                "has_configuration": proto >= 764,
                "login_start_uuid": proto >= 760,
            }
        _auto_tables = auto_play
        print(f"[packets] 已加载自动生成协议表: {len(auto_play)} 个版本")
        # 健康检查：常用协议关键字段缺失时打警告
        _REQUIRED_FIELDS = ("sb_chat", "cb_keep_alive", "sb_keep_alive", "cb_disconnect", "cb_teleport")
        from .protocol import COMMON_PROTOCOLS
        _warned = 0
        for _p in COMMON_PROTOCOLS:
            _t = auto_play.get(_p)
            if not _t:
                continue
            _missing = [f for f in _REQUIRED_FIELDS if _t.get(f) is None]
            if _missing:
                print(f"[packets] 警告: 协议 {_p} 缺少关键字段 {_missing}，聊天/保活可能失败")
                _warned += 1
        if _warned:
            print(f"[packets] 共 {_warned} 个常用协议存在字段缺失，建议重新生成协议表")
    except ImportError:
        # packets_auto.py 不存在（可选扩展），使用手写表
        pass
    except Exception as e:
        print(f"[packets] 自动协议表加载失败，回退手写表: {e}")
    return _auto_tables


def get_play_packets(proto: int) -> dict | None:
    """获取指定协议版本的 Play 包 ID 表（手写表优先，自动表补全）"""
    # 先找手写表
    handwritten = None
    for table in _PLAY_TABLES:
        if table["min_proto"] <= proto <= table["max_proto"]:
            handwritten = dict(table)
            break
    # 再找自动表（精确匹配，找不到时用最近的低版本回退）
    auto = _load_auto_tables()
    auto_entry = None
    if auto:
        auto_entry = auto.get(proto)
        if auto_entry is None:
            # 回退：找小于等于proto的最大版本
            lower = [v for v in auto.keys() if v <= proto]
            if lower:
                fallback = max(lower)
                auto_entry = auto.get(fallback)
    # 合并：手写表非None值优先，自动表补全None
    result = None
    if handwritten and auto_entry:
        result = dict(auto_entry)
        for k, v in handwritten.items():
            if v is not None:
                result[k] = v
    elif handwritten:
        result = handwritten
    elif auto_entry:
        result = dict(auto_entry)
    if result is None:
        return None
    result["chat_format"] = get_chat_format(proto)
    result["has_configuration"] = proto >= 764
    result["login_start_uuid"] = proto >= 760
    # 完整性检查：缺少必需字段时返回None，避免bot静默用残缺表
    _REQUIRED = ("sb_chat", "cb_keep_alive", "sb_keep_alive", "cb_disconnect")
    _missing = [f for f in _REQUIRED if result.get(f) is None]
    # ≥764（1.20.2+）有Configuration阶段，teleport确认也是必需的
    if proto >= 764:
        _missing += [f for f in ("cb_teleport", "sb_confirm_teleport") if result.get(f) is None]
    if _missing:
        print(f"[packets] 协议 {proto} 缺少必需字段 {_missing}，该版本不可用")
        return None
    return result


def get_config_packets(proto: int) -> dict | None:
    """获取 Configuration 阶段包 ID（1.20.2+，以自动表为唯一真相源，手写常量仅兜底）"""
    if proto < 764:
        return None
    # 优先从自动表获取（唯一真相源）
    try:
        from .packets_auto import PACKET_TABLES_AUTO
        table = PACKET_TABLES_AUTO.get(str(proto), {})
        cfg = table.get("configuration", {})
        cb = cfg.get("toClient", {})
        sb = cfg.get("toServer", {})
        if cfg and cb.get("finish_configuration") is not None:
            result = {
                "cb_plugin_message": cb.get("custom_payload"),
                "cb_disconnect": cb.get("disconnect"),
                "cb_finish": cb.get("finish_configuration"),
                "cb_keep_alive": cb.get("keep_alive"),
                "cb_ping": cb.get("ping"),
                "cb_registry_data": cb.get("registry_data"),
                "cb_known_packs": cb.get("known_packs", cb.get("select_known_packs")),
                "cb_cookie_request": cb.get("cookie_request"),
                "sb_client_info": sb.get("settings", sb.get("client_information")),
                "sb_plugin_message": sb.get("custom_payload"),
                "sb_finish": sb.get("finish_configuration"),
                "sb_keep_alive": sb.get("keep_alive"),
                "sb_pong": sb.get("pong"),
                "sb_known_packs": sb.get("known_packs", sb.get("select_known_packs")),
                "sb_cookie_response": sb.get("cookie_response"),
            }
            return {k: v for k, v in result.items() if v is not None}
    except Exception as e:
        print(f"[packets] 自动表Configuration解析失败(proto={proto}): {e}")
    # 兜底：手写常量（仅当自动表无configuration段时使用）
    print(f"[packets] 警告: 协议 {proto} 自动表无Configuration段，回退手写常量（建议重新生成协议表）")
    from .protocol import (
        CONFIG_CB_DISCONNECT,
        CONFIG_CB_FINISH_CONFIGURATION,
        CONFIG_CB_KEEP_ALIVE,
        CONFIG_CB_KNOWN_PACKS,
        CONFIG_CB_PING,
        CONFIG_CB_PLUGIN_MESSAGE,
        CONFIG_SB_CLIENT_INFORMATION,
        CONFIG_SB_FINISH_CONFIGURATION,
        CONFIG_SB_KEEP_ALIVE,
        CONFIG_SB_KNOWN_PACKS,
        CONFIG_SB_PLUGIN_MESSAGE,
        CONFIG_SB_PONG,
    )
    # 1.20.2~1.20.4（764/765）还没有 Cookie Request 包，Configuration 阶段的
    # clientbound/serverbound 包 ID 比 766+ 整体小 1（已用自动表逐项核对过：
    # 764 的 custom_payload=0x00、finish=0x02，而 766+ 是 0x01、0x03）。
    # protocol.py 里的常量是按 766+ 写的，直接套用会让这两个版本配置阶段全部发错包。
    shift = 0 if proto >= 766 else -1

    def _c(value):
        return value + shift

    return {
        "cb_plugin_message": _c(CONFIG_CB_PLUGIN_MESSAGE),
        "cb_finish": _c(CONFIG_CB_FINISH_CONFIGURATION),
        "cb_keep_alive": _c(CONFIG_CB_KEEP_ALIVE),
        "cb_ping": _c(CONFIG_CB_PING),
        "cb_disconnect": _c(CONFIG_CB_DISCONNECT),
        "cb_known_packs": _c(CONFIG_CB_KNOWN_PACKS),
        "sb_client_info": _c(CONFIG_SB_CLIENT_INFORMATION),
        "sb_plugin_message": _c(CONFIG_SB_PLUGIN_MESSAGE),
        "sb_finish": _c(CONFIG_SB_FINISH_CONFIGURATION),
        "sb_keep_alive": _c(CONFIG_SB_KEEP_ALIVE),
        "sb_pong": _c(CONFIG_SB_PONG),
        "sb_known_packs": _c(CONFIG_SB_KNOWN_PACKS),
    }


def get_login_packets() -> dict:
    """获取 Login 阶段包 ID（通用）"""
    return {
        "sb_start": 0x00,
        "cb_disconnect": 0x00,
        "cb_encryption": 0x01,
        "cb_success": 0x02,
        "cb_compress": 0x03,
        "cb_plugin_request": 0x04,
        "sb_plugin_response": 0x02,
        "sb_acknowledged": 0x03,
    }


def supported_protos() -> list:
    """返回所有支持的协议版本号。

    原实现只把每张手写表的 min/max 收进来，语义与函数名不符
    （例如 341-753 那段只返回 341 和 753 两个数）。现在以自动表的全部精确版本
    为主，再补上手写表的边界，去重排序。
    """
    protos = set()
    auto = _load_auto_tables()
    if auto:
        protos.update(auto.keys())
    for table in _PLAY_TABLES:
        protos.add(table["min_proto"])
        if table["max_proto"] < 9999:
            protos.add(table["max_proto"])
    return sorted(protos)
