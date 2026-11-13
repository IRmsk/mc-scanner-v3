"""1.12.2-1.15.2（协议 340-578）协议处理器
聊天包只有 message 字段（无 position/sender UUID）
Player Info 用位掩码：add/gamemode/latency/display/remove"""
from __future__ import annotations

from ..buffer import (
    BytesStream,
    read_boolean_from_stream,
    read_string_from_stream,
    read_uuid_from_stream,
    read_varint_from_stream,
    write_string,
)
from .base import ProtocolHandler


class Handler(ProtocolHandler):
    protocol_version = 340
    version_name = "1.12.2-1.15.2"

    def login_start_payload(self, username: str, uuid=None) -> bytes:
        return write_string(username)

    def send_chat_payload(self, message: str) -> bytes:
        return write_string(message[:256])

    def send_command_payload(self, command: str) -> bytes:
        return write_string("/" + command[:255])

    def extract_chat_text(self, data: bytes, is_system: bool) -> str:
        """1.12.2-1.15.2 聊天包只有 message 字段（JSON字符串）"""
        try:
            stream = BytesStream(data)
            json_str = read_string_from_stream(stream)
            return self._parse_json_chat(json_str)
        except Exception:
            return ""

    def extract_chat_sender(self, data: bytes) -> str:
        """1.12.2-1.15.2 无 sender UUID，sender 嵌在 text 的 <> 前缀中，由 bot 统一处理"""
        return "未知玩家"

    def parse_player_info(self, data: bytes) -> None:
        """旧版 Player Info：位掩码 add(0x01) gamemode(0x02) latency(0x04) display(0x08) remove(0x10)"""
        try:
            stream = BytesStream(data)
            actions = read_varint_from_stream(stream)
            count = read_varint_from_stream(stream)
            for _ in range(count):
                uid = str(read_uuid_from_stream(stream))
                if actions & 0x01:
                    name = read_string_from_stream(stream)
                    is_new = uid not in self.bot.player_list
                    self.bot.player_list[uid] = name
                    props = read_varint_from_stream(stream)
                    for _ in range(props):
                        read_string_from_stream(stream); read_string_from_stream(stream)
                        if read_boolean_from_stream(stream): read_string_from_stream(stream)
                    if is_new and self.bot.player_callback:
                        try: self.bot.player_callback(name, "join")
                        except Exception: pass
                if actions & 0x02: read_varint_from_stream(stream)
                if actions & 0x04: read_varint_from_stream(stream)
                if actions & 0x08:
                    if read_boolean_from_stream(stream): read_string_from_stream(stream)
                if actions & 0x10:
                    old = self.bot.player_list.pop(uid, None)
                    if old is not None and self.bot.player_callback:
                        try: self.bot.player_callback(old, "leave")
                        except Exception: pass
        except Exception:
            pass
