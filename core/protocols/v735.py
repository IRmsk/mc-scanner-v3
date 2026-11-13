"""1.16-1.16.1（协议 735-750）协议处理器
1.16 起聊天包增加 position(Byte) + sender UUID(16字节)
Player Info 仍用位掩码（1.16.2才改枚举值）"""
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
    protocol_version = 735
    version_name = "1.16-1.16.1"

    def login_start_payload(self, username: str, uuid=None) -> bytes:
        return write_string(username)

    def send_chat_payload(self, message: str) -> bytes:
        return write_string(message[:256])

    def send_command_payload(self, command: str) -> bytes:
        return write_string("/" + command[:255])

    def extract_chat_text(self, data: bytes, is_system: bool) -> str:
        """1.16+ 聊天包：message + position(Byte) + sender UUID(16)"""
        try:
            stream = BytesStream(data)
            json_str = read_string_from_stream(stream)
            stream.read(1)   # position
            stream.read(16)  # sender UUID
            return self._parse_json_chat(json_str)
        except Exception:
            return ""

    def extract_chat_sender(self, data: bytes) -> str:
        """从 sender UUID 查 player_list"""
        try:
            stream = BytesStream(data)
            read_string_from_stream(stream)
            stream.read(1)
            uuid_bytes = stream.read(16)
            name = self._sender_from_uuid(uuid_bytes)
            if name:
                return name
            # 离线服/插件服 UUID 查不到 → 回退从聊天 JSON with[0] 提取
            try:
                name = self._sender_from_json(stream)
            except Exception:
                name = ""
            return name or "未知玩家"
        except Exception:
            return "未知玩家"

    def parse_player_info(self, data: bytes) -> None:
        """1.16-1.16.1 Player Info：位掩码（同1.12.2格式）"""
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
