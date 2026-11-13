"""1.16.2-1.18.2（协议 751-758）协议处理器
聊天包：message + position(Byte) + sender UUID(16)
Player Info 改为枚举值：0=Add 1=GameMode 2=Latency 3=DisplayName 4=Remove"""
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
    protocol_version = 751
    version_name = "1.16.2-1.18.2"

    def login_start_payload(self, username: str, uuid=None) -> bytes:
        return write_string(username)

    def send_chat_payload(self, message: str) -> bytes:
        return write_string(message[:256])

    def send_command_payload(self, command: str) -> bytes:
        return write_string("/" + command[:255])

    def extract_chat_text(self, data: bytes, is_system: bool) -> str:
        """1.16.2+ 聊天包：message + position + sender UUID"""
        try:
            stream = BytesStream(data)
            json_str = read_string_from_stream(stream)
            stream.read(1)
            stream.read(16)
            return self._parse_json_chat(json_str)
        except Exception:
            return ""

    def extract_chat_sender(self, data: bytes) -> str:
        """从 sender UUID 查 player_list，全零UUID为系统消息"""
        try:
            stream = BytesStream(data)
            read_string_from_stream(stream)
            stream.read(1)
            uuid_bytes = stream.read(16)
            # 全零UUID = 系统消息
            if uuid_bytes == b'\x00' * 16:
                return "系统"
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
        """1.16.2+ Player Info：枚举值 Add/GameMode/Latency/DisplayName/Remove"""
        try:
            stream = BytesStream(data)
            actions = read_varint_from_stream(stream)
            count = read_varint_from_stream(stream)
            for _ in range(count):
                uid = str(read_uuid_from_stream(stream))
                if actions == 0:
                    name = read_string_from_stream(stream)
                    is_new = uid not in self.bot.player_list
                    self.bot.player_list[uid] = name
                    props = read_varint_from_stream(stream)
                    for _ in range(props):
                        read_string_from_stream(stream); read_string_from_stream(stream)
                        if read_boolean_from_stream(stream): read_string_from_stream(stream)
                    read_varint_from_stream(stream)  # gamemode
                    read_varint_from_stream(stream)  # ping
                    if read_boolean_from_stream(stream): read_string_from_stream(stream)  # displayName
                    if is_new and self.bot.player_callback:
                        try: self.bot.player_callback(name, "join")
                        except Exception: pass
                elif actions == 1:
                    read_varint_from_stream(stream)
                elif actions == 2:
                    read_varint_from_stream(stream)
                elif actions == 3:
                    if read_boolean_from_stream(stream): read_string_from_stream(stream)
                elif actions == 4:
                    old = self.bot.player_list.pop(uid, None)
                    if old is not None and self.bot.player_callback:
                        try: self.bot.player_callback(old, "leave")
                        except Exception: pass
        except Exception:
            pass
