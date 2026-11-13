"""1.19（协议 759）协议处理器"""
from __future__ import annotations

import struct
import time

from ..buffer import BytesStream, read_boolean_from_stream, read_string_from_stream, write_string, write_uuid
from .base import ProtocolHandler


class Handler(ProtocolHandler):
    protocol_version = 759
    version_name = "1.19"

    def login_start_payload(self, username: str, uuid=None) -> bytes:
        payload = write_string(username)
        if uuid:
            payload += b'\x01' + write_uuid(uuid)  # hasPlayerUUID=true + UUID
        return payload

    def send_chat_payload(self, message: str) -> bytes:
        timestamp = int(time.time() * 1000)
        return (write_string(message[:256])
                + struct.pack(">q", timestamp)
                + struct.pack(">q", 0)
                + b'\x00')  # hasSignature=false（1.19无signedPreview）

    def send_command_payload(self, command: str) -> bytes:
        # 1.19 命令包格式同聊天包
        timestamp = int(time.time() * 1000)
        return (write_string(command[:256])
                + struct.pack(">q", timestamp)
                + struct.pack(">q", 0)
                + b'\x00')  # hasSignature=false

    def extract_chat_text(self, data: bytes, is_system: bool) -> str:
        try:
            stream = BytesStream(data)
            if is_system:
                json_str = read_string_from_stream(stream)
            else:
                stream.read(16)  # UUID
                read_string_from_stream(stream)  # nickname
                stream.read(8)  # timestamp
                stream.read(8)  # salt
                if read_boolean_from_stream(stream):
                    stream.read(256)  # signature
                json_str = read_string_from_stream(stream)
            return self._parse_json_chat(json_str)
        except Exception:
            return ""

    def extract_chat_sender(self, data: bytes) -> str:
        try:
            stream = BytesStream(data)
            stream.read(16)  # UUID
            nick_json = read_string_from_stream(stream)
            name = self._parse_json_chat(nick_json)
            if name:
                return name
            # nick 组件为空 → 回退从聊天 JSON with[0] 提取
            try:
                name = self._sender_from_json(stream)
            except Exception:
                name = ""
            return name or "未知玩家"
        except Exception:
            return "未知玩家"

    def parse_player_info(self, data: bytes) -> None:
        """759 在 751-760 区间，player_info 格式同 v760（枚举值，无RemoteChatSession）"""
        from .v760 import Handler as V760Handler
        V760Handler.parse_player_info(self, data)
