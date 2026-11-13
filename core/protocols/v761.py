"""1.19.3-1.20.4（协议 761-765）协议处理器
761-763: Login Start 有 hasPlayerUUID 字段
764-765: Login Start 直接 UUID，有 Configuration 阶段"""
from __future__ import annotations

import struct
import time

from ..buffer import (
    BytesStream,
    read_boolean_from_stream,
    read_string_from_stream,
    read_uuid_from_stream,
    read_varint_from_stream,
    write_string,
    write_uuid,
    write_varint,
)
from .base import ProtocolHandler


class Handler(ProtocolHandler):
    protocol_version = 761
    version_name = "1.19.3-1.20.4"

    def login_start_payload(self, username: str, uuid=None) -> bytes:
        payload = write_string(username)
        if self.bot.protocol_version >= 764:
            payload += write_uuid(uuid)
        else:
            payload += b'\x01' + write_uuid(uuid)
        return payload

    def send_chat_payload(self, message: str) -> bytes:
        timestamp = int(time.time() * 1000)
        return (write_string(message[:256])
                + struct.pack(">q", timestamp)
                + struct.pack(">q", 0)
                + b'\x00'           # hasSignature=false
                + write_varint(0)   # messageCount=0
                + b"\x00\x00\x00")  # acknowledged: 固定3字节BitSet

    def send_command_payload(self, command: str) -> bytes:
        timestamp = int(time.time() * 1000)
        return (write_string(command[:256])
                + struct.pack(">q", timestamp)
                + struct.pack(">q", 0)
                + b'\x00'           # hasSignature=false
                + write_varint(0)   # messageCount=0
                + b"\x00\x00\x00")  # acknowledged: 固定3字节BitSet

    def extract_chat_text(self, data: bytes, is_system: bool) -> str:
        try:
            stream = BytesStream(data)
            if is_system:
                json_str = read_string_from_stream(stream)
            else:
                stream.read(16)  # senderUuid
                read_varint_from_stream(stream)  # index
                if read_boolean_from_stream(stream):
                    sig_len = read_varint_from_stream(stream)
                    stream.read(sig_len)
                json_str = read_string_from_stream(stream)
            return self._parse_json_chat(json_str)
        except Exception:
            return ""

    def extract_chat_sender(self, data: bytes) -> str:
        try:
            stream = BytesStream(data)
            uuid_bytes = stream.read(16)
            name = self._sender_from_uuid(uuid_bytes)
            if name:
                return name
            name = self._sender_from_json(stream)
            return name or "未知玩家"
        except Exception:
            return "未知玩家"

    def parse_player_info(self, data: bytes) -> None:
        """1.19.3+ Player Info：位掩码 add/init_chat/gamemode/listed/latency/display"""
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
                if actions & 0x02:
                    if read_boolean_from_stream(stream):
                        stream.read(16); stream.read(8)
                        klen = read_varint_from_stream(stream); stream.read(klen)
                if actions & 0x04: read_varint_from_stream(stream)
                if actions & 0x08: read_varint_from_stream(stream)
                if actions & 0x10: read_varint_from_stream(stream)
                if actions & 0x20:
                    if read_boolean_from_stream(stream): read_string_from_stream(stream)
        except Exception:
            pass
