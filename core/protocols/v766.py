"""1.20.5-1.21.10（协议 766-773）协议处理器"""
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
    protocol_version = 766
    version_name = "1.20.5-1.21.10"

    def login_start_payload(self, username: str, uuid=None) -> bytes:
        return write_string(username) + write_uuid(uuid)

    def send_chat_payload(self, message: str) -> bytes:
        timestamp = int(time.time() * 1000)
        payload = (write_string(message[:256])
                   + struct.pack(">q", timestamp)
                   + struct.pack(">q", 0)
                   + b'\x00'           # hasSignature=false
                   + write_varint(0)   # messageCount=0
                   + b"\x00\x00\x00")  # acknowledged: FixedBitSet固定3字节（1.20.5+无长度前缀）
        # 1.21.5+ (769+) 增加 checksum 字节，无签名消息=1
        if getattr(self.bot, 'protocol_version', 766) >= 769:
            payload += b'\x01'
        return payload

    def send_command_payload(self, command: str) -> bytes:
        return write_string(command[:256])

    def get_client_info_extra(self) -> bytes:
        """1.21.4+ (769+) Client Information 增加 particleStatus"""
        if getattr(self.bot, 'protocol_version', 766) >= 769:
            return write_varint(0)
        return b""

    def extract_chat_text(self, data: bytes, is_system: bool) -> str:
        try:
            stream = BytesStream(data)
            if is_system:
                # 先尝试NBT格式，失败则回退到JSON（需重置stream位置）
                saved_pos = stream.pos
                try:
                    txt = self.bot._nbt_component_to_text(stream)
                    if txt:
                        return txt
                except Exception:
                    pass
                stream.pos = saved_pos  # 回退，NBT解析失败时可能消耗了字节
                json_str = read_string_from_stream(stream)
            else:
                proto = getattr(self.bot, 'protocol_version', 766)
                if proto >= 768:
                    # 1.21.2+ (768+): globalIndex(varint) + senderUuid(16) + index(varint) + signature(option: bool+256固定字节) + plainMessage(string)
                    read_varint_from_stream(stream)  # globalIndex
                    stream.read(16)  # senderUuid
                    read_varint_from_stream(stream)  # index
                    if read_boolean_from_stream(stream):
                        stream.read(256)  # 固定256字节签名
                else:
                    # 旧格式: senderUuid(16) + index(varint) + signature(option: bool+varint长度)
                    stream.read(16)
                    read_varint_from_stream(stream)
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
            proto = getattr(self.bot, 'protocol_version', 766)
            if proto >= 768:
                read_varint_from_stream(stream)  # globalIndex (1.21.2+)
            uuid_bytes = stream.read(16)
            name = self._sender_from_uuid(uuid_bytes)
            if name:
                return name
            name = self._sender_from_json(stream)
            return name or "未知玩家"
        except Exception:
            return "未知玩家"

    def parse_player_info(self, data: bytes) -> None:
        """1.20.5+ Player Info Update：位掩码 add/init_chat/gamemode/listed/latency/display"""
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
                if actions & 0x08:
                    listed = read_boolean_from_stream(stream)
                    if not listed:
                        old = self.bot.player_list.pop(uid, None)
                        if old is not None and self.bot.player_callback:
                            try: self.bot.player_callback(old, "leave")
                            except Exception: pass
                if actions & 0x10: read_varint_from_stream(stream)
                if actions & 0x20:
                    if read_boolean_from_stream(stream): read_string_from_stream(stream)
        except Exception:
            pass
