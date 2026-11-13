"""1.19.1/1.19.2（协议 760）协议处理器，继承 761 仅覆盖差异"""
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
from .v761 import Handler as V761Handler


class Handler(V761Handler):
    protocol_version = 760
    version_name = "1.19.1/1.19.2"

    def login_start_payload(self, username: str, uuid=None) -> bytes:
        # 1.19.1/1.19.2: username + hasPlayerUUID(true) + UUID
        payload = write_string(username)
        payload += b'\x01' + write_uuid(uuid)
        return payload

    def send_chat_payload(self, message: str) -> bytes:
        # 1.19.1: message + timestamp + salt + hasSignature + signedPreview + previousMessages(数组)
        timestamp = int(time.time() * 1000)
        return (write_string(message[:256])
                + struct.pack(">q", timestamp)
                + struct.pack(">q", 0)
                + b'\x00'  # hasSignature=false
                + b'\x00'  # signedPreview=false
                + write_varint(0))  # previousMessages=空数组

    def send_command_payload(self, command: str) -> bytes:
        timestamp = int(time.time() * 1000)
        return (write_string(command[:256])
                + struct.pack(">q", timestamp)
                + struct.pack(">q", 0)
                + b'\x00'  # hasSignature=false
                + b'\x00'  # signedPreview=false
                + write_varint(0))  # previousMessages=空数组

    def extract_chat_text(self, data: bytes, is_system: bool) -> str:
        try:
            stream = BytesStream(data)
            if is_system:
                json_str = read_string_from_stream(stream)
            else:
                stream.read(16)  # sender UUID
                read_varint_from_stream(stream)  # index (varint, 不是1字节)
                if read_boolean_from_stream(stream):
                    slen = read_varint_from_stream(stream)
                    stream.read(slen)
                json_str = read_string_from_stream(stream)
            return self._parse_json_chat(json_str)
        except Exception:
            return ""

    def parse_player_info(self, data: bytes) -> None:
        """751-760 Player Info：枚举值 Add/GameMode/Latency/DisplayName/Remove，760多RemoteChatSession"""
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
                    read_varint_from_stream(stream)
                    read_varint_from_stream(stream)
                    if read_boolean_from_stream(stream): read_string_from_stream(stream)
                    if self.bot.protocol_version >= 760:
                        if read_boolean_from_stream(stream):
                            stream.read(16); stream.read(8)
                            klen = read_varint_from_stream(stream); stream.read(klen)
                            slen = read_varint_from_stream(stream); stream.read(slen)
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
