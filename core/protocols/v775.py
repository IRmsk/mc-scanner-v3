"""Minecraft 26.1（协议 775）协议处理器，继承 774
26.1 变化：
- PLAYER_CHAT 包开头新增 Global Index (VarInt)，然后才是 Sender UUID
- 聊天包 hasSignature+messageCount → signature(option)+offset
- 无签名时编码结果与 774 相同
- Player Info Update：action 由 varint 改为 u8 bitflags，并新增 update_hat / update_list_order 两位；
  update_listed 由 bool 改为 varint（详见 parse_player_info）"""
from __future__ import annotations

from ..buffer import (
    BytesStream,
    read_boolean_from_stream,
    read_string_from_stream,
    read_uuid_from_stream,
    read_varint_from_stream,
)
from .v774 import Handler as V774Handler


class Handler(V774Handler):
    protocol_version = 775
    version_name = "26.1"

    def parse_player_info(self, data: bytes) -> None:
        """26.1 Player Info Update（官方 minecraft-data 结构）：
        u8 bitflags action：
          0x01 add_player / 0x02 initialize_chat / 0x04 update_game_mode /
          0x08 update_listed / 0x10 update_latency / 0x20 update_display_name /
          0x40 update_hat / 0x80 update_list_order
        每条玩家：UUID + 按 action 位读字段（1.20.5 的 varint action 与 bool listed 在此版本已不同）"""
        try:
            from ..nbt import nbt_skip_value
            stream = BytesStream(data)
            actions = stream.read(1)[0]  # u8 bitflags
            count = read_varint_from_stream(stream)
            for _ in range(count):
                uid = str(read_uuid_from_stream(stream))
                if actions & 0x01:  # add_player: name + properties
                    name = read_string_from_stream(stream)
                    is_new = uid not in self.bot.player_list
                    self.bot.player_list[uid] = name
                    props = read_varint_from_stream(stream)
                    for _ in range(props):
                        read_string_from_stream(stream)
                        read_string_from_stream(stream)
                        if read_boolean_from_stream(stream):
                            read_string_from_stream(stream)
                    if is_new and self.bot.player_callback:
                        try:
                            self.bot.player_callback(name, "join")
                        except Exception:
                            pass
                if actions & 0x02:  # initialize_chat: option(uuid + expire i64 + keyBuffer + sigBuffer)
                    if read_boolean_from_stream(stream):
                        stream.read(16)
                        stream.read(8)
                        klen = read_varint_from_stream(stream)
                        stream.read(klen)
                        slen = read_varint_from_stream(stream)
                        stream.read(slen)
                if actions & 0x04:  # update_game_mode: varint
                    read_varint_from_stream(stream)
                if actions & 0x08:  # update_listed: varint（26.1 由 bool 改 varint）
                    if not read_varint_from_stream(stream):
                        old = self.bot.player_list.pop(uid, None)
                        if old is not None and self.bot.player_callback:
                            try:
                                self.bot.player_callback(old, "leave")
                            except Exception:
                                pass
                if actions & 0x10:  # update_latency: varint
                    read_varint_from_stream(stream)
                if actions & 0x20:  # update_display_name: option(anonymousNbt)
                    if read_boolean_from_stream(stream):
                        raw = stream.read(1)
                        if raw:
                            nbt_skip_value(stream, raw[0])
                if actions & 0x40:  # update_hat: bool
                    read_boolean_from_stream(stream)
                if actions & 0x80:  # update_list_order: varint
                    read_varint_from_stream(stream)
        except Exception:
            pass

    def extract_chat_text(self, data: bytes, is_system: bool) -> str:
        """26.1 PLAYER_CHAT: Global Index(VarInt) + Sender UUID + Index + Signature + Message + ..."""
        try:
            stream = BytesStream(data)
            if is_system:
                saved_pos = stream.pos
                try:
                    txt = self.bot._nbt_component_to_text(stream)
                    if txt:
                        return txt
                except Exception:
                    pass
                stream.pos = saved_pos
                return read_string_from_stream(stream)
            # 玩家聊天：跳过 Global Index
            read_varint_from_stream(stream)
            stream.read(16)  # Sender UUID
            read_varint_from_stream(stream)  # Index
            # signature: option<buffer(256)>
            if read_boolean_from_stream(stream):
                stream.read(256)
            json_str = read_string_from_stream(stream)
            return self._parse_json_chat(json_str)
        except Exception:
            return ""

    def extract_chat_sender(self, data: bytes) -> str:
        """26.1 PLAYER_CHAT: 先跳过 Global Index，再读 Sender UUID；
        UUID 查不到（离线服/插件服常见）时回退从聊天 JSON with[0] 提取"""
        try:
            stream = BytesStream(data)
            read_varint_from_stream(stream)  # Global Index
            uuid_bytes = stream.read(16)
            name = self._sender_from_uuid(uuid_bytes)
            if name:
                return name
            # UUID 查不到 → 尝试从聊天 JSON with[0] 提取 sender
            try:
                name = self._sender_from_json(stream)
            except Exception:
                name = ""
            return name or "未知玩家"
        except Exception:
            return "未知玩家"
