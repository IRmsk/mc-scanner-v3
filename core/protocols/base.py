"""协议处理器基类 — 每个版本继承并实现自己的格式"""
from __future__ import annotations

import json
from typing import Optional


class ProtocolHandler:
    """版本协议处理器基类。子类只负责自己版本的包格式。"""

    protocol_version: int = 0
    version_name: str = "unknown"

    def __init__(self, bot):
        self.bot = bot

    # ---- 登录阶段 ----
    def login_start_payload(self, username: str, uuid: Optional[str] = None) -> bytes:
        """构造 Login Start 包 payload"""
        raise NotImplementedError

    # ---- 配置阶段 ----
    def do_configuration(self) -> bool:
        """处理 Configuration 阶段，返回是否成功"""
        return True

    # ---- 聊天发送 ----
    def send_chat_payload(self, message: str) -> bytes:
        """构造聊天消息包 payload"""
        raise NotImplementedError

    def send_command_payload(self, command: str) -> bytes:
        """构造命令包 payload（不含前导 /）"""
        raise NotImplementedError

    # ---- 聊天接收 ----
    def extract_chat_text(self, data: bytes, is_system: bool) -> str:
        """从聊天包提取纯文本"""
        return ""

    def extract_chat_sender(self, data: bytes) -> str:
        """从聊天包提取发送者名字"""
        return "未知玩家"

    # ---- Play 阶段包处理 ----
    def handle_play_packet(self, packet_id: int, data: bytes) -> bool:
        """处理一个 play 阶段包。返回 True 表示已处理，False 表示未识别。"""
        return False

    def parse_player_info(self, data: bytes) -> None:
        """解析 Player Info Update 包，更新 bot.player_list 和 player_callback。
        各版本按自己的格式覆盖。"""

    def get_client_info_extra(self) -> bytes:
        """Configuration 阶段 Client Information 包的版本特有额外字段。"""
        return b""

    # ===== 通用辅助方法（各版本共用，减少重复）=====

    @staticmethod
    def _parse_json_chat(json_str: str) -> str:
        """解析 JSON 聊天组件为纯文本（带翻译表）"""
        try:
            obj = json.loads(json_str)
            from ..bot import MCBot
            return MCBot._json_component_to_text(obj)
        except (json.JSONDecodeError, TypeError):
            return json_str

    def _sender_from_uuid(self, uuid_bytes: bytes) -> str:
        """从 UUID 字节查 player_list 获取玩家名，查不到返回空串"""
        try:
            import uuid as _uuid
            uuid_str = str(_uuid.UUID(bytes=uuid_bytes))
            # 匹配自己的UUID（离线模式offline_uuid）
            if getattr(self.bot, 'uuid', None) and uuid_str == str(self.bot.uuid):
                return self.bot.username
            return self.bot.player_list.get(uuid_str, "")
        except Exception:
            return ""

    def _sender_from_json(self, stream) -> str:
        """从聊天 JSON 的 chat.type.text.with[0] 提取 sender（player_list查不到时的fallback）。

        签名字段的布局各版本并不统一：老版本用 VarInt 长度前缀，
        1.19.3+ 的 Optional Signature 是"Bool + 固定 256 字节"。
        原来只按长度前缀解析，于是新版离线服（UUID 查不到、正是要走这个 fallback 的场景）
        永远解析失败。这里把剩余字节取出来，两种布局各试一次，
        只接受**能解出合法 chat.type.text JSON** 的结果；都失败就返回 ""，
        与原来的失败行为一致，不会带来新副作用。
        """
        try:
            data = getattr(stream, "data", None)
            if data is not None and hasattr(stream, "pos"):
                rest = data[stream.pos:]
                stream.pos = len(data)   # 原实现会消费流；保持一致，避免调用方拿到半截数据
            else:
                rest = stream.read()
            for fixed_sig in (False, True):
                name = self._sender_with_signature_layout(rest, fixed_sig)
                if name:
                    return name
        except Exception:
            pass
        return ""

    @staticmethod
    def _sender_with_signature_layout(rest: bytes, fixed_sig: bool) -> str:
        """按指定签名布局解析剩余字节，解不出 chat.type.text 就返回空串。"""
        try:
            from ..buffer import BytesStream, read_boolean_from_stream, read_string_from_stream, read_varint_from_stream
            s = BytesStream(rest)
            read_varint_from_stream(s)              # index
            if read_boolean_from_stream(s):         # hasSignature
                if fixed_sig:
                    s.read(256)                     # 1.19.3+ 的固定 256 字节签名
                else:
                    s.read(read_varint_from_stream(s))
            json_str = read_string_from_stream(s)
            obj = json.loads(json_str)
            if isinstance(obj, dict) and obj.get("translate") == "chat.type.text":
                with_args = obj.get("with", [])
                if with_args:
                    sender_obj = with_args[0]
                    if isinstance(sender_obj, dict):
                        return sender_obj.get("text", "") or str(sender_obj)
                    return str(sender_obj)
        except Exception:
            pass
        return ""
