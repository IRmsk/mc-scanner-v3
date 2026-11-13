"""Minecraft 26.2（协议 776）协议处理器，继承 775
26.2 仅新增 chat-spam-threshold-seconds / command-spam-threshold-seconds 服务器属性，
包 ID 和聊天包格式与 26.1 完全相同"""
from __future__ import annotations

from .v775 import Handler as V775Handler


class Handler(V775Handler):
    protocol_version = 776
    version_name = "26.2"
