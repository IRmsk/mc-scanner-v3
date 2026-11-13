"""协议处理器工厂 — 根据协议版本号返回对应版本的处理器"""
from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# 已知最大协议号，超过此值可能是未来版本，格式可能不兼容
_KNOWN_MAX_PROTOCOL = 776
_warned_versions = set()


def get_protocol_handler(bot) -> Optional[object]:
    """根据 bot.protocol_version 返回对应版本的处理器"""
    proto = bot.protocol_version
    if proto is None:
        return None

    # 未来版本警告：只打一次
    if proto > _KNOWN_MAX_PROTOCOL and proto not in _warned_versions:
        _warned_versions.add(proto)
        logger.warning(
            f"协议版本 {proto} 超过已知最大版本 {_KNOWN_MAX_PROTOCOL}，"
            f"将回退使用 v776 处理器，聊天/命令格式可能不兼容"
        )

    if proto >= 776:
        from .v776 import Handler
    elif proto >= 775:
        from .v775 import Handler
    elif proto >= 774:
        from .v774 import Handler
    elif proto >= 766:
        from .v766 import Handler
    elif proto >= 761:
        from .v761 import Handler
    elif proto >= 760:
        from .v760 import Handler
    elif proto >= 759:
        from .v759 import Handler
    elif proto >= 751:
        from .v751 import Handler
    elif proto >= 735:
        from .v735 import Handler
    else:
        from .v340 import Handler

    return Handler(bot)
