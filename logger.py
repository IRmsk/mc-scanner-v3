# -*- coding: utf-8 -*-
"""
统一日志模块。
替换全项目 print()，支持控制台输出 + 自定义Handler（Web端实时推送日志）。
"""
import logging
import sys
from collections import deque
from typing import Optional

_LOGGER_NAME = "mcscanner"
_logger = None
_memory_handler: Optional["MemoryLogHandler"] = None


class MemoryLogHandler(logging.Handler):
    """内存日志Handler，保留最近N条日志，供Web端SSE推送。"""
    def __init__(self, capacity: int = 500):
        super().__init__()
        self.logs = deque(maxlen=capacity)
        self.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s",
                                             datefmt="%H:%M:%S"))

    def emit(self, record):
        try:
            msg = self.format(record)
            self.logs.append({
                "time": record.asctime if hasattr(record, 'asctime') else "",
                "level": record.levelname,
                "msg": msg,
            })
        except Exception:
            pass

    def get_recent(self, count: int = 100):
        return list(self.logs)[-count:]


def setup_logger(level: str = "INFO", with_memory: bool = True) -> logging.Logger:
    """初始化全局logger。重复调用返回同一实例。"""
    global _logger, _memory_handler
    if _logger is not None:
        return _logger

    logger = logging.getLogger(_LOGGER_NAME)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.propagate = False

    # 控制台输出
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s",
                                       datefmt="%H:%M:%S"))
    logger.addHandler(ch)

    # 内存日志（Web端用）
    if with_memory:
        _memory_handler = MemoryLogHandler(capacity=500)
        logger.addHandler(_memory_handler)

    _logger = logger
    return logger


def get_logger() -> logging.Logger:
    """获取全局logger，未初始化时自动初始化。"""
    if _logger is None:
        setup_logger()
    return _logger


def get_memory_handler() -> Optional[MemoryLogHandler]:
    """获取内存日志Handler，供Web端读取实时日志。"""
    return _memory_handler


# 便捷函数
def info(msg: str, *args, **kwargs):
    get_logger().info(msg, *args, **kwargs)


def warning(msg: str, *args, **kwargs):
    get_logger().warning(msg, *args, **kwargs)


def error(msg: str, *args, **kwargs):
    get_logger().error(msg, *args, **kwargs)


def exception(msg: str, *args, **kwargs):
    """在 except 块里用：自动带上异常堆栈，比只打一行 error 有用得多。"""
    get_logger().exception(msg, *args, **kwargs)


def debug(msg: str, *args, **kwargs):
    get_logger().debug(msg, *args, **kwargs)
