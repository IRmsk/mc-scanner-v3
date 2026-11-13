# -*- coding: utf-8 -*-
"""
异步 SLP 探测 + 认证检测。
用 asyncio 实现 MC 协议握手，比同步 socket 快 3-10 倍。
复用 core/buffer.py 的 VarInt 编解码和 core/protocol.py 的协议号。
可选 pysimdjson 加速 JSON 解析。
"""
import asyncio
import atexit
import concurrent.futures
import json
import threading
import time

from core.buffer import read_varint, write_varint
from core.probe import _motd_text, detect_core_type, extract_forge_channels, extract_mods
from core.protocol import COMMON_PROTOCOLS

# 全局认证检测线程池（避免每次调用创建/销毁）
_AUTH_EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=100, thread_name_prefix="auth-probe")


def _shutdown_executor():
    """程序退出时关闭全局线程池"""
    try:
        _AUTH_EXECUTOR.shutdown(wait=False, cancel_futures=True)
    except Exception:
        pass


atexit.register(_shutdown_executor)

try:
    import simdjson
    _HAS_SIMDJSON = True
    _parser_local = threading.local()
except Exception:
    # simdjson 未安装或加载失败时回退标准库，
    # 避免健康监控线程等在无 simdjson 环境下整轮崩溃导致"监控扫不上"
    _HAS_SIMDJSON = False


def _get_parser():
    """每线程一个 simdjson.Parser。

    旧实现是模块级共享 Parser，而 web 每个扫描线程各自 asyncio.run，
    pysimdjson 的 Parser 并非线程安全，共享会解析错乱/崩溃。
    """
    parser = getattr(_parser_local, "parser", None)
    if parser is None:
        parser = simdjson.Parser()
        _parser_local.parser = parser
    return parser


def _parse_json(data: bytes):
    """解析 JSON，优先用 simdjson，回退标准库。"""
    if _HAS_SIMDJSON:
        try:
            return _get_parser().parse(data).as_dict()
        except Exception:
            pass
    try:
        return json.loads(data)
    except Exception:
        return None


async def _recv_exact(reader: asyncio.StreamReader, n: int) -> bytes:
    """精确读取 n 字节。"""
    data = b""
    while len(data) < n:
        chunk = await reader.read(n - len(data))
        if not chunk:
            break
        data += chunk
    return data


async def _recv_packet(reader: asyncio.StreamReader):
    """读取一个 MC 数据包（长度前缀）。"""
    # 读取包长度（VarInt）
    length_bytes = b""
    while True:
        b = await _recv_exact(reader, 1)
        if not b:
            return None, None
        length_bytes += b
        if not (b[0] & 0x80):
            break
        if len(length_bytes) > 5:
            return None, None
    try:
        length, _ = read_varint(length_bytes, 0)
    except Exception:
        return None, None
    if length <= 0 or length > 4 * 1024 * 1024:
        return None, None
    payload = await _recv_exact(reader, length)
    if len(payload) < length:
        return None, None
    # 解析包 ID
    try:
        packet_id, offset = read_varint(payload, 0)
    except Exception:
        return None, None
    return packet_id, payload[offset:]


def _build_handshake(host: str, port: int, proto: int) -> bytes:
    """构建 Handshake 包。"""
    data = write_varint(0x00)  # Packet ID
    data += write_varint(proto)  # Protocol Version
    # Server Address (string)
    host_bytes = host.encode("utf-8")
    data += write_varint(len(host_bytes)) + host_bytes
    data += port.to_bytes(2, "big")  # Server Port
    data += write_varint(1)  # Next State: Status (1)
    return write_varint(len(data)) + data


def _build_status_request() -> bytes:
    """构建 Status Request 包。"""
    data = write_varint(0x00)
    return write_varint(len(data)) + data


def _build_ping(payload: int) -> bytes:
    """构建 Ping 包。"""
    data = write_varint(0x01) + payload.to_bytes(8, "big", signed=True)
    return write_varint(len(data)) + data


# 单主机整体探测预算倍数（见 async_slp_probe 说明）
_PROBE_BUDGET_FACTOR = 3.0


async def async_slp_probe(ip: str, port: int, timeout: float = 4.0, fast=False) -> dict:
    """
    异步 SLP 探测。
    fast=True: 只试自动版本，不遍历所有协议（健康监控用，快但可能漏老版本服）

    整机预算：非 fast 模式最多 _PROBE_BUDGET_FACTOR 个 timeout，
    避免旧实现"每个协议各吃满 timeout（20 个协议 = 20×timeout）"拖垮整轮扫描。
    """
    last_error = ""
    protos = (-1,) if fast else (-1,) + COMMON_PROTOCOLS
    deadline = time.monotonic() + timeout * (1.0 if fast else _PROBE_BUDGET_FACTOR)
    for proto in protos:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            last_error = last_error or "probe budget exhausted"
            break
        attempt_timeout = min(timeout, remaining)
        writer = None
        try:
            start = time.time()
            from scanner.async_portscan import _open_connection
            reader, writer = await _open_connection(ip, port, attempt_timeout)

            # 发送 Handshake + Status Request
            writer.write(_build_handshake(ip, port, proto))
            writer.write(_build_status_request())
            # drain 必须限时：恶意端不读数据填满发送窗口时会永久挂起
            await asyncio.wait_for(writer.drain(), timeout=attempt_timeout)

            # 接收 Status Response
            packet_id, payload = await asyncio.wait_for(
                _recv_packet(reader), timeout=attempt_timeout)

            if packet_id != 0x00 or not payload:
                last_error = f"bad packet id={packet_id}"
                continue

            # 解析 JSON 长度前缀
            try:
                json_len, offset = read_varint(payload, 0)
                json_data = payload[offset:offset + json_len]
            except Exception:
                json_data = payload

            info = _parse_json(json_data)
            if not info:
                # Hypixel 等服务器可能截断 JSON，尝试修复
                try:
                    raw = json_data.decode("utf-8", errors="replace")
                    # 找到最后一个完整的 }
                    idx = raw.rfind("}")
                    if idx > 0:
                        info = json.loads(raw[:idx + 1])
                except Exception:
                    pass

            if not info:
                last_error = "json parse failed"
                continue

            # Ping 测量
            ping_ms = None
            try:
                ping_payload = int(time.time() * 1000) & 0xFFFFFFFFFFFFFFFF
                writer.write(_build_ping(ping_payload))
                await asyncio.wait_for(writer.drain(), timeout=attempt_timeout)
                pong_id, _ = await asyncio.wait_for(
                    _recv_packet(reader), timeout=min(2.0, attempt_timeout))
                if pong_id == 0x01:
                    ping_ms = int((time.time() - start) * 1000)
            except Exception:
                ping_ms = int((time.time() - start) * 1000)

            # 远端字段类型不可信（见 banner.py 同类问题），逐层 isinstance 兜底
            version = info.get("version", {})
            if isinstance(version, dict):
                ver_name = version.get("name", "")
                proto = version.get("protocol", 0)
            else:
                # 少数服务端把 version 直接写成字符串/数字，当作版本名保留
                ver_name, proto = version, 0
            players = info.get("players", {})
            if not isinstance(players, dict):
                players = {}
            sample = players.get("sample", [])
            if not isinstance(sample, list):
                sample = []
            if ver_name is None:
                ver_name = ""
            if not isinstance(ver_name, str):
                ver_name = str(ver_name)

            return {
                "state": "up",
                "version": ver_name,
                "proto": proto,
                "motd": _motd_text(info.get("description", "")),
                "online": players.get("online", 0),
                "max": players.get("max", 0),
                "sample": sample,
                "favicon": info.get("favicon", ""),
                "ping_ms": ping_ms,
                "core_type": detect_core_type(ver_name, info),
                "mods": extract_mods(info),
                "forge_channels": extract_forge_channels(info),
                "_raw": info,
            }

        except asyncio.TimeoutError:
            last_error = "timeout"
            continue
        except (ConnectionRefusedError, OSError) as e:
            last_error = str(e)[:80]
            continue
        except Exception as e:
            last_error = str(e)[:80]
            continue
        finally:
            # 超时/异常分支也必须关闭 writer：transport 被 selector 引用，
            # StreamWriter 出作用域不会释放 fd（实测单主机 20 次协议尝试泄漏 20 个 fd）
            if writer is not None:
                try:
                    writer.close()
                    await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
                except Exception:
                    pass

    return {"state": "offline", "error": last_error}


async def async_auth_probe(ip: str, port: int, proto: int = 0,
                           timeout: float = 4.0) -> dict:
    """
    异步认证模式检测（简化版，实际登录握手）。
    返回 state: online/cracked/whitelist/rejected/offline/error
    """
    from core.probe import auth_probe

    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(
        _AUTH_EXECUTOR, lambda: auth_probe(ip, port, reported_proto=proto, timeout=timeout))
    # 统一返回格式：auth_mode 字段兼容旧代码
    if isinstance(result, dict) and 'state' in result and 'auth_mode' not in result:
        result['auth_mode'] = result['state']
    return result


def has_simdjson() -> bool:
    return _HAS_SIMDJSON
