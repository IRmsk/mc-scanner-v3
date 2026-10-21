# -*- coding: utf-8 -*-
"""Web 面板共享状态。"""
import threading
from datetime import datetime
import config
import logger

scan_stop_event = threading.Event()
scan_lock = threading.Lock()
task_counter = 0

# 任务队列：支持多任务排队，不互相覆盖
scan_tasks = {}          # task_id -> task_state dict
scan_queue = []          # 排队中的 task_id 列表
current_task_id = None   # 当前正在运行的 task_id

# 同时最多可运行的扫描任务数（>1 时多个扫描任务可并发执行，适合多网段并行扫描）
# 注意：并发扫描会成倍增加网络请求与被扫方的告警风险，按需调大
max_concurrent_scans = max(1, int(config.get("max_concurrent_scans", 2)))

scan_state = {
    "running": False,
    "progress": 0,
    "total": 0,
    "scanned": 0,
    "open_count": 0,
    "results": [],
    "logs": [],
    "start_time": None,
    "task_id": None,
    "history": [],
}


def new_task_state(task_id, targets_count=0, scan_type="manual"):
    """创建一个新的扫描任务状态"""
    return {
        "task_id": task_id,
        "running": False,
        "status": "queued",  # queued / running / done / stopped / error
        "progress": 0,
        "total": targets_count,
        "scanned": 0,
        "open_count": 0,
        "results": [],
        "logs": [],
        "start_time": None,
        "end_time": None,
        "scan_type": scan_type,
        "stop_event": threading.Event(),
    }


def log_scan(msg: str, task_id=None):
    logger.info(msg)
    entry = {"time": datetime.now().strftime("%H:%M:%S"), "msg": msg}
    with scan_lock:
        # 写入当前活动任务的日志
        if task_id and task_id in scan_tasks:
            scan_tasks[task_id]["logs"].append(entry)
            if len(scan_tasks[task_id]["logs"]) > 500:
                scan_tasks[task_id]["logs"] = scan_tasks[task_id]["logs"][-500:]
        # 兼容旧接口：写入全局scan_state
        scan_state["logs"].append(entry)
        if len(scan_state["logs"]) > 500:
            scan_state["logs"] = scan_state["logs"][-500:]

observer_sessions = {}
observer_lock = threading.Lock()

health_monitor = {
    "running": False,
    "once_running": False,
    "thread": None,
    "stop_event": threading.Event(),
    "interval": max(60, int(config.get("health_interval", 300))),
    "events": [],
    "last_check": None,
    "status": {},
}

# 健康监控状态锁：监控线程与 Web 请求线程共享 status/events/last_players，
# 之前两边都无锁（监控线程 del、请求线程遍历）会抛 RuntimeError 并返回 500。
health_lock = threading.RLock()

_ai_bots = {}
_ai_bot_seq = 0
_ai_bot_lock = threading.Lock()


def next_ai_bot_seq() -> int:
    """线程安全地分配AI会话序号。

    原实现各路由直接 state._ai_bot_seq += 1，并发请求会拿到同一个 id，
    同名会话互相覆盖，旧会话失控且无法 stop。
    """
    global _ai_bot_seq
    with _ai_bot_lock:
        _ai_bot_seq += 1
        return _ai_bot_seq

# 全局安全开关：只读模式下禁止危险操作（警告/进服/扫描）
read_only_mode = False


def is_read_only():
    return read_only_mode or config.get("read_only_mode", False)


def set_read_only(enabled: bool):
    global read_only_mode
    read_only_mode = enabled


def capability_enabled(cap: str) -> bool:
    """能力分级检查：高风险能力默认关闭，需在config.capabilities显式开启。
    cap: 'scan' / 'login_interact' / 'rcon_commands'"""
    caps = config.get("capabilities", {})
    if not isinstance(caps, dict):
        return False
    # scan：基础扫描能力（默认 True，允许扫自己的服务器）
    # public_scan：公网随机扫描（默认 False，禁止全网扫）
    if cap == "scan":
        return bool(caps.get("scan", True))
    if cap == "public_scan":
        return bool(caps.get("public_scan", False))
    return bool(caps.get(cap, False))


def safe_db_path(path: str) -> str:
    """只允许纯文件名（.db 结尾），拒绝任何路径分隔符、上级目录、盘符和URL编码绕过。"""
    if not path or not isinstance(path, str):
        return "mcscanner.db"
    # 归一化反斜杠，封堵 Windows 路径绕过（..\..\x.db）
    name = path.replace("\\", "/")
    low = name.lower()
    # 拒绝：绝对路径、任何层级分隔、上级目录、盘符、URL编码分隔符
    if name.startswith("/") or "/" in name or name in (".", ".."):
        return "mcscanner.db"
    if ".." in name or (len(name) >= 2 and name[1] == ":"):
        return "mcscanner.db"
    if "%2f" in low or "%5c" in low or "://" in low:
        return "mcscanner.db"
    if not name.endswith(".db"):
        return "mcscanner.db"
    return name


def parse_ports_spec(ports_spec, max_ports=2000):
    """解析端口规格，返回去重排序后的端口列表。max_ports限制单次扫描端口数防滥用。

    原实现先把 range(start, end+1) 整段物化再截断，传入 "1-99999999" 这类输入会直接
    吃掉几 GB 内存；现在先把区间夹到合法端口范围（1-65535），并在收集到 max_ports 时
    立即停止，绝不物化超长区间。范围外的端口直接丢弃（由调用方决定是否报错）。
    """
    if ports_spec is None or (isinstance(ports_spec, str) and not ports_spec.strip()):
        return [25565]
    if isinstance(ports_spec, list):
        result = set()
        for p in ports_spec:
            result.update(parse_ports_spec(p, max_ports))
            if len(result) >= max_ports:
                break
        return sorted(result)[:max_ports]
    if not isinstance(ports_spec, str):
        # 显式类型分支：原实现 int(dict) 之类会 TypeError 直冒到 500
        try:
            port = int(ports_spec)
        except (TypeError, ValueError):
            return []
        return [port] if 1 <= port <= 65535 else []
    result = set()
    full = False
    for part in ports_spec.split(","):
        if full:
            break
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                start = int(start.strip()); end = int(end.strip())
            except ValueError:
                continue
            if start > end:
                start, end = end, start
            start = max(1, start)
            end = min(65535, end)
            for p in range(start, end + 1):
                result.add(p)
                if len(result) >= max_ports:
                    full = True
                    break
        else:
            try:
                p = int(part)
            except ValueError:
                continue
            if 1 <= p <= 65535:
                result.add(p)
                if len(result) >= max_ports:
                    full = True
    if full:
        # 不再静默截断：用户以为扫了全部端口却没扫，留日志便于排查
        logger.warning(f"[!] 端口数量超过上限 {max_ports}，已截断（超出部分被忽略）")
    return sorted(result)[:max_ports]
