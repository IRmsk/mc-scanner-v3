"""
随机 IP + 随机端口 暴力扫描模块
生成随机公网 IP 和端口，批量扫描寻找 Minecraft 服务器
支持异步高速模式、排除列表（含中国IP段）
"""
import ipaddress
import random
import socket
import threading
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from typing import Iterator, List, Optional, Tuple

try:
    from .exclude import Excluder
except ImportError:
    from exclude import Excluder

# 排除的私有/保留地址段
EXCLUDED_NETWORKS = [
    ipaddress.ip_network('0.0.0.0/8'),
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('100.64.0.0/10'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.0.0.0/24'),
    ipaddress.ip_network('192.0.2.0/24'),
    ipaddress.ip_network('192.88.99.0/24'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('198.18.0.0/15'),
    ipaddress.ip_network('198.51.100.0/24'),
    ipaddress.ip_network('203.0.113.0/24'),
    ipaddress.ip_network('224.0.0.0/4'),
    ipaddress.ip_network('240.0.0.0/4'),
]

# Minecraft 常见端口范围
DEFAULT_PORT_RANGES = [
    (25565, 25575),
    (19132, 19133),
    (25500, 25600),
    (1, 65535),
]


def is_public_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        for net in EXCLUDED_NETWORKS:
            if ip in net:
                return False
        return True
    except ValueError:
        return False


# 常见公网首字节分布（云厂商/ISP集中段，MC服务器概率更高）
WEIGHTED_FIRST_OCTETS = [
    (1, 1), (2, 1), (3, 2), (4, 3), (5, 3), (6, 2), (7, 2), (8, 4),
    (9, 3), (11, 2), (12, 3), (13, 2), (14, 2), (15, 2), (16, 2),
    (17, 2), (18, 2), (19, 2), (20, 3), (21, 2), (22, 2), (23, 3), (24, 4),
    (25, 2), (26, 2), (27, 3), (28, 2), (29, 2), (30, 2), (31, 2), (32, 3),
    (34, 2), (35, 2), (36, 3), (37, 3), (38, 2), (39, 2), (40, 3), (41, 2),
    (42, 2), (43, 3), (44, 2), (45, 3), (46, 3), (47, 2), (48, 2), (49, 3),
    (50, 3), (51, 2), (52, 4), (53, 2), (54, 4), (55, 2), (56, 2), (57, 2),
    (58, 4), (59, 4), (60, 3), (61, 4), (62, 3), (63, 3), (64, 4), (65, 3),
    (66, 3), (67, 3), (68, 3), (69, 2), (70, 3), (71, 3), (72, 3), (73, 3),
    (74, 3), (75, 3), (76, 2), (77, 3), (78, 3), (79, 3), (80, 3), (81, 3),
    (82, 3), (83, 3), (84, 3), (85, 3), (86, 3), (87, 3), (88, 3), (89, 3),
    (90, 3), (91, 3), (92, 3), (93, 3), (94, 3), (95, 3), (96, 3), (97, 3),
    (98, 3), (99, 3), (101, 3), (102, 3), (103, 4), (104, 4), (105, 3),
    (106, 3), (107, 3), (108, 3), (109, 3), (110, 3), (111, 3), (112, 3), (113, 3),
    (114, 3), (115, 3), (116, 3), (117, 3), (118, 3), (119, 3), (120, 3), (121, 3),
    (122, 3), (123, 3), (124, 3), (125, 3), (128, 3), (129, 3), (130, 3),
    (131, 2), (132, 2), (133, 2), (134, 2), (135, 2), (136, 3), (137, 2), (138, 3),
    (139, 2), (140, 3), (141, 3), (142, 2), (143, 2), (144, 3), (145, 3), (146, 3),
    (147, 3), (148, 3), (149, 3), (150, 3), (151, 3), (152, 3), (153, 3), (154, 3),
    (155, 3), (156, 3), (157, 3), (158, 3), (159, 3), (160, 3), (161, 3), (162, 3),
    (163, 3), (164, 3), (165, 3), (166, 3), (167, 3), (170, 3),
    (171, 3), (173, 3), (174, 3), (175, 3), (176, 3), (177, 3), (178, 3),
    (179, 3), (180, 3), (181, 3), (182, 3), (183, 3), (184, 3), (185, 4), (186, 3),
    (187, 3), (188, 3), (189, 3), (190, 3), (191, 3), (193, 3), (194, 3),
    (195, 3), (196, 3), (197, 3), (199, 3), (200, 3), (201, 3), (202, 3),
    (204, 3), (205, 3), (206, 3), (207, 3), (208, 3), (209, 3), (210, 3),
    (211, 3), (212, 3), (213, 3), (214, 3), (215, 3), (216, 3), (217, 3), (218, 3),
    (219, 3), (220, 3), (221, 3), (222, 3), (223, 2),
]

_weighted_octets = []
_weighted_weights = []
for octet, weight in WEIGHTED_FIRST_OCTETS:
    if weight > 0:
        _weighted_octets.append(octet)
        _weighted_weights.append(weight)


def random_public_ip() -> str:
    while True:
        first = random.choices(_weighted_octets, weights=_weighted_weights, k=1)[0]
        ip = f"{first}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        if is_public_ip(ip):
            return ip


def random_port(port_ranges: Optional[List[Tuple[int, int]]] = None) -> int:
    if port_ranges is None:
        port_ranges = [(25565, 25575)]
    start, end = random.choice(port_ranges)
    return random.randint(start, end)


def generate_random_targets(
    count: int,
    port_ranges: Optional[List[Tuple[int, int]]] = None,
    excluder: Optional[Excluder] = None,
) -> Iterator[Tuple[str, int]]:
    yielded = 0
    while yielded < count:
        ip = random_public_ip()
        if excluder and excluder.is_excluded(ip):
            continue
        yield ip, random_port(port_ranges)
        yielded += 1


def check_port(ip: str, port: int, timeout: float = 2.0) -> bool:
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        return result == 0
    except Exception:
        return False
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def random_scan(
    target_count: int = 1000,
    max_workers: int = 200,
    timeout: float = 2.0,
    port_ranges: Optional[List[Tuple[int, int]]] = None,
    progress_callback=None,
    stop_event: Optional[threading.Event] = None,
    exclude_file: Optional[str] = None,
) -> List[Tuple[str, int]]:
    excluder = Excluder(exclude_file) if exclude_file else None
    target_gen = generate_random_targets(target_count, port_ranges, excluder)
    open_ports = []
    done = 0
    BATCH_SIZE = max(max_workers * 4, 200)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {}
        # 初始填充一批
        for ip, port in target_gen:
            if len(futures) >= BATCH_SIZE:
                break
            futures[executor.submit(check_port, ip, port, timeout)] = (ip, port)
        while futures:
            if stop_event and stop_event.is_set():
                for f in futures:
                    f.cancel()
                break
            done_set, _ = wait(futures, return_when=FIRST_COMPLETED)
            for future in done_set:
                ip, port = futures.pop(future)
                done += 1
                try:
                    if future.result():
                        open_ports.append((ip, port))
                except Exception:
                    pass
                # 补充新任务
                try:
                    nip, nport = next(target_gen)
                    futures[executor.submit(check_port, nip, nport, timeout)] = (nip, nport)
                except StopIteration:
                    pass
            if progress_callback:
                progress_callback(done, target_count, len(open_ports))
    return open_ports


async def async_random_scan(
    target_count: int = 1000,
    concurrency: int = 1000,
    timeout: float = 2.0,
    port_ranges: Optional[List[Tuple[int, int]]] = None,
    progress_callback=None,
    stop_event: Optional[threading.Event] = None,
    exclude_file: Optional[str] = None,
) -> List[Tuple[str, int]]:
    """异步随机扫描：asyncio 协程并发，比线程池快 3-5 倍

    进度回调签名：progress_callback(done, total, found)（与端口扫描的
    callback(done, open_count) 不同，调用方注意区分）。
    """
    try:
        from .async_portscan import scan_ports_async
    except ImportError:
        from async_portscan import scan_ports_async
    excluder = Excluder(exclude_file) if exclude_file else None
    # 惰性生成器直接传入，scan_ports_async 内部统一物化+打乱一次（原为双重物化，大 count 内存翻倍）
    targets = generate_random_targets(target_count, port_ranges, excluder)

    def _progress(done, opened):
        if progress_callback:
            progress_callback(done, target_count, opened)

    # stop_event 必须透传：旧实现声明了参数却从不传入，异步随机扫描无法停止
    results = await scan_ports_async(targets, concurrency=concurrency, timeout=timeout,
                                     progress_cb=_progress, stop_event=stop_event)
    return [(r.ip, r.port) for r in results if r.is_open]


def parse_port_ranges(spec: str) -> List[Tuple[int, int]]:
    """解析端口段 '25565-25575,19132'。

    旧实现不处理 start>end（random_port 随即 ValueError）也不处理非数字，
    会让扫描线程直接异常退出；现在交换区间、跳过非法项并限制到 1..65535。
    """
    ranges = []
    for part in str(spec).split(','):
        part = part.strip()
        if not part:
            continue
        try:
            if '-' in part:
                start, end = part.split('-', 1)
                start, end = int(start), int(end)
                if start > end:
                    start, end = end, start
                start, end = max(start, 1), min(end, 65535)
                if start <= end:
                    ranges.append((start, end))
            else:
                p = int(part)
                if 1 <= p <= 65535:
                    ranges.append((p, p))
        except ValueError:
            continue
    return ranges if ranges else [(25565, 25575)]
