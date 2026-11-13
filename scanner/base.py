# -*- coding: utf-8 -*-
"""
扫描器抽象基类。
统一 portscan / masscan / random_scan 三种扫描方式的接口，
上层 engine 不需要写多套 if 判断适配不同扫描器。
"""
import os
import threading
from abc import ABC, abstractmethod
from typing import Iterator, Optional, Tuple


class BaseScanner(ABC):
    """扫描器基类，所有扫描方式继承此类。"""

    @abstractmethod
    def scan(self, targets, ports=None, max_workers: int = 200,
             timeout: float = 3.0, rate: int = 0,
             stop_event: Optional[threading.Event] = None) -> Iterator[Tuple[str, int]]:
        """
        扫描目标，yield (ip, port) 开放端口。
        子类必须实现。
        """
        raise NotImplementedError

    def scan_list(self, targets, ports=None, max_workers: int = 200,
                  timeout: float = 3.0, rate: int = 0,
                  stop_event: Optional[threading.Event] = None) -> list:
        """扫描并返回列表（便捷方法）。"""
        return list(self.scan(targets, ports, max_workers, timeout, rate, stop_event))


class TCPPortScanner(BaseScanner):
    """Python原生TCP全连接端口扫描器。"""

    def scan(self, targets, ports=None, max_workers: int = 200,
             timeout: float = 3.0, rate: int = 0,
             stop_event: Optional[threading.Event] = None) -> Iterator[Tuple[str, int]]:
        from .portscan import get_open_ports, scan_ports
        from .targets import parse_targets
        # 将 targets(IP/网段列表) 与 ports 展开成 (ip, port) 对，再交给端口扫描
        port_list = ports or [25565]
        pairs = list(parse_targets([str(t) for t in targets], port_list))
        results = scan_ports(pairs, max_workers=max_workers, timeout=timeout,
                             rate=rate, stop_event=stop_event, show_progress=False)
        for ip, port in get_open_ports(results):
            yield ip, port


class MasscanScanner(BaseScanner):
    """masscan高速端口扫描器（需要系统安装masscan）。"""

    def __init__(self, rate: int = 1000, exclude_file: str = "exclude.conf"):
        self.rate = rate
        self.exclude_file = exclude_file

    def scan(self, targets, ports=None, max_workers: int = 200,
             timeout: float = 3.0, rate: int = 0,
             stop_event: Optional[threading.Event] = None) -> Iterator[Tuple[str, int]]:
        from .masscan import has_masscan, parse_masscan_json, run_masscan
        if not has_masscan():
            raise RuntimeError("masscan 未安装")
        targets_str = ",".join(str(t) for t in targets) if isinstance(targets, (list, tuple)) else str(targets)
        ports_str = ",".join(str(p) for p in ports) if ports else "25565"
        result_path = run_masscan(targets=targets_str, ports=ports_str,
                                   rate=rate or self.rate, exclude_file=self.exclude_file)
        try:
            for ip, port, _banner in parse_masscan_json(result_path):
                yield ip, port
        finally:
            # run_masscan 未指定 output_file 时会自建临时 NDJSON，
            # 本生成器消费完/被关闭后这个文件不再需要，立即删除避免堆积
            try:
                os.remove(result_path)
            except OSError:
                pass


class RandomScanner(BaseScanner):
    """随机IP随机端口暴力扫描器。"""

    def __init__(self, target_count: int = 1000):
        self.target_count = target_count

    def scan(self, targets=None, ports=None, max_workers: int = 200,
             timeout: float = 3.0, rate: int = 0,
             stop_event: Optional[threading.Event] = None) -> Iterator[Tuple[str, int]]:
        from .random_scan import parse_port_ranges, random_scan
        port_ranges = parse_port_ranges(ports) if isinstance(ports, str) else (ports or [(25565, 25575)])
        open_ports = random_scan(self.target_count, max_workers, timeout, port_ranges,
                                  stop_event=stop_event)
        for ip, port in open_ports:
            yield ip, port


def get_scanner(scan_type: str = "tcp", **kwargs) -> BaseScanner:
    """工厂方法：根据类型获取扫描器实例。"""
    scanners = {
        "tcp": TCPPortScanner,
        "python": TCPPortScanner,
        "masscan": MasscanScanner,
        "random": RandomScanner,
    }
    cls = scanners.get(scan_type.lower(), TCPPortScanner)
    return cls(**kwargs)
