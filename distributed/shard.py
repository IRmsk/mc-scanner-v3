# -*- coding: utf-8 -*-
"""
分布式任务分片（v3.2.1 新增，融合 matscan 特性）。
将大网段扫描任务分割为多个分片，分配给多个 worker 节点并行执行。
基于文件的简单分片管理（不依赖 Redis/Zookeeper，与原版轻量风格一致）。
"""
import contextlib
import hashlib
import ipaddress
import json
import os
import re
import threading
import time

try:
    import fcntl  # POSIX 文件锁；Windows 下降级为进程内线程锁
except ImportError:         # pragma: no cover
    fcntl = None

# job_id 会直接拼进文件名，必须白名单化（否则 "../../evil" 可写出 state_dir）
_JOB_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
# fcntl 不可用时的进程内互斥
_PROC_LOCK = threading.RLock()


def _validate_num_shards(num_shards: int):
    if not isinstance(num_shards, int) or num_shards < 1:
        raise ValueError(f"num_shards 必须为正整数，收到: {num_shards!r}")


def _validate_job_id(job_id: str):
    if not isinstance(job_id, str) or not _JOB_ID_RE.match(job_id):
        raise ValueError(f"非法 job_id（仅允许字母数字与 _.- ，长度 1-64）: {job_id!r}")


def shard_cidr(cidr: str, num_shards: int, ports: list = None) -> list:
    """
    将 CIDR 网段分割为多个分片。
    返回: [{"shard_id": 0, "targets": "1.0.0.0/24", "ports": [25565], "estimated_hosts": N}, ...]
    """
    if ports is None:
        ports = [25565]
    # num_shards<=0 会让 len(subnets)//num_shards 抛 ZeroDivisionError；负数还会返回 256 个分片
    _validate_num_shards(num_shards)

    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        # 把裸 ValueError 转成带目标的明确错误（cli --create 传入非法目标不再直接崩栈）
        raise ValueError(f"非法 CIDR: {cidr!r} ({e})") from e
    total_hosts = net.num_addresses

    if total_hosts <= num_shards:
        shards = []
        for i, addr in enumerate(net.hosts()):
            shards.append({
                "shard_id": i,
                "targets": [str(addr)],
                "ports": ports,
                "estimated_hosts": 1,
            })
        return shards

    # 按前缀长度分割
    prefix_len = net.prefixlen
    new_prefix = prefix_len
    # 上限用 net.max_prefixlen（IPv4=32，IPv6=128）；原来写死 32 对 IPv6 完全错误
    while (2 ** (new_prefix - prefix_len)) < num_shards and new_prefix < net.max_prefixlen:
        new_prefix += 1

    subnets = list(net.subnets(new_prefix=new_prefix))
    per_shard = max(1, len(subnets) // num_shards)
    shards = []
    for i in range(0, len(subnets), per_shard):
        group = subnets[i:i + per_shard]
        if not group:
            break
        shard_id = len(shards)
        # targets 统一用 CIDR 列表，避免 "a.b.c.d-x.y.z.w" 范围格式无法被 parse_targets 解析
        target = [str(s) for s in group]
        shards.append({
            "shard_id": shard_id,
            "targets": target,
            "ports": ports,
            "estimated_hosts": sum(s.num_addresses for s in group),
            "subnets": [str(s) for s in group],
        })
        if len(shards) >= num_shards:
            break
    return shards


def shard_target_file(filepath: str, num_shards: int, ports: list = None) -> list:
    """
    将目标文件中的目标分配到多个分片（一致性哈希）。
    """
    if ports is None:
        ports = [25565]
    _validate_num_shards(num_shards)   # 否则 h % num_shards 会 ZeroDivisionError

    targets = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(line)
    except FileNotFoundError:
        return []

    shards = [{"shard_id": i, "targets": [], "ports": ports, "estimated_hosts": 0}
              for i in range(num_shards)]

    for target in targets:
        h = int(hashlib.md5(target.encode()).hexdigest(), 16)
        shard_id = h % num_shards
        shards[shard_id]["targets"].append(target)
        shards[shard_id]["estimated_hosts"] += 1

    return [s for s in shards if s["targets"]]


class ShardManager:
    """分片管理器：分配、领取、完成分片任务（基于文件状态）。"""

    def __init__(self, state_dir: str = "shards"):
        self.state_dir = state_dir
        os.makedirs(state_dir, exist_ok=True)

    def create_job(self, job_id: str, targets: str, num_shards: int,
                    ports: list = None) -> list:
        """创建一个扫描任务，生成分片。"""
        _validate_job_id(job_id)
        _validate_num_shards(num_shards)
        if "/" in targets:
            shards = shard_cidr(targets, num_shards, ports)
        elif os.path.exists(targets):
            shards = shard_target_file(targets, num_shards, ports)
        else:
            # 单目标也统一存成 list，避免下游 run_full_scan(shard["targets"]) 依赖 str/list 双形态
            shards = [{"shard_id": 0, "targets": [targets], "ports": ports or [25565], "estimated_hosts": 1}]

        job = {
            "job_id": job_id,
            "total_shards": len(shards),
            "completed_shards": 0,
            "shards": {str(s["shard_id"]): {**s, "status": "pending", "worker": None, "completed_at": None}
                        for s in shards},
        }
        with self._locked_job(job_id):
            self._save_job(job_id, job)
        return shards

    def claim_shard(self, job_id: str, worker_id: str) -> dict:
        """Worker 领取一个待处理的分片。

        整个「读整份 JSON → 找 pending → 改成 running → 整文件回写」在文件锁内完成，
        否则并发 worker 会同时读到同一个 pending 分片（重复扫描、流量翻倍）。
        """
        with self._locked_job(job_id):
            job = self._load_job(job_id)
            if not job:
                return None
            for sid, shard in job["shards"].items():
                if shard["status"] == "pending":
                    shard["status"] = "running"
                    shard["worker"] = worker_id
                    self._save_job(job_id, job)
                    return shard
        return None

    def complete_shard(self, job_id: str, shard_id: int, result_summary: dict):
        """标记分片完成（幂等：重复上报不会让 completed_shards 虚高）。"""
        with self._locked_job(job_id):
            job = self._load_job(job_id)
            if not job:
                return
            sid = str(shard_id)
            shard = job["shards"].get(sid)
            if shard is None:
                return
            if shard.get("status") == "completed":
                return  # 重复完成直接忽略
            shard["status"] = "completed"
            shard["result"] = result_summary
            # 用实际统计重算，兼容历史状态文件
            job["completed_shards"] = sum(
                1 for s in job["shards"].values() if s.get("status") == "completed")
            self._save_job(job_id, job)

    def get_job_status(self, job_id: str) -> dict:
        """获取任务状态。"""
        job = self._load_job(job_id)
        if not job:
            return {}
        return {
            "job_id": job_id,
            "total_shards": job["total_shards"],
            "completed_shards": job["completed_shards"],
            "progress": round(job["completed_shards"] / job["total_shards"] * 100, 1) if job["total_shards"] else 0,
            "shards": {k: {"status": v["status"], "worker": v.get("worker")}
                        for k, v in job["shards"].items()},
        }

    def _job_path(self, job_id: str) -> str:
        _validate_job_id(job_id)
        path = os.path.join(self.state_dir, f"{job_id}.json")
        # 双保险：即使正则被放宽，也确保最终路径仍在 state_dir 内
        base = os.path.abspath(self.state_dir)
        if os.path.commonpath([os.path.abspath(path), base]) != base:
            raise ValueError(f"job_id 导致路径越界: {job_id!r}")
        return path

    @contextlib.contextmanager
    def _locked_job(self, job_id: str):
        """对单个任务加跨进程文件锁；fcntl 不可用时退化为进程内互斥。

        无锁时并发 worker 会互相覆盖整份状态文件，且能读到写了一半的 JSON。
        """
        self._job_path(job_id)
        if fcntl is None:                       # pragma: no cover - Windows
            with _PROC_LOCK:
                yield
            return
        lock_path = os.path.join(self.state_dir, f"{job_id}.lock")
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    def _save_job(self, job_id: str, job: dict):
        path = self._job_path(job_id)
        tmp = path + ".tmp"
        # 先写临时文件再 rename：读取方永远不会看到半截 JSON
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(job, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)

    def _load_job(self, job_id: str) -> dict:
        """读取任务状态；遇到半截/损坏文件时短暂重试，不让 worker 直接崩在 JSONDecodeError。"""
        path = self._job_path(job_id)
        for _ in range(5):
            if not os.path.exists(path):
                return {}
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                time.sleep(0.05)
        return {}
