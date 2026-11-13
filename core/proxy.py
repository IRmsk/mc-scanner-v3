# -*- coding: utf-8 -*-
"""
代理管理器：自动从 ProxyScrape 获取代理、轮换、失败标记、健康检查。
支持 SOCKS5 和 HTTP CONNECT 两种代理协议（纯 Python 实现，无额外依赖）。

吸收自 MCScanner (Sandelslover/MCScanner) 的 proxy_manager.py 优点：
- 启动时从 ProxyScrape API 拉取新鲜代理
- 自动轮换（5分钟或强制轮换）
- 失败代理自动剔除并更新文件
- 避免连续选中同一个代理
"""
import logging
import os
import random
import socket
import struct
import threading
import time
from typing import Optional

logger = logging.getLogger(__name__)

# ProxyScrape 免费 API（HTTP 代理）
DEFAULT_PROXY_API = "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all"
# SOCKS5 代理 API
DEFAULT_SOCKS_API = "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=10000&country=all&ssl=all&anonymity=all"


class Proxy:
    """代理条目"""
    def __init__(self, host: str, port: int, proto: str = "http", username: str = "", password: str = ""):
        self.host = host
        self.port = port
        self.proto = proto.lower()  # "http" or "socks5"
        self.username = username
        self.password = password
        self.fail_count = 0
        self.last_used = 0.0
        self.last_success = 0.0

    def key(self) -> str:
        return f"{self.proto}://{self.host}:{self.port}"

    def __repr__(self):
        return f"Proxy({self.proto}://{self.host}:{self.port}, fails={self.fail_count})"


def parse_proxy_line(line: str) -> Optional[Proxy]:
    """解析代理行，支持格式：
    - host:port
    - host:port:user:pass
    - http://host:port
    - socks5://host:port
    - socks5://user:pass@host:port
    """
    line = line.strip()
    if not line:
        return None
    proto = "http"
    if line.startswith("socks5://"):
        proto = "socks5"
        line = line[len("socks5://"):]
    elif line.startswith("http://"):
        line = line[len("http://"):]
    elif line.startswith("https://"):
        line = line[len("https://"):]

    # 去掉末尾斜杠
    line = line.rstrip("/")

    # 处理 user:pass@host:port
    username = ""
    password = ""
    if "@" in line:
        auth_part, host_part = line.rsplit("@", 1)
        if ":" in auth_part:
            username, password = auth_part.split(":", 1)
        line = host_part

    parts = line.split(":")
    if len(parts) < 2:
        return None
    host = parts[0]
    try:
        port = int(parts[1])
    except ValueError:
        return None
    # 端口合法性校验：非法端口会在连接时才炸，且 0/负数无意义
    if not (1 <= port <= 65535):
        return None

    # 支持 host:port:user:pass 格式
    if len(parts) >= 4 and not username:
        username = parts[2]
        password = parts[3]

    return Proxy(host, port, proto, username, password)


class ProxyManager:
    """代理管理器"""

    def __init__(self, proxy_file: str = "proxies.txt", rotation_interval: float = 300.0,
                 max_fail: int = 3, auto_fetch: bool = True, fetch_socks5: bool = False):
        self.proxies: list[Proxy] = []
        self.proxy_file = proxy_file
        self.rotation_interval = rotation_interval  # 秒
        self.max_fail = max_fail
        self.current: Optional[Proxy] = None
        self.last_rotation = 0.0
        # RLock：mark_failed 持锁时会调用 _remove_from_file，需要可重入
        self._lock = threading.RLock()

        if auto_fetch:
            self.fetch_from_api(fetch_socks5=fetch_socks5)
        self.load_from_file()

    def fetch_from_api(self, fetch_socks5: bool = False) -> int:
        """从 ProxyScrape API 获取新鲜代理，合并到文件"""
        import urllib.request
        urls = [DEFAULT_PROXY_API]
        if fetch_socks5:
            urls.append(DEFAULT_SOCKS_API)

        new_proxies = set()
        for url in urls:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=15) as resp:
                    text = resp.read().decode("utf-8", errors="replace")
                for line in text.splitlines():
                    line = line.strip()
                    if line and ":" in line:
                        new_proxies.add(line)
            except Exception as e:
                logger.warning(f"从 API 获取代理失败: {e}")

        if not new_proxies:
            return 0

        # 合并到现有文件（读改写全程持锁，避免与 add_proxy/_remove_from_file 并发丢更新）
        with self._lock:
            existing = set()
            if os.path.exists(self.proxy_file):
                try:
                    with open(self.proxy_file, "r", encoding="utf-8") as f:
                        existing = {line.strip() for line in f if line.strip()}
                except Exception:
                    pass

            all_proxies = existing | new_proxies
            try:
                with open(self.proxy_file, "w", encoding="utf-8") as f:
                    f.write("\n".join(sorted(all_proxies)))
            except Exception as e:
                logger.warning(f"写入代理文件失败: {e}")

        logger.info(f"API 获取 {len(new_proxies)} 个代理，文件总计 {len(all_proxies)} 个")
        return len(new_proxies)

    def load_from_file(self) -> int:
        """从文件加载代理。先清空并按 key 去重：原先纯 append，
        重复调用（例如 health_check 前后）会产生重复条目。"""
        with self._lock:
            self.proxies = []
            if not os.path.exists(self.proxy_file):
                return 0
            count = 0
            seen = set()
            try:
                with open(self.proxy_file, "r", encoding="utf-8") as f:
                    for line in f:
                        p = parse_proxy_line(line)
                        if p and p.key() not in seen:
                            seen.add(p.key())
                            self.proxies.append(p)
                            count += 1
            except Exception as e:
                logger.warning(f"加载代理文件失败: {e}")
            logger.info(f"从文件加载 {count} 个代理")
            return count

    def get_proxy(self, force_rotate: bool = False) -> Optional[Proxy]:
        """获取当前代理，必要时轮换"""
        with self._lock:
            if not self.proxies:
                return None
            now = time.time()
            need_rotate = (
                force_rotate
                or self.current is None
                or (now - self.last_rotation) > self.rotation_interval
            )
            if need_rotate:
                self._rotate_unlocked()
            return self.current

    def _rotate_unlocked(self):
        """轮换到新代理（调用方需持锁）"""
        if not self.proxies:
            self.current = None
            return
        # 优先选失败次数少、最近没用过的
        candidates = sorted(
            self.proxies,
            key=lambda p: (p.fail_count, p.last_used)
        )
        # 从前 20% 中随机选，避免总是同一个
        top_n = max(1, len(candidates) // 5)
        chosen = random.choice(candidates[:top_n])
        self.current = chosen
        self.last_rotation = time.time()
        chosen.last_used = time.time()

    def mark_success(self):
        """标记当前代理成功"""
        with self._lock:
            if self.current:
                self.current.fail_count = max(0, self.current.fail_count - 1)
                self.current.last_success = time.time()

    def mark_failed(self):
        """标记当前代理失败，超过阈值则剔除并强制轮换"""
        with self._lock:
            if not self.current:
                return
            self.current.fail_count += 1
            if self.current.fail_count >= self.max_fail:
                dead = self.current
                self.proxies = [p for p in self.proxies if p.key() != dead.key()]
                logger.warning(f"剔除失效代理: {dead.key()} (失败 {dead.fail_count} 次)")
                self._remove_from_file(dead)
                self.current = None
            self._rotate_unlocked()

    def _remove_from_file(self, proxy: Proxy):
        """从代理文件中移除失效代理（持锁，允许被 mark_failed 重入调用）"""
        if not os.path.exists(self.proxy_file):
            return
        with self._lock:
            try:
                with open(self.proxy_file, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                with open(self.proxy_file, "w", encoding="utf-8") as f:
                    for line in lines:
                        p = parse_proxy_line(line)
                        if p and p.key() != proxy.key():
                            f.write(line)
            except Exception:
                pass

    def add_proxy(self, proxy_str: str):
        """手动添加代理（持锁，避免与 fetch/remove 并发写同一文件）"""
        p = parse_proxy_line(proxy_str)
        if not p:
            return
        with self._lock:
            if any(existing.key() == p.key() for existing in self.proxies):
                return
            self.proxies.append(p)
            try:
                with open(self.proxy_file, "a", encoding="utf-8") as f:
                    f.write(proxy_str.strip() + "\n")
            except Exception as e:
                logger.warning(f"写入代理文件失败: {e}")

    def health_check(self, test_host: str = None, test_port: int = 25565,
                     timeout: float = 5.0, max_workers: int = 32,
                     max_check: int = 500) -> tuple[int, int]:
        """对所有代理做健康检查，返回 (存活数, 总数)。

        修复三点：
        1) 原先串行遍历全部代理，N 个代理就是 N×timeout 的阻塞（占住 Flask 工作线程）；
           这里改为有界并发 + 单次检查数量上限。
        2) 原先在循环里不持锁直接 self.proxies.remove(p)，与 get_proxy/mark_failed 并发
           会丢/错删条目；现在统一在锁内按 key 批量剔除。
        3) 原先默认测试目标是第三方生产服 mc.hypixel.net，无授权就产生流量；
           现在必须由调用方显式指定自己有权测试的目标。
        """
        if not test_host:
            raise ValueError("health_check 需要显式指定 test_host（请使用你已获授权测试的目标地址）")
        with self._lock:
            total = len(self.proxies)
            targets = self.proxies[:max_check]
        if not targets:
            return 0, total

        def _check(p):
            s = None
            ok = False
            try:
                s = create_proxy_socket(p, timeout)
                s.connect((test_host, test_port))
                ok = True
            except Exception:
                ok = False
            finally:
                # 原先失败路径不关闭 socket，会泄漏 fd
                if s is not None:
                    try:
                        s.close()
                    except Exception:
                        pass
            return p, ok

        from concurrent.futures import ThreadPoolExecutor
        alive = 0
        dead = []
        with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(targets)))) as ex:
            for p, ok in ex.map(_check, targets):
                if ok:
                    p.fail_count = 0
                    alive += 1
                else:
                    p.fail_count += 1
                    if p.fail_count >= self.max_fail:
                        dead.append(p)
        if dead:
            with self._lock:
                dead_keys = {p.key() for p in dead}
                self.proxies = [x for x in self.proxies if x.key() not in dead_keys]
                if self.current is not None and self.current.key() in dead_keys:
                    self.current = None
        return alive, total

    def __len__(self):
        return len(self.proxies)


# ===== 代理 Socket 实现（纯 Python，无额外依赖）=====

def create_proxy_socket(proxy: Optional[Proxy], timeout: float = 10.0) -> socket.socket:
    """创建一个通过代理连接的 socket。
    如果 proxy 为 None，返回普通 socket。
    返回的 socket 已连接到代理服务器，后续调用 connect((host, port)) 会通过代理隧道。
    """
    if proxy is None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        return s

    if proxy.proto == "socks5":
        return _Socks5Socket(proxy, timeout)
    else:
        return _HttpConnectSocket(proxy, timeout)


class _Socks5Socket(socket.socket):
    """SOCKS5 代理 socket（支持无认证和用户名/密码认证）"""

    def __init__(self, proxy: Proxy, timeout: float):
        super().__init__(socket.AF_INET, socket.SOCK_STREAM)
        self._proxy = proxy
        self.settimeout(timeout)
        super().connect((proxy.host, proxy.port))

    def connect(self, address):
        host, port = address
        # 握手：版本5，方法数
        if self._proxy.username:
            methods = b"\x05\x02\x00\x02"  # 无认证 + 用户名密码
        else:
            methods = b"\x05\x01\x00"  # 仅无认证
        self.sendall(methods)
        resp = self._recv_exact(2)
        if resp[0] != 0x05:
            raise ConnectionError("SOCKS5 代理响应版本错误")
        method = resp[1]
        if method == 0x02:
            # 用户名密码认证
            self._socks5_auth()
        elif method != 0x00:
            raise ConnectionError(f"SOCKS5 代理不支持的认证方法: {method}")

        # 连接请求
        host_bytes = host.encode("idna") if not _is_ip(host) else None
        if host_bytes:
            addr_type = b"\x03"
            addr_data = bytes([len(host_bytes)]) + host_bytes
        else:
            try:
                ip_bytes = socket.inet_aton(host)
                addr_type = b"\x01"
                addr_data = ip_bytes
            except OSError:
                # IPv6
                ip_bytes = socket.inet_pton(socket.AF_INET6, host)
                addr_type = b"\x04"
                addr_data = ip_bytes

        req = b"\x05\x01\x00" + addr_type + addr_data + struct.pack(">H", port)
        self.sendall(req)
        resp = self._recv_exact(4)
        if resp[1] != 0x00:
            errors = {1: "通用失败", 2: "不允许", 3: "网络不可达", 4: "主机不可达",
                      5: "连接拒绝", 6: "TTL过期", 7: "命令不支持", 8: "地址类型不支持"}
            raise ConnectionError(f"SOCKS5 连接失败: {errors.get(resp[1], '未知错误')}")
        # 读取绑定地址（忽略）
        addr_type = resp[3]
        if addr_type == 0x01:
            self._recv_exact(4)
        elif addr_type == 0x03:
            length = self._recv_exact(1)[0]
            self._recv_exact(length)
        elif addr_type == 0x04:
            self._recv_exact(16)
        self._recv_exact(2)  # 端口

    def _socks5_auth(self):
        user = self._proxy.username.encode("utf-8")
        pwd = self._proxy.password.encode("utf-8")
        req = b"\x01" + bytes([len(user)]) + user + bytes([len(pwd)]) + pwd
        self.sendall(req)
        resp = self._recv_exact(2)
        if resp[1] != 0x00:
            raise ConnectionError("SOCKS5 代理认证失败")

    def _recv_exact(self, n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = self.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("SOCKS5 代理连接关闭")
            buf.extend(chunk)
        return bytes(buf)


class _HttpConnectSocket(socket.socket):
    """HTTP CONNECT 代理 socket"""

    def __init__(self, proxy: Proxy, timeout: float):
        super().__init__(socket.AF_INET, socket.SOCK_STREAM)
        self._proxy = proxy
        self.settimeout(timeout)
        super().connect((proxy.host, proxy.port))

    def connect(self, address):
        host, port = address
        # host 来自扫描目标字符串（不可信输入）：过滤 CR/LF/空白，防止 CONNECT 头注入
        host = str(host).strip()
        if not host or any(c in host for c in "\r\n\t "):
            raise ConnectionError(f"HTTP 代理 CONNECT 目标非法: {host!r}")
        try:
            port = int(port)
        except Exception:
            raise ConnectionError(f"HTTP 代理 CONNECT 端口非法: {port!r}")
        if not (1 <= port <= 65535):
            raise ConnectionError(f"HTTP 代理 CONNECT 端口超出范围: {port}")
        req = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n"
        if self._proxy.username:
            import base64
            auth = base64.b64encode(
                f"{self._proxy.username}:{self._proxy.password}".encode()
            ).decode()
            req += f"Proxy-Authorization: Basic {auth}\r\n"
        req += "\r\n"
        self.sendall(req.encode())

        # 读取响应头：必须有总量上限与总超时。
        # 恶意/被劫持代理可以持续输出却永远不发 CRLFCRLF → 循环挂死 + 内存放大。
        # 上限与 core/conn.py 的同类实现保持一致（64KB）。
        response = b""
        header_deadline = time.time() + 60
        while b"\r\n\r\n" not in response:
            if time.time() > header_deadline:
                raise ConnectionError("HTTP 代理 CONNECT 响应超时")
            chunk = self.recv(4096)
            if not chunk:
                raise ConnectionError("HTTP 代理连接关闭")
            response += chunk
            if len(response) > 65536:
                raise ConnectionError("HTTP代理响应头过大")

        status_line = response.split(b"\r\n")[0].decode("utf-8", errors="replace")
        if "200" not in status_line:
            raise ConnectionError(f"HTTP 代理 CONNECT 失败: {status_line}")


def _is_ip(host: str) -> bool:
    """判断是否为 IP 地址（IPv4 或 IPv6）"""
    try:
        socket.inet_aton(host)
        return True
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return True
    except OSError:
        return False


# 全局代理管理器单例
_global_manager: Optional[ProxyManager] = None
_manager_lock = threading.Lock()


def get_proxy_manager(proxy_file: str = "proxies.txt", auto_fetch: bool = False,
                      **kwargs) -> Optional[ProxyManager]:
    """获取全局代理管理器单例（初始化加锁，避免并发创建出两个 manager 实例）"""
    global _global_manager
    with _manager_lock:
        if _global_manager is None:
            if not os.path.exists(proxy_file) and not auto_fetch:
                return None
            mgr = ProxyManager(proxy_file=proxy_file, auto_fetch=auto_fetch, **kwargs)
            if len(mgr) == 0:
                return None  # 空管理器不缓存，允许后续重新创建
            _global_manager = mgr
        return _global_manager
