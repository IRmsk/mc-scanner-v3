# -*- coding: utf-8 -*-
"""
MC TCP 连接：收发包、长度前缀、可选压缩、状态管理。
融合 V1 的健壮性（半包处理、超时恢复）和 V2 的简洁设计。
"""
import io
import socket
import struct
import threading
import time
import zlib

from .buffer import read_varint_from_stream, write_string, write_varint

PROTO_STATE_HANDSHAKE = 0
PROTO_STATE_STATUS = 1
PROTO_STATE_LOGIN = 2
PROTO_STATE_CONFIGURATION = 3
PROTO_STATE_PLAY = 4

MAX_PACKET_SIZE = 2 * 1024 * 1024  # 单个包最大2MB，防止恶意服务器内存放大
MAX_UNCOMPRESSED_SIZE = 8 * 1024 * 1024  # 单包解压后最大8MB，防 zip 炸弹

# 全局代理（设置后所有MCConnection默认走代理）
_global_proxy = None
_global_proxy_lock = threading.Lock()
_global_proxy_manager = None  # ProxyManager实例，设置后每次连接自动轮换

def set_global_proxy(proxy):
    """设置全局代理（Proxy对象或None）。设置后所有新连接默认走代理。"""
    global _global_proxy
    with _global_proxy_lock:
        _global_proxy = proxy

def get_global_proxy():
    """获取当前全局代理。如果设置了ProxyManager，会自动轮换。"""
    with _global_proxy_lock:
        if _global_proxy_manager is not None:
            p = _global_proxy_manager.get_proxy()
            if p is not None:
                return p
        return _global_proxy

def set_global_proxy_manager(manager):
    """设置全局ProxyManager，每次连接自动从它获取代理（轮换）。"""
    global _global_proxy_manager
    with _global_proxy_lock:
        _global_proxy_manager = manager


def _recv_n(sock, n: int) -> bytes:
    """从代理连接精确读取 n 字节，半包循环读完，断开抛 ConnectionError。"""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("代理连接提前关闭")
        buf += chunk
    return buf


def _connect_via_socks5(sock, proxy_host, proxy_port, target_host, target_port, username="", password=""):
    """通过SOCKS5代理建立TCP连接。"""
    sock.connect((proxy_host, proxy_port))
    # 握手: VER=5, NMETHODS, METHODS
    if username and password:
        sock.sendall(b"\x05\x01\x02")  # 用户名密码认证
    else:
        sock.sendall(b"\x05\x01\x00")  # 无认证
    resp = _recv_n(sock, 2)
    if resp[0] != 0x05:
        raise ConnectionError("SOCKS5代理响应错误")
    if resp[1] == 0x02:
        # 用户名密码认证
        sock.sendall(b"\x01" + bytes([len(username)]) + username.encode() + bytes([len(password)]) + password.encode())
        auth_resp = _recv_n(sock, 2)
        if auth_resp[1] != 0x00:
            raise ConnectionError("SOCKS5代理认证失败")
    elif resp[1] != 0x00:
        raise ConnectionError("SOCKS5代理不支持的认证方式")
    # CONNECT请求: VER=5, CMD=1, RSV=0, ATYP=1(IPv4), DST.ADDR, DST.PORT
    try:
        addr_bytes = socket.inet_aton(target_host)
        sock.sendall(b"\x05\x01\x00\x01" + addr_bytes + struct.pack(">H", target_port))
    except OSError:
        # 域名，用ATYP=3
        host_bytes = target_host.encode()
        sock.sendall(b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes + struct.pack(">H", target_port))
    # CONNECT应答: VER CMD RSV ATYP + 地址 + 端口，按ATYP读取完整长度，避免截断
    head = _recv_n(sock, 4)
    if head[1] != 0x00:
        raise ConnectionError(f"SOCKS5代理连接失败，错误码={head[1]}")
    atyp = head[3]
    if atyp == 0x01:
        _recv_n(sock, 4 + 2)
    elif atyp == 0x04:
        _recv_n(sock, 16 + 2)
    elif atyp == 0x03:
        addr_len = _recv_n(sock, 1)[0]
        _recv_n(sock, addr_len + 2)


def _connect_via_http(sock, proxy_host, proxy_port, target_host, target_port, username="", password=""):
    """通过HTTP CONNECT代理建立TCP连接。"""
    sock.connect((proxy_host, proxy_port))
    auth_header = ""
    if username and password:
        import base64
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        auth_header = f"Proxy-Authorization: Basic {token}\r\n"
    request = f"CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n{auth_header}\r\n"
    sock.sendall(request.encode())
    # 读取响应头（限制大小防止无限增长）
    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = sock.recv(4096)
        if not chunk:
            break
        resp += chunk
        if len(resp) > 65536:
            raise ConnectionError("HTTP代理响应头过大")
    if b"200" not in resp.split(b"\r\n")[0]:
        proxy_status = resp.split(b"\r\n")[0].decode(errors="ignore")
        raise ConnectionError(f"HTTP代理连接失败: {proxy_status}")


class MCConnection:
    def __init__(self, host: str, port: int = 25565, timeout: float = 15.0, proxy=None):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock: socket.socket | None = None
        self.compression_threshold = -1
        self.state = PROTO_STATE_HANDSHAKE
        self._send_lock = threading.Lock()
        self.proxy = proxy  # Proxy对象或None
        self._encryptor = None
        self._decryptor = None

    def enable_encryption(self, shared_secret: bytes):
        """启用AES/CFB8加密（正版服），优先cryptography(OpenSSL)，备选pyjnius(APK)，最后pycryptodome手动CFB8"""
        self._crypto_backend = None
        # 最高优先：cryptography库（OpenSSL绑定，和Java AES/CFB8/NoPadding完全一致）
        try:
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            _cipher = Cipher(algorithms.AES(shared_secret), modes.CFB8(shared_secret), backend=default_backend())
            self._enc_cipher = _cipher.encryptor()
            self._dec_cipher = _cipher.decryptor()
            self._crypto_backend = "cryptography"
            print("[加密] 使用cryptography(OpenSSL)后端")
            return
        except ImportError:
            pass
        # 备选pyjnius（APK环境，调用Java Cipher，和服务器完全一致）
        try:
            from jnius import autoclass
            SecretKeySpec = autoclass('javax.crypto.spec.SecretKeySpec')
            Cipher = autoclass('javax.crypto.Cipher')
            self._aes_key = SecretKeySpec(shared_secret, "AES")
            self._enc_cipher = Cipher.getInstance("AES/CFB8/NoPadding")
            self._dec_cipher = Cipher.getInstance("AES/CFB8/NoPadding")
            self._enc_cipher.init(Cipher.ENCRYPT_MODE, self._aes_key)
            self._dec_cipher.init(Cipher.DECRYPT_MODE, self._aes_key)
            self._crypto_backend = "pyjnius"
            print("[加密] 使用pyjnius(Java)后端")
            return
        except ImportError:
            pass
        # 最后备选：pycryptodome手动实现CFB8（可能和Java有细微差别，仅兜底）
        try:
            from Crypto.Cipher import AES
            self._aes_ecb = AES.new(shared_secret, AES.MODE_ECB)
            self._enc_shift = bytearray(shared_secret)
            self._dec_shift = bytearray(shared_secret)
            self._crypto_backend = "pycryptodome_cfb8"
            print("[加密] 使用pycryptodome手动CFB8后端（兜底，可能和Java不一致）")
            return
        except ImportError:
            pass
        raise RuntimeError("当前环境不支持正版服加密，请安装 cryptography（pip install cryptography）；Termux/手机可改装 pycryptodome（pip install pycryptodome），或使用 APK")

    def _encrypt(self, data: bytes) -> bytes:
        """加密数据，自动适配后端"""
        if self._crypto_backend == "cryptography":
            return self._enc_cipher.update(data)
        if self._crypto_backend == "pycryptodome_cfb8":
            out = bytearray(len(data))
            for i in range(len(data)):
                keystream = self._aes_ecb.encrypt(bytes(self._enc_shift))
                out[i] = data[i] ^ keystream[0]
                self._enc_shift = self._enc_shift[1:] + bytes([out[i]])
            return bytes(out)
        else:  # pyjnius
            return bytes(self._enc_cipher.update(data))

    def _decrypt(self, data: bytes) -> bytes:
        """解密数据，自动适配后端"""
        if self._crypto_backend == "cryptography":
            return self._dec_cipher.update(data)
        if self._crypto_backend == "pycryptodome_cfb8":
            out = bytearray(len(data))
            for i in range(len(data)):
                keystream = self._aes_ecb.encrypt(bytes(self._dec_shift))
                out[i] = data[i] ^ keystream[0]
                self._dec_shift = self._dec_shift[1:] + bytes([data[i]])
            return bytes(out)
        else:  # pyjnius
            return bytes(self._dec_cipher.update(data))

    def connect(self):
        proxy = self.proxy if self.proxy is not None else get_global_proxy()
        # 本地/私有地址不走代理（否则会连到代理服务器的本地）
        if proxy is not None:
            import ipaddress
            try:
                addr = ipaddress.ip_address(self.host)
                if addr.is_private or addr.is_loopback or addr.is_link_local:
                    proxy = None
            except ValueError:
                pass
        try:
            if proxy is None:
                # 用 create_connection 而不是手搓 AF_INET：域名解析出 AAAA 记录时也能连上
                # （原来只建 AF_INET 套接字，纯 IPv6 目标一律失败），并自动做多地址回退。
                self.sock = socket.create_connection(
                    (self.host, self.port), timeout=self.timeout)
            else:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.settimeout(self.timeout)
                if proxy.proto == "socks5":
                    _connect_via_socks5(self.sock, proxy.host, proxy.port,
                                        self.host, self.port,
                                        proxy.username, proxy.password)
                else:
                    _connect_via_http(self.sock, proxy.host, proxy.port,
                                      self.host, self.port,
                                      proxy.username, proxy.password)
        except Exception:
            if self.sock is not None:
                try:
                    self.sock.close()
                except Exception:
                    pass
            self.sock = None
            raise

    def close(self):
        if self.sock:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.close()

    def handshake(self, protocol: int, next_state: int):
        payload = (write_varint(protocol) + write_string(self.host)
                   + self.port.to_bytes(2, "big") + write_varint(next_state))
        self.send_packet(0x00, payload)
        self.state = next_state

    def set_compression(self, threshold: int):
        self.compression_threshold = threshold

    def send_packet(self, packet_id: int, payload: bytes = b""):
        if self.sock is None:
            raise ConnectionError("未连接")
        id_bytes = write_varint(packet_id)
        uncompressed = id_bytes + payload
        if self.compression_threshold >= 0:
            if len(uncompressed) >= self.compression_threshold:
                data_length = write_varint(len(uncompressed))
                compressed = zlib.compress(uncompressed)
                packet_data = data_length + compressed
            else:
                packet_data = write_varint(0) + uncompressed
        else:
            packet_data = uncompressed
        frame = write_varint(len(packet_data)) + packet_data
        with self._send_lock:
            # 不再为每个包新建 selectors/epoll（高频发包时每次都 epoll_create 是纯开销）。
            # socket 已在 connect 时 settimeout(self.timeout)，sendall 阻塞超时自己会抛。
            data = frame
            if getattr(self, '_crypto_backend', None) is not None:
                data = self._encrypt(data)
            sock = self.sock
            if sock is None:
                raise ConnectionError("未连接")
            sock.sendall(data)

    def recv_packet(self, timeout: float | None = None) -> tuple:
        """接收一个数据包，返回 (packet_id, payload_bytes)
        读包数据中途失败（半包）时关闭连接，避免后续流错位；
        仅等待数据时的正常超时不关闭连接（调用方用于轮询）。
        用 select 实现超时，不修改 socket.timeout，避免影响并发 send。"""
        if self.sock is None:
            raise ConnectionError("未连接")
        import selectors
        sel = selectors.DefaultSelector()
        sel.register(self.sock, selectors.EVENT_READ)
        try:
            if timeout is not None:
                events = sel.select(timeout=timeout)
                if not events:
                    raise socket.timeout("recv 超时")
            packet_length = self._recv_varint()
            if packet_length > MAX_PACKET_SIZE:
                self.close()
                raise ValueError(f"包过大: {packet_length} > {MAX_PACKET_SIZE}")
            if packet_length < 0:
                self.close()
                raise ValueError(f"包长度非法: {packet_length}")
            try:
                # timeout 只用于“等待数据就绪”（configuration/play 用 0.5~1s 短轮询，
                # 以便及时响应 deadline/stop）。一旦包开始到达，读完整包用 self.timeout 兜底：
                # 否则短轮询遇到大 registry/地形包在 timeout 内读不完，会落到下面的
                # except socket.timeout → self.close() 杀掉连接，表现为观察者“立即断开/未连接”，
                # 且跨网慢链路每次重连都死在同一处。
                _payload_timeout = self.timeout if self.timeout else (timeout or self.timeout)
                raw = self._recv_exact(packet_length, total_timeout=_payload_timeout)
            except socket.timeout:
                self.close()  # 读包中途超时=半包，关闭连接避免流错位
                raise
            except Exception:
                self.close()
                raise
        finally:
            # close() 会把 self.sock 置 None，此时不能再 unregister，
            # 否则会抛 ValueError 掩蔽原始异常（socket.timeout/包过大等）
            if self.sock is not None:
                sel.unregister(self.sock)
            sel.close()

        if self.compression_threshold >= 0:
            buf = io.BytesIO(raw)
            data_length = read_varint_from_stream(buf)
            remaining = buf.read()
            if data_length == 0:
                decompressed = remaining
            elif data_length < 0:
                self.close()
                raise ValueError(f"解压长度非法: {data_length}")
            else:
                # 解压上限8MB：防止恶意服务器发小压缩包解压出超大内存（zip炸弹）
                if data_length > MAX_UNCOMPRESSED_SIZE:
                    self.close()
                    raise ValueError(f"解压后数据过大: {data_length}")
                # data_length 是服务器自报的，不可信：真正的防线是让解压过程本身在
                # MAX_UNCOMPRESSED_SIZE 处停下。zlib.decompress 没有 max_length 参数，
                # 会先全量解压再返回——200KB 的包就能解出 256MB，先前的"解压后再检查"无效。
                try:
                    dec = zlib.decompressobj(15)
                    decompressed = dec.decompress(remaining, MAX_UNCOMPRESSED_SIZE)
                    # unconsumed_tail 非空说明还有数据没解出来，即超出上限
                    if dec.unconsumed_tail:
                        self.close()
                        raise ValueError("解压后数据过大")
                except zlib.error as e:
                    self.close()
                    raise ValueError("压缩包解压超限或损坏") from e
        else:
            decompressed = raw
        buf = io.BytesIO(decompressed)
        packet_id = read_varint_from_stream(buf)
        payload = buf.read()
        return packet_id, payload

    def _recv_varint(self) -> int:
        result = 0
        num_read = 0
        while True:
            # 取局部引用：close() 可能在别处把 self.sock 置 None，
            # 直接 self.sock.recv 会抛 AttributeError 而不是可读的 ConnectionError
            sock = self.sock
            if sock is None:
                raise ConnectionError("未连接")
            b = sock.recv(1)
            if not b:
                raise ConnectionError("连接已关闭")
            # 启用加密后，长度字段也是加密的，需要先解密
            if getattr(self, '_crypto_backend', None) is not None:
                b = self._decrypt(b)
            byte = b[0]
            result |= (byte & 0x7F) << (7 * num_read)
            num_read += 1
            # MC VarInt 最长 5 字节。原先这个判断写在 break 之后，第 6 字节会被先收下再判断，
            # 实际接受了 6 字节的非法编码。
            if num_read > 5:
                raise ValueError("VarInt 过长")
            if not (byte & 0x80):
                break
        return result

    def _recv_exact(self, n: int, total_timeout: float = 15.0) -> bytes:
        buf = bytearray()
        deadline = time.time() + total_timeout
        while len(buf) < n:
            if time.time() > deadline:
                raise socket.timeout(f"读包中途超时（已读{len(buf)}/{n}）")
            sock = self.sock
            if sock is None:
                raise ConnectionError("连接已关闭")
            try:
                chunk = sock.recv(n - len(buf))
            except socket.timeout:
                continue  # 短暂超时继续，但受 total_timeout 总限制
            if not chunk:
                raise ConnectionError("连接在读取中关闭")
            if getattr(self, '_crypto_backend', None) is not None:
                chunk = self._decrypt(chunk)
            buf.extend(chunk)
        return bytes(buf)
