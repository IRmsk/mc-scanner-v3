#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Mock Minecraft 服务器，用于测试。
支持完整流程：SLP 响应 → 登录 → Configuration → Play。
包 ID 为官方手工核对常量，与实现分离。
"""
import io
import json
import os
import socket
import struct
import sys
import threading
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.buffer import read_varint_from_stream, write_string, write_varint
from core.conn import PROTO_STATE_LOGIN, PROTO_STATE_STATUS


class SocketStream:
    def __init__(self, sock):
        self.sock = sock

    def read(self, n):
        buf = b''
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("closed")
            buf += chunk
        return buf


class MockMCServer:
    def __init__(self, host="127.0.0.1", port=0, mode="cracked",
                 protocol=767, version_name="1.21.1", motd="Mock Server",
                 players_online=5, players_max=100):
        self.host = host
        self.port = port
        self.mode = mode
        self.protocol = protocol
        self.version_name = version_name
        self.motd = motd
        self.players_online = players_online
        self.players_max = players_max
        self.server_socket = None
        self.running = False
        self.thread = None
        self.received_messages = []
        # 配置阶段收到的品牌/插件消息（模组服测试）
        self.received_brands = []

    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.port = self.server_socket.getsockname()[1]
        self.running = True
        self.thread = threading.Thread(target=self._accept_loop, daemon=True)
        self.thread.start()
        return self

    def stop(self):
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                pass

    def _accept_loop(self):
        while self.running:
            try:
                self.server_socket.settimeout(1.0)
                conn, addr = self.server_socket.accept()
                t = threading.Thread(target=self._handle_client, args=(conn,), daemon=True)
                t.start()
            except socket.timeout:
                continue
            except Exception:
                break

    def _handle_client(self, conn):
        try:
            conn.settimeout(8.0)
            stream = SocketStream(conn)
            STATE_HANDSHAKE = 0
            STATE_CONFIG = 3
            STATE_PLAY = 4
            state = STATE_HANDSHAKE
            username = "TestBot"
            last_ka = time.time()

            while True:
                length = read_varint_from_stream(stream)
                if length <= 0 or length > 1024 * 1024:
                    break
                data = stream.read(length)

                buf = io.BytesIO(data)
                packet_id = read_varint_from_stream(buf)
                payload = buf.read()

                if state == STATE_HANDSHAKE:
                    if packet_id == 0x00:
                        off = 0
                        proto, off = _read_varint(payload, off)
                        host, off = _read_string(payload, off)
                        off += 2  # port
                        next_state, off = _read_varint(payload, off)
                        state = next_state
                    continue

                elif state == PROTO_STATE_STATUS:
                    if packet_id == 0x00:
                        self._send_packet(conn, 0x00, write_string(json.dumps({
                            "version": {"name": self.version_name, "protocol": self.protocol},
                            "players": {"online": self.players_online, "max": self.players_max},
                            "description": {"text": self.motd},
                        })))
                    elif packet_id == 0x01:
                        conn.sendall(write_varint(len(data)) + data)
                        return

                elif state == PROTO_STATE_LOGIN:
                    if packet_id == 0x00:  # Login Start
                        if self.mode == "online":
                            self._send_packet(conn, 0x01, write_string("") + b"\x00" + write_varint(0) + b"\x00" * 4)
                            return
                        elif self.mode == "whitelist":
                            self._send_disconnect(conn, "You are not whitelisted on this server!")
                            return
                        elif self.mode == "rejected":
                            self._send_disconnect(conn, "Connection rejected")
                            return
                        elif self.mode == "forge":
                            # 模拟 Forge FML2/FML3 登录握手：登录阶段发插件请求，客户端必须回应才放行
                            try:
                                username, _ = _read_string(payload, 0)
                            except Exception:
                                username = "TestBot"
                            self._send_packet(conn, 0x04,
                                              write_varint(1) + write_string("fml:loginwrapper") + b"\x00")
                            conn.settimeout(3.0)
                            try:
                                rlen = read_varint_from_stream(stream)
                                rdata = stream.read(rlen)
                                rbuf = io.BytesIO(rdata)
                                rpid = read_varint_from_stream(rbuf)
                                if rpid != 0x02:  # 必须收到 LoginPluginResponse
                                    raise ConnectionError("no plugin response")
                            except Exception:
                                return  # 客户端未响应插件消息 → 服务端挂起/断开
                            conn.settimeout(8.0)
                            player_uuid = uuid.uuid3(uuid.NAMESPACE_OID, f"OfflinePlayer:{username}")
                            self._send_packet(conn, 0x02, write_uuid(player_uuid) + write_string(username))
                        else:
                            try:
                                username, _ = _read_string(payload, 0)
                            except Exception:
                                pass
                            player_uuid = uuid.uuid3(uuid.NAMESPACE_OID, f"OfflinePlayer:{username}")
                            self._send_packet(conn, 0x02, write_uuid(player_uuid) + write_string(username))
                    elif packet_id == 0x03:  # Login Acknowledged
                        if self.protocol >= 764:
                            state = STATE_CONFIG
                            # 发送 Known Packs 询问
                            self._send_packet(conn, 0x0E, write_varint(0))
                        else:
                            state = STATE_PLAY
                            self._send_login_play(conn)
                            self._send_keep_alive(conn)

                elif state == STATE_CONFIG:
                    if packet_id == 0x00:  # Client Information
                        # 模拟服务端询问品牌（vanilla 客户端需回 minecraft:brand）
                        self._send_packet(conn, 0x01, write_string("minecraft:brand"))
                    elif packet_id == 0x02:  # Custom Payload（客户端插件消息）
                        try:
                            chan, _ = _read_string(payload, 0)
                            if chan in ("minecraft:brand", "MC|Brand"):
                                self.received_brands.append(payload)
                        except Exception:
                            pass
                    elif packet_id == 0x07:  # Known Packs (client response)
                        # 客户端回应Known Packs后，服务器主动发Finish Configuration
                        self._send_packet(conn, 0x03, b"")  # Finish Configuration (server)
                    elif packet_id == 0x03:  # Finish Configuration (client)
                        # 客户端回应Finish，进入Play
                        state = STATE_PLAY
                        self._send_login_play(conn)
                        self._send_keep_alive(conn)
                    elif packet_id == 0x04:  # Keep Alive
                        conn.sendall(write_varint(len(data)) + data)
                    elif packet_id == 0x05:  # Ping
                        conn.sendall(write_varint(len(data)) + data)
                    # 其他包忽略

                elif state == STATE_PLAY:
                    if packet_id == 0x1B:  # Keep Alive response
                        pass
                    elif packet_id in (0x08, 0x03, 0x05):  # Chat Message (各版本)
                        try:
                            msg, _ = _read_string(payload, 0)
                            self.received_messages.append(msg)
                        except Exception:
                            pass
                    elif packet_id == 0x06:  # Chat Command
                        pass
                    elif packet_id == 0x00:  # Confirm Teleport
                        pass
                    elif packet_id == 0x2C:  # Pong
                        pass

                    if time.time() - last_ka > 3:
                        self._send_keep_alive(conn)
                        last_ka = time.time()

        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _send_packet(self, conn, packet_id, payload=b""):
        body = write_varint(packet_id) + payload
        conn.sendall(write_varint(len(body)) + body)

    def _send_disconnect(self, conn, reason):
        msg = json.dumps({"text": reason})
        self._send_packet(conn, 0x00, write_string(msg))

    def _send_login_play(self, conn):
        login_play = (
            struct.pack(">i", 1) + b"\x00" + write_varint(1)
            + write_string("minecraft:overworld")
            + write_string("minecraft:overworld")
            + write_string("minecraft:overworld")
            + struct.pack(">q", 0) + write_varint(20)
            + write_varint(8) + write_varint(8)
            + b"\x00" + b"\x01" + b"\x00" + b"\x00" + b"\x00" + b"\x00"
            + struct.pack(">i", 0)
        )
        self._send_packet(conn, 0x30, login_play)

    def _send_keep_alive(self, conn):
        self._send_packet(conn, 0x2B, struct.pack(">q", 12345))


def _read_varint(data, offset):
    result = 0
    num_read = 0
    while True:
        byte = data[offset + num_read]
        result |= (byte & 0x7F) << (7 * num_read)
        num_read += 1
        if not (byte & 0x80):
            break
    if result >= (1 << 31):
        result -= (1 << 32)
    return result, offset + num_read


def _read_string(data, offset):
    length, offset = _read_varint(data, offset)
    s = data[offset:offset + length].decode("utf-8", errors="replace")
    return s, offset + length


def write_uuid(u):
    return u.int.to_bytes(16, "big")


if __name__ == "__main__":
    server = MockMCServer(mode="cracked", port=25565)
    server.start()
    print(f"Mock server running on {server.host}:{server.port} (mode={server.mode})")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        server.stop()
        print("Stopped")
