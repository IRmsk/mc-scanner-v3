# -*- coding: utf-8 -*-
import json
import os
import threading
import time
from collections import deque
from datetime import datetime

from core.bot import MCBot
from core.protocol import get_version_name

try:
    from web import state
except ImportError:
    import state  # type: ignore


class ObserverSession:
    """单个服务器观察者会话，支持自动重连和聊天实时落盘"""

    def __init__(self, host, port, username, authme_password=None, timeout=20.0,
                 duration=0, protocol_version=None, keywords=None,
                 max_reconnect=5, use_premium=True, premium_uuid=None):
        self.session_id = ""
        self.duration = duration  # 观察时长（秒），0=一直观察
        self.host = host
        self.port = port
        self.username = username
        self.authme_password = authme_password
        self.timeout = timeout
        self.protocol_version = protocol_version
        self.keywords = keywords or []  # 关键词告警
        self.max_reconnect = max_reconnect
        self.use_premium = use_premium  # 是否使用正版账户登录
        self.premium_uuid = premium_uuid  # 指定正版账户UUID，None则用config活跃账户
        self.bot = None
        self.thread = None
        self.stop_event = threading.Event()
        # RLock：_next_seq/_ensure_log_file/_append_log 会互相嵌套取锁
        self.lock = threading.RLock()
        self.status = "connecting"  # connecting / connected / reconnecting / disconnected / stopped / error
        self.error = ""
        self.auth_mode = "unknown"
        self.version_name = ""
        self.start_time = time.time()
        self.connect_time = None
        self.disconnect_time = None
        self.reconnect_count = 0
        self.chat_log = deque(maxlen=2000)   # (seq, time_str, sender, text)
        self.events = deque(maxlen=4000)     # (seq, time_str, type, ...)
        self._seq = 0
        self._log_file = None
        self._log_file_path = None

    def _next_seq(self):
        # bot 回调线程与主循环并发调用，无锁时 seq 会重复，前端增量拉取（since）会漏消息
        with self.lock:
            self._seq += 1
            return self._seq

    @staticmethod
    def _ts():
        return datetime.now().strftime("%H:%M:%S")

    def _ensure_log_file(self):
        """确保日志文件打开，实时追加写入。

        加锁：多线程同时进来会重复 open 同一路径，泄漏文件句柄。
        """
        with self.lock:
            if self._log_file is not None:
                return
            try:
                os.makedirs('observer_logs', exist_ok=True)
                safe_id = self.session_id.replace('/', '_').replace('\\', '_')
                self._log_file_path = f'observer_logs/{safe_id}.jsonl'
                self._log_file = open(self._log_file_path, 'a', encoding='utf-8')
            except Exception:
                self._log_file = None

    def _append_log(self, event_type, data):
        """实时追加一条事件到日志文件（加锁：并发写会行交错、JSON 半截）"""
        try:
            with self.lock:
                self._ensure_log_file()
                if self._log_file:
                    record = {"time": self._ts(), "type": event_type}
                    record.update(data)
                    self._log_file.write(json.dumps(record, ensure_ascii=False) + "\n")
                    self._log_file.flush()
        except Exception:
            pass

    def _check_keywords(self, text):
        """检查关键词并触发告警"""
        if not self.keywords:
            return
        for kw in self.keywords:
            if kw and kw in text:
                self._append_log("keyword_alert", {"keyword": kw, "text": text[:200]})
                # 触发邮件告警（异步，不阻塞）
                try:
                    import config
                    if config.get("email_enabled"):
                        from core.notifier import send_email
                        subject = f"[观察者关键词告警] {kw} @ {self.host}:{self.port}"
                        body = f"服务器: {self.host}:{self.port}\n关键词: {kw}\n内容: {text[:300]}\n时间: {datetime.now()}"
                        threading.Thread(target=send_email, args=(subject, body), daemon=True).start()
                except Exception:
                    pass
                break

    def _on_chat(self, text, sender="未知"):
        try:
            seq = self._next_seq()
            with self.lock:
                self.events.append((seq, self._ts(), "chat", sender, text))
                self.chat_log.append((seq, self._ts(), sender, text))
            self._append_log("chat", {"sender": sender, "text": text})
            self._check_keywords(text)
        except Exception:
            pass

    def _on_player(self, name, action):
        try:
            seq = self._next_seq()
            with self.lock:
                self.events.append((seq, self._ts(), action, name))
            self._append_log("player", {"action": action, "name": name})
        except Exception:
            pass

    def _save_final(self):
        """会话结束时保存完整JSON快照（0条聊天消息不存）"""
        try:
            with self.lock:
                if not self.chat_log:
                    return  # 空会话不保存
                os.makedirs('observer_logs', exist_ok=True)
                safe_id = self.session_id.replace('/', '_').replace('\\', '_')
                with open(f'observer_logs/{safe_id}.json', 'w', encoding='utf-8') as f:
                    json.dump({
                        'session_id': self.session_id,
                        'host': self.host, 'port': self.port,
                        'username': self.username,
                        'status': self.status,
                        'chat_log': list(self.chat_log),
                        'events': list(self.events),
                        'reconnect_count': self.reconnect_count,
                        'saved_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    }, f, ensure_ascii=False)
        except Exception:
            pass
        finally:
            with self.lock:
                if self._log_file:
                    try:
                        self._log_file.close()
                    except Exception:
                        pass
                    self._log_file = None

    def run(self):
        """运行主循环，断开后自动指数退避重连"""
        reconnect_delay = 5.0

        while not self.stop_event.is_set():
            try:
                # 重连前关闭旧bot，避免socket泄漏
                if self.bot:
                    try:
                        self.bot.close()
                    except Exception:
                        pass
                    self.bot = None
                self.bot = MCBot(host=self.host, port=self.port,
                                 username=self.username, timeout=self.timeout,
                                 protocol_version=self.protocol_version,
                                 use_premium=self.use_premium,
                                 premium_uuid=self.premium_uuid)
                self.bot.chat_callback = self._on_chat
                self.bot.player_callback = self._on_player
                self.bot.connect()
                with self.lock:
                    self.status = "connected"
                    self.auth_mode = getattr(self.bot, 'auth_mode', 'unknown')
                    self.version_name = get_version_name(self.bot.protocol_version)
                    self.protocol_version = self.bot.protocol_version
                    self.connect_time = time.time()
                    self.error = ""
                self.reconnect_count = 0
                reconnect_delay = 5.0
                self._append_log("system", {"text": f"已连接 {self.host}:{self.port}"})
                if self.authme_password:
                    # 先等服务器 Play 阶段就绪再发 /login，避免命令被吞导致"不登录"
                    time.sleep(1.5)
                    try:
                        self.bot.authme_login(self.authme_password, mode="auto")
                        if getattr(self.bot, "_authme_failed", False):
                            self._append_log("system", {"text": "AuthMe 登录失败：密码错误或账号被锁定（检查密码/是否已注册）"})
                        else:
                            self._append_log("system", {"text": "AuthMe 登录命令已发送"})
                    except Exception as e:
                        self._append_log("system", {"text": f"AuthMe 登录异常: {e}"})
                # 保持连接
                while not self.stop_event.is_set():
                    if not getattr(self.bot, "connected", True):
                        with self.lock:
                            self.status = "reconnecting"
                            self.disconnect_time = time.time()
                        self._append_log("system", {"text": "连接断开，准备重连"})
                        break
                    if self.duration > 0 and self.connect_time and (time.time() - self.connect_time) >= self.duration:
                        with self.lock:
                            self.status = "stopped"
                            self.disconnect_time = time.time()
                        self._append_log("system", {"text": "观察时长到期，停止"})
                        self._cleanup()
                        return
                    time.sleep(0.5)
                if self.stop_event.is_set():
                    break
            except Exception as e:
                with self.lock:
                    self.status = "error"
                    self.error = str(e)[:300]
                self._append_log("error", {"text": str(e)[:300]})
                err_str = str(e)
                # Connection refused说明端口没开，服务器大概率下线了，只重试1次就放弃
                if "Connection refused" in err_str or "Errno 111" in err_str:
                    print(f"[观察者] {self.username}@{self.host}:{self.port} 端口未开放({err_str[:50]})")
                    if self.reconnect_count >= 1:
                        print(f"[观察者] {self.username}@{self.host}:{self.port} 端口未开放，停止重连")
                        with self.lock:
                            self.status = "disconnected"
                        self._append_log("system", {"text": "端口未开放，停止重连"})
                        break
                else:
                    print(f"[观察者错误] {self.username}@{self.host}:{self.port} - {e}")

            if self.stop_event.is_set():
                break
            if self.reconnect_count >= self.max_reconnect:
                with self.lock:
                    self.status = "disconnected"
                self._append_log("system", {"text": f"达到最大重连次数({self.max_reconnect})，停止"})
                break
            self.reconnect_count += 1
            print(f"[观察者] {self.username}@{self.host}:{self.port} 断开，{reconnect_delay:.0f}秒后第{self.reconnect_count}次重连...")
            with self.lock:
                self.status = "reconnecting"
            # 指数退避等待，可被stop中断
            wait_end = time.time() + reconnect_delay
            while time.time() < wait_end and not self.stop_event.is_set():
                time.sleep(0.5)
            reconnect_delay = min(reconnect_delay * 1.5, 60.0)

        # 真正结束
        with self.lock:
            if self.status not in ("stopped", "disconnected"):
                self.status = "stopped"
            self.disconnect_time = time.time()
        self._cleanup()

    def _cleanup(self):
        """清理资源：关闭bot、保存日志、从全局字典移除"""
        if self.bot:
            try:
                self.bot.close()
            except Exception:
                pass
        self._save_final()
        # 从全局字典移除
        try:
            observer_sessions = getattr(state, 'observer_sessions', {})
            observer_lock = getattr(state, 'observer_lock', None)
            if observer_lock:
                with observer_lock:
                    observer_sessions.pop(self.session_id, None)
            else:
                observer_sessions.pop(self.session_id, None)
        except Exception:
            pass

    def stop(self):
        self.stop_event.set()

    def _players(self):
        if not self.bot:
            return []
        try:
            return sorted(set(v for v in self.bot.player_list.values() if v))
        except Exception:
            return []

    def brief(self):
        with self.lock:
            return {
                "session_id": self.session_id,
                "host": self.host,
                "port": self.port,
                "username": self.username,
                "status": self.status,
                "error": self.error,
                "auth_mode": self.auth_mode,
                "version_name": self.version_name,
                "uptime": time.time() - self.start_time,
                "players_online": len(self._players()),
                "chat_count": len(self.chat_log),
                "reconnect_count": self.reconnect_count,
            }

    def full(self, since=None):
        with self.lock:
            players = self._players()
            all_events = list(self.events)
            last_seq = self._seq
        if since is not None:
            all_events = [e for e in all_events if e[0] > since]
        events_out = []
        for e in all_events[-100:]:
            if e[2] == "chat":
                events_out.append({"seq": e[0], "time": e[1], "type": e[2], "sender": e[3], "text": e[4]})
            else:
                events_out.append({"seq": e[0], "time": e[1], "type": e[2], "name": e[3]})
        return {
            "session_id": self.session_id,
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "status": self.status,
            "error": self.error,
            "auth_mode": self.auth_mode,
            "version_name": self.version_name,
            "protocol_version": self.protocol_version,
            "start_time": self.start_time,
            "connect_time": self.connect_time,
            "uptime": time.time() - self.start_time,
            "players_online": len(players),
            "players": players,
            "events": events_out,
            "last_seq": last_seq,
            "chat": list(self.chat_log),
            "reconnect_count": self.reconnect_count,
        }
