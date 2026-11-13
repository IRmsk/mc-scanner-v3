#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AuthMe 登录逻辑测试：验证三种模式（auto/login_only/register_then_login）的行为。"""
import os
import sys
import time
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.bot import MCBot


class TestAuthMe:
    """AuthMe 登录模式测试（用mock验证发命令行为，不需要真实服务器）"""

    def _make_bot(self):
        """创建一个mock了send_command的bot"""
        bot = MCBot.__new__(MCBot)
        bot.state = "play"
        bot.chat_callback = None
        bot._sent_commands = []
        # mock send_command
        def fake_send_command(cmd):
            bot._sent_commands.append(cmd)
        bot.send_command = fake_send_command
        return bot

    def test_login_only_does_not_register(self):
        """login_only模式：只发/login，不发/register"""
        bot = self._make_bot()
        bot.authme_login("testpass", mode="login_only", timeout=1.0)
        assert any("login" in c for c in bot._sent_commands), "应发送/login"
        assert not any("register" in c for c in bot._sent_commands), "login_only不应发送/register"

    def test_register_then_login(self):
        """register_then_login模式：先发/register再发/login"""
        bot = self._make_bot()
        bot.authme_login("testpass", mode="register_then_login", timeout=1.0)
        cmds = bot._sent_commands
        assert any("register" in c for c in cmds), "应发送/register"
        assert any("login" in c for c in cmds), "应发送/login"
        # register应在login之前
        reg_idx = next(i for i, c in enumerate(cmds) if "register" in c)
        login_idx = next(i for i, c in enumerate(cmds) if "login" in c)
        assert reg_idx < login_idx, "/register应在/login之前"

    def test_auto_no_register_when_login_succeeds(self):
        """auto模式：login成功（无未注册提示）时不发register"""
        bot = self._make_bot()
        # 模拟服务器回复"登录成功"
        def trigger_success():
            time.sleep(0.3)
            if bot.chat_callback:
                bot.chat_callback("登录成功！欢迎回来", "Server")
        import threading
        t = threading.Thread(target=trigger_success)
        t.start()
        bot.authme_login("testpass", mode="auto", timeout=2.0)
        t.join(timeout=1)
        assert any("login" in c for c in bot._sent_commands), "应发送/login"
        assert not any("register" in c for c in bot._sent_commands), "login成功后不应发送/register"

    def test_auto_register_when_unregistered(self):
        """auto模式：服务器提示未注册时发register"""
        bot = self._make_bot()
        # 模拟服务器回复"请先注册"
        def trigger_unregistered():
            time.sleep(0.3)
            if bot.chat_callback:
                bot.chat_callback("您还未注册，请先使用/register注册", "Server")
        import threading
        t = threading.Thread(target=trigger_unregistered)
        t.start()
        bot.authme_login("testpass", mode="auto", timeout=2.0)
        t.join(timeout=1)
        assert any("login" in c for c in bot._sent_commands), "应先发送/login"
        assert any("register" in c for c in bot._sent_commands), "未注册提示后应发送/register"

    def test_chat_callback_restored(self):
        """authme_login结束后恢复原chat_callback"""
        bot = self._make_bot()
        original_cb = MagicMock()
        bot.chat_callback = original_cb
        bot.authme_login("testpass", mode="login_only", timeout=0.5)
        assert bot.chat_callback is original_cb, "应恢复原chat_callback"
