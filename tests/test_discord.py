#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
v3.2.1 新增：Discord Webhook 通知测试。
验证通知器的消息构建和冷却逻辑（不实际发送网络请求）。
"""
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from notify.discord import DiscordNotifier


class TestDiscordNotifier(unittest.TestCase):
    """Discord 通知器测试"""

    def setUp(self):
        self.notifier = DiscordNotifier("https://discord.com/api/webhooks/test/123")

    def test_init(self):
        self.assertEqual(self.notifier.webhook_url, "https://discord.com/api/webhooks/test/123")
        self.assertEqual(self.notifier.username, "MC Scanner")

    def test_empty_webhook_skips(self):
        n = DiscordNotifier("")
        result = n.send("test")
        self.assertFalse(result)

    @patch("notify.discord.urllib.request.urlopen")
    def test_send_success(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.status = 204
        mock_urlopen.return_value.__enter__.return_value = mock_response
        result = self.notifier.send("Hello World")
        self.assertTrue(result)
        mock_urlopen.assert_called_once()

    @patch("notify.discord.urllib.request.urlopen")
    def test_send_with_embed(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.status = 204
        mock_urlopen.return_value.__enter__.return_value = mock_response
        embed = {"title": "Test", "description": "Desc", "color": 0x00FF00}
        result = self.notifier.send(embed=embed)
        self.assertTrue(result)

    def test_notify_new_server_builds_embed(self):
        server = {
            "ip": "1.2.3.4", "port": 25565,
            "version": "Paper 1.20.4", "motd": "My Server",
            "players_online": 5, "players_max": 20,
            "auth": "cracked", "ping_ms": 45,
        }
        with patch.object(self.notifier, "send", return_value=True) as mock_send:
            self.notifier.notify_new_server(server)
            mock_send.assert_called_once()
            call_args = mock_send.call_args
            self.assertIsNotNone(call_args[1].get("embed"))

    def test_notify_cracked_server(self):
        server = {
            "ip": "1.2.3.4", "port": 25565,
            "version": "Paper 1.20.4", "motd": "Cracked Server",
            "players_online": 10, "players_max": 50,
            "auth": "cracked",
        }
        with patch.object(self.notifier, "send", return_value=True) as mock_send:
            self.notifier.notify_cracked_server(server)
            mock_send.assert_called_once()

    def test_cooldown_prevents_duplicate(self):
        server = {"ip": "1.2.3.4", "port": 25565, "version": "Paper", "motd": "Test"}
        with patch.object(self.notifier, "send", return_value=True) as mock_send:
            self.notifier.notify_new_server(server)
            self.notifier.notify_new_server(server)  # 第二次应被冷却阻止
            self.assertEqual(mock_send.call_count, 1)

    def test_notify_player_join(self):
        server = {"ip": "1.2.3.4", "port": 25565, "version": "Paper"}
        with patch.object(self.notifier, "send", return_value=True) as mock_send:
            self.notifier.notify_player_join(server, "TestPlayer")
            mock_send.assert_called_once()

    def test_notify_player_leave(self):
        server = {"ip": "1.2.3.4", "port": 25565, "version": "Paper"}
        with patch.object(self.notifier, "send", return_value=True) as mock_send:
            self.notifier.notify_player_leave(server, "TestPlayer")
            mock_send.assert_called_once()


if __name__ == "__main__":
    unittest.main()
