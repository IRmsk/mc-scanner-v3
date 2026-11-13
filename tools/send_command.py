#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
命令执行工具：登录服务器并发送命令（仅限授权服务器使用）。
用法:
  python tools/send_command.py 1.2.3.4 25565 BotName "list"
  python tools/send_command.py 1.2.3.4 25565 BotName --proto 767 "help"
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.bot import MCBot


def main():
    parser = argparse.ArgumentParser(description="Minecraft 服务器命令执行工具")
    parser.add_argument("host", help="服务器 IP")
    parser.add_argument("port", type=int, help="端口")
    parser.add_argument("username", help="机器人用户名")
    parser.add_argument("command", help="要执行的命令（不含前导 /）")
    parser.add_argument("--proto", type=int, default=None, help="协议版本（默认自动检测）")
    parser.add_argument("--timeout", type=float, default=15.0, help="超时秒数")
    parser.add_argument("--hold", type=float, default=3.0, help="发送后保持连接秒数")
    args = parser.parse_args()

    print(f"[*] 连接 {args.host}:{args.port} (用户: {args.username})")
    bot = MCBot(args.host, args.port, protocol_version=args.proto,
                username=args.username, timeout=args.timeout)
    try:
        bot.connect()
        print(f"[+] 登录成功 (协议 {bot.protocol_version}, {bot.version_name if hasattr(bot, 'version_name') else ''})")
        print(f"[*] 执行命令: /{args.command}")
        bot.send_command(args.command)
        print("[+] 命令已发送")
        bot.keep_alive(args.hold)
        print(f"[*] 保持连接 {args.hold}s 后退出")
    except Exception as e:
        print(f"[!] 失败: {e}")
        sys.exit(1)
    finally:
        bot.close()


if __name__ == "__main__":
    main()
