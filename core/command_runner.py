# -*- coding: utf-8 -*-
"""
命令执行器：Bot 登录服务器后自动执行预设命令列表。
支持条件执行（根据服务器响应决定下一步）、延迟控制、结果收集。

吸收自 MCPTool 的 "登录后执行命令列表" 功能。
"""
import re
import time
from dataclasses import dataclass, field
from typing import Optional

from .bot import MCBot


@dataclass
class CommandResult:
    """单条命令执行结果"""
    command: str
    success: bool = False
    response: str = ""
    error: str = ""
    duration: float = 0.0


@dataclass
class CommandScript:
    """命令脚本：按顺序执行的命令列表"""
    commands: list[str] = field(default_factory=list)
    delay: float = 1.0  # 命令间延迟
    # 单条命令等待响应的超时；None 表示沿用 CommandRunner.timeout
    timeout: Optional[float] = None
    stop_on_error: bool = False  # 出错时是否停止

    @classmethod
    def from_file(cls, path: str, delay: float = 1.0) -> "CommandScript":
        """从文件加载命令脚本（每行一条命令，# 开头为注释）"""
        commands = []
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    commands.append(line)
        return cls(commands=commands, delay=delay)

    def add(self, command: str):
        """添加命令"""
        self.commands.append(command)

    def add_conditional(self, condition: str, command: str):
        """添加条件命令（简化版，实际执行时检查）"""
        self.commands.append(f"IF {condition} THEN {command}")


class CommandRunner:
    """命令执行器"""

    def __init__(self, bot: MCBot, delay: float = 1.0, timeout: float = 10.0):
        self.bot = bot
        self.delay = delay
        self.timeout = timeout
        self.results: list[CommandResult] = []
        self._chat_buffer: list[str] = []

    def run_script(self, script: CommandScript) -> list[CommandResult]:
        """执行命令脚本"""
        for cmd in script.commands:
            result = self.execute(cmd, script.timeout)
            self.results.append(result)
            if not result.success and script.stop_on_error:
                break
            time.sleep(script.delay)
        return self.results

    def execute(self, command: str, timeout: Optional[float] = None) -> CommandResult:
        """执行单条命令。timeout 为等待响应的秒数，None 时用 self.timeout。"""
        eff_timeout = float(timeout if timeout is not None else (self.timeout or 10.0))
        result = CommandResult(command=command)
        start = time.time()
        try:
            # 条件命令处理
            if command.upper().startswith("IF "):
                result = self._execute_conditional(command, eff_timeout)
            else:
                if self.bot is None:
                    raise RuntimeError("未提供 bot 实例")
                before = self._chat_baseline()
                self.bot.send_command(command)
                # 等到收到响应或超时：原先固定 time.sleep(delay) 且无条件 success=True，
                # 既没有超时保护，stop_on_error 也永远不生效（结果全是假成功）。
                result.response = self._wait_for_response(before, eff_timeout)
                if result.response:
                    result.success = True
                else:
                    result.error = f"等待 {eff_timeout:.1f}s 未捕获到命令响应"
        except Exception as e:
            result.error = str(e)
            result.success = False
        result.duration = time.time() - start
        return result

    def _chat_baseline(self):
        """增量读取基准：优先用单调序号（不受 chat_messages 头部截断影响），旧 bot 退回长度。"""
        if hasattr(self.bot, "chat_seq"):
            return ("seq", self.bot.chat_seq())
        return ("len", len(self.bot.chat_messages))

    def _chat_since(self, baseline) -> list:
        """按基准取新增聊天。"""
        kind, mark = baseline
        try:
            if kind == "seq":
                messages, _ = self.bot.chat_since(mark)
                return list(messages)
            return list(self.bot.chat_messages[mark:])
        except Exception:
            return []

    def _wait_for_response(self, baseline, timeout: float, settle: float = 0.4) -> str:
        """轮询等待命令响应。收到首条后再等 settle 秒收集同一条响应的后续分包。"""
        deadline = time.time() + max(0.0, timeout)
        while True:
            messages = self._chat_since(baseline)
            if messages:
                settle_end = time.time() + settle
                while time.time() < settle_end:
                    time.sleep(0.1)
                return "\n".join(self._chat_since(baseline) or messages)
            if time.time() >= deadline:
                return ""
            time.sleep(0.1)

    def _execute_conditional(self, command: str, timeout: Optional[float] = None) -> CommandResult:
        """执行条件命令：IF <关键词> THEN <命令>"""
        result = CommandResult(command=command)
        match = re.match(r'IF\s+(.+?)\s+THEN\s+(.+)', command, re.IGNORECASE)
        if not match:
            result.error = "条件命令格式错误"
            return result
        condition, actual_cmd = match.group(1), match.group(2)
        # 检查最近聊天中是否包含条件关键词
        recent = self._get_recent_chat(0).lower()
        if condition.lower() in recent:
            result = self.execute(actual_cmd, timeout)
            result.command = command
        else:
            result.success = True
            result.response = f"条件不满足，跳过: {actual_cmd}"
        return result

    def _get_recent_chat(self, since: int = 0) -> str:
        """获取最近聊天（since>0 时按单调序号取增量，0 表示全部）"""
        try:
            if since and hasattr(self.bot, "chat_seq"):
                messages, _ = self.bot.chat_since(since)
            else:
                messages = self.bot.chat_messages
            return "\n".join(messages) if messages else ""
        except Exception:
            return ""

    def get_summary(self) -> str:
        """获取执行摘要"""
        success = sum(1 for r in self.results if r.success)
        failed = len(self.results) - success
        lines = [
            f"命令执行摘要: 共 {len(self.results)} 条, 成功 {success}, 失败 {failed}",
        ]
        for r in self.results:
            status = "✓" if r.success else "✗"
            lines.append(f"  {status} {r.command}")
            if r.error:
                lines.append(f"    错误: {r.error}")
        return "\n".join(lines)


# 预设的常用命令脚本
PRESET_SCRIPTS = {
    "info": CommandScript(
        commands=["plugins", "version", "help", "list"],
        delay=1.5,
        stop_on_error=False,
    ),
    # ⚠ 占位示例：password 不是真实密码！实际使用请用命令行 --authme 你的密码
    # （走 bot.authme_login 处理，无需手写此脚本），或修改下面的命令为真实密码
    "auth": CommandScript(
        commands=[
            "login password",
            "register password password",
        ],
        delay=2.0,
        stop_on_error=False,
    ),
}


def run_commands_on_server(host: str, port: int, username: str,
                            commands: list[str], delay: float = 1.0,
                            timeout: float = 15.0,
                            authme_password: str = "") -> list[CommandResult]:
    """
    便捷函数：连接服务器并执行命令列表。
    吸收自 MCPTool 的 "send a bot that will execute a list of commands upon login"。
    """
    bot = MCBot(host, port, username=username, timeout=timeout)
    results = []
    try:
        bot.connect()
        # AuthMe 登录
        if authme_password:
            try:
                bot.authme_login(authme_password, mode="auto")
            except Exception:
                pass
        # timeout 必须真正透传到执行器：原先只存在形参里，从未生效
        runner = CommandRunner(bot, delay=delay, timeout=timeout)
        script = CommandScript(commands=commands, delay=delay, timeout=timeout)
        results = runner.run_script(script)
    except Exception as e:
        results.append(CommandResult(command="connect", error=str(e)))
    finally:
        bot.close()
    return results
