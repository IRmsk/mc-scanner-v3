#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
v3.3 新增：命令执行器测试。
测试命令脚本解析、条件命令、结果统计（不实际连接服务器）。
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.command_runner import CommandResult, CommandRunner, CommandScript


class TestCommandResult(unittest.TestCase):
    """命令结果测试"""

    def test_result_init(self):
        r = CommandResult("/list", True, "There are 2 players")
        self.assertEqual(r.command, "/list")
        self.assertTrue(r.success)
        self.assertEqual(r.response, "There are 2 players")

    def test_result_failed(self):
        r = CommandResult("/plugins", False, "", error="Connection refused")
        self.assertFalse(r.success)
        self.assertEqual(r.error, "Connection refused")


class TestCommandScript(unittest.TestCase):
    """命令脚本测试"""

    def test_script_init(self):
        script = CommandScript(delay=2.0)
        self.assertEqual(script.delay, 2.0)
        self.assertEqual(len(script.commands), 0)

    def test_add_command(self):
        script = CommandScript()
        script.add("/plugins")
        script.add("/version")
        self.assertEqual(len(script.commands), 2)
        self.assertEqual(script.commands[0], "/plugins")

    def test_add_conditional(self):
        script = CommandScript()
        script.add_conditional("logged in", "/plugins")
        self.assertEqual(len(script.commands), 1)
        self.assertIn("IF", script.commands[0])

    def test_from_file(self):
        tmp = tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode='w')
        tmp.write("# 注释行\n/plugins\n/version\n\n/help\n")
        tmp.close()
        try:
            script = CommandScript.from_file(tmp.name, delay=1.5)
            self.assertEqual(script.delay, 1.5)
            # 注释和空行应被跳过
            self.assertEqual(len(script.commands), 3)
            self.assertEqual(script.commands[0], "/plugins")
        finally:
            os.unlink(tmp.name)

    def test_from_file_nonexistent(self):
        with self.assertRaises(FileNotFoundError):
            CommandScript.from_file("/tmp/nonexistent_script_12345.txt")


class TestCommandRunner(unittest.TestCase):
    """命令执行器测试"""

    def test_runner_init(self):
        # bot 可以是 None，因为我们不实际执行
        runner = CommandRunner(bot=None, delay=1.0, timeout=5.0)
        self.assertEqual(runner.delay, 1.0)
        self.assertEqual(runner.timeout, 5.0)
        self.assertEqual(len(runner.results), 0)

    def test_get_summary_empty(self):
        runner = CommandRunner(bot=None)
        summary = runner.get_summary()
        # 精确断言摘要格式：原来 assertIn("0", summary) 任何含 0 的输出都能通过
        self.assertEqual(summary, "命令执行摘要: 共 0 条, 成功 0, 失败 0")

    def test_execute_without_bot(self):
        """没有 bot 时执行应失败但不崩溃"""
        runner = CommandRunner(bot=None, timeout=1.0)
        result = runner.execute("/list")
        self.assertIsInstance(result, CommandResult)
        self.assertFalse(result.success)

    def test_run_script_without_bot(self):
        """没有 bot 时运行脚本应全部失败但不崩溃"""
        runner = CommandRunner(bot=None, timeout=0.5)
        script = CommandScript(delay=0.1)
        script.add("/plugins")
        script.add("/version")
        results = runner.run_script(script)
        self.assertEqual(len(results), 2)
        for r in results:
            self.assertFalse(r.success)

    def test_summary_after_results(self):
        runner = CommandRunner(bot=None, timeout=0.5)
        runner.results = [
            CommandResult("/a", True, "ok"),
            CommandResult("/b", False, "", error="fail"),
        ]
        summary = runner.get_summary()
        # 断言具体的统计字段而不是裸 "1"（"共 1 条"、"成功 11" 里也都含 1）
        self.assertIn("共 2 条", summary)
        self.assertIn("成功 1", summary)
        self.assertIn("失败 1", summary)
        self.assertIn("✓ /a", summary)
        self.assertIn("✗ /b", summary)


if __name__ == "__main__":
    unittest.main()
