"""Compose 调用范围与参数边界；真实部署由集成验收覆盖。"""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import compose_host


class ComposeRunnerTests(unittest.TestCase):
    def test_commands_always_use_this_project(self):
        with patch.object(compose_host.subprocess, "run") as run:
            compose_host.compose("down", "--volumes")
        command = run.call_args.args[0]
        self.assertEqual(command, ["docker", "compose", "--project-directory", str(compose_host.PROJECT),
                                   "-f", str(compose_host.PROJECT / "compose.yaml"), "down", "--volumes"])
        self.assertNotIn("shell", run.call_args.kwargs)

    def test_node_arguments_are_not_shell_commands(self):
        with patch.object(compose_host.subprocess, "run") as run:
            compose_host.node_command("printf", "$(synthetic)", capture=True, timeout=7)
        self.assertEqual(run.call_args.args[0][-5:], ["exec", "-T", "sandbox", "printf", "$(synthetic)"])
        self.assertTrue(run.call_args.kwargs["capture_output"])
        self.assertEqual(run.call_args.kwargs["timeout"], 7)


if __name__ == "__main__":
    unittest.main()
