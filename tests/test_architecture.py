"""Architecture aliases and platform identities must agree across runtime and cache."""
import unittest
from unittest.mock import patch

from sandbox_model.architecture import runtime_architecture, runtime_platform


class ArchitectureTests(unittest.TestCase):
    def test_supported_host_aliases(self):
        for machine, expected in [('x86_64', 'amd64'), ('AMD64', 'amd64'),
                                  ('aarch64', 'arm64'), ('arm64', 'arm64')]:
            with self.subTest(machine=machine):
                self.assertEqual(runtime_architecture(machine), expected)
                self.assertEqual(runtime_platform(machine), 'linux/' + expected)

    def test_unknown_architecture_fails_closed(self):
        for machine in ('i686', 'riscv64', ''):
            with self.subTest(machine=machine):
                with self.assertRaisesRegex(ValueError, 'UNSUPPORTED_NODE_ARCHITECTURE'):
                    runtime_architecture(machine)

    def test_machine_is_resolved_at_runtime(self):
        with patch('sandbox_model.architecture.platform.machine', return_value='x86_64'):
            self.assertEqual(runtime_architecture(), 'amd64')
            self.assertEqual(runtime_platform(), 'linux/amd64')
        with patch('sandbox_model.architecture.platform.machine', return_value='aarch64'):
            self.assertEqual(runtime_architecture(), 'arm64')
            self.assertEqual(runtime_platform(), 'linux/arm64')
