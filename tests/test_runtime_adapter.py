"""固定运行保护的离线检查；真实 gVisor 和磁盘扫描由 Linux 集成测试覆盖。"""
import os
import shlex
from pathlib import Path
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from docker.types import HostConfig
from sandbox_model import runtime_adapter


def request(**changes):
    values = dict(metadata={"lazyx.job": "job-1"}, image=SimpleNamespace(uri="sandbox-model-runtime:sb0", auth=None), network_policy=None, volumes=None, extensions=None, credential_proxy=None, snapshot_id=None, entrypoint=["sleep", "infinity"], env={"LAZYX_GATEWAY": "http://172.30.1.1:18600"})
    values.update(changes)
    return SimpleNamespace(**values)


class RuntimeAdapterTests(unittest.TestCase):
    def test_entrypoint_reserves_trusted_temporary_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bootstrap = root / "bootstrap.sh"
            bootstrap.write_text('#!/bin/sh\nprintf "%s\\n" "$TMPDIR"\n')
            bootstrap.chmod(0o755)
            script = (Path(__file__).resolve().parents[1] / "deploy/entrypoint.sh").read_text()
            script = script.replace("/run/execd-tmp", str(root / "execd-tmp"))
            # 测试夹具在可能为 noexec 的 tmpfs 中；显式解释脚本，仍验证原入口设置的 TMPDIR。
            script = script.replace('exec /opt/opensandbox/upstream-bootstrap.sh', 'exec sh ' + shlex.quote(str(bootstrap)))
            entrypoint = root / "entrypoint.sh"
            entrypoint.write_text(script)
            result = subprocess.run(["sh", str(entrypoint)], check=True, capture_output=True, text=True,
                env=dict(os.environ, EXECD_TRUSTED_PEER="172.30.1.1", EXECD_ENVS=str(root / "execd.env"), TMPDIR="/tmp"))
            trusted = root / "execd-tmp"
            self.assertEqual(result.stdout.strip(), str(trusted))
            self.assertEqual(trusted.stat().st_mode & 0o777, 0o711)
            self.assertEqual(trusted.stat().st_uid, os.geteuid())

    def test_host_config_has_only_bounded_memory_writes(self):
        config = {"network_mode": "test-job", "mem_limit": 256 * 1024 * 1024, "port_bindings": {"44772": ("0.0.0.0", 19000)}}
        runtime_adapter.harden_host_config(config)
        encoded = HostConfig(version="1.45", **config)
        self.assertTrue(encoded["ReadonlyRootfs"])
        self.assertEqual(encoded["Runtime"], "runsc")
        self.assertEqual(encoded["MemorySwap"], encoded["Memory"])
        self.assertEqual(encoded["LogConfig"]["Type"], "none")
        self.assertEqual(encoded["PortBindings"]["44772/tcp"][0]["HostIp"], "127.0.0.1")
        self.assertEqual(encoded["CapDrop"], ["ALL"])
        self.assertEqual(set(encoded["CapAdd"]), {"CHOWN", "SETUID", "SETGID", "DAC_OVERRIDE", "KILL"})
        self.assertNotIn("NET_RAW", encoded["CapAdd"])
        self.assertNotIn("NET_ADMIN", encoded["CapAdd"])
        self.assertEqual(encoded["Ulimits"], [{"Name": "core", "Soft": 0, "Hard": 0}, {"Name": "nproc", "Soft": 128, "Hard": 128}])
        self.assertEqual(encoded["PidsLimit"], 512)
        self.assertEqual(set(encoded["Tmpfs"]), {"/workspace", "/tmp", "/var/tmp", "/run", "/home/sandbox"})
        self.assertTrue(all("size=" in value for value in encoded["Tmpfs"].values()))

    def test_memory_limit_required_and_host_mounts_rejected(self):
        for config in ({}, {"mem_limit": 0}, {"mem_limit": 256, "binds": ["/secret:/data:ro"]}, {"mem_limit": 256, "privileged": True}, {"mem_limit": 256, "device_requests": [{"Count": -1}]}):
            with self.subTest(config=config), self.assertRaises(ValueError):
                runtime_adapter.harden_host_config(config)

    def test_trusted_gateway_is_allowed(self):
        self.assertEqual(runtime_adapter.validate_request(request(), {"sandbox-model-runtime:sb0"}), "job-1")

    def test_unregistered_image_and_credentials_rejected(self):
        for image in (SimpleNamespace(uri="evil:latest", auth=None), SimpleNamespace(uri="sandbox-model-runtime:sb0", auth=object())):
            with self.subTest(image=image), self.assertRaises(ValueError):
                runtime_adapter.validate_request(request(image=image), {"sandbox-model-runtime:sb0"})

    def test_control_credentials_and_bootstrap_injection_rejected(self):
        for env in ({"API_KEY": "synthetic"}, {"EXECD_ACCESS_TOKEN": "synthetic"}, {"EXECD_BOOTSTRAP_PRE_SCRIPT": "/workspace/evil.sh"}, {"HTTP_PROXY": "http://synthetic:secret@proxy:3128"}):
            with self.subTest(env=env), self.assertRaises(ValueError):
                runtime_adapter.validate_request(request(env=env), {"sandbox-model-runtime:sb0"})

    def test_untrusted_start_command_and_missing_identity_rejected(self):
        for override in ({"metadata": {}}, {"entrypoint": ["sh", "-c", "malicious"]}):
            with self.subTest(override=override), self.assertRaises(ValueError):
                runtime_adapter.validate_request(request(**override), {"sandbox-model-runtime:sb0"})

    def test_other_runtime_paths_rejected(self):
        for key in ("network_policy", "volumes", "extensions", "credential_proxy", "snapshot_id"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                runtime_adapter.validate_request(request(**{key: object()}), {"sandbox-model-runtime:sb0"})

    def test_version_mismatch_fails_before_docker(self):
        with patch.object(runtime_adapter, "_INSTALLED", False), patch.object(runtime_adapter, "version", return_value="9.9.9"), self.assertRaises(RuntimeError):
            runtime_adapter.install(object())


if __name__ == "__main__":
    unittest.main()
