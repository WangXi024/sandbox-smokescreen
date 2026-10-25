"""人工调用方的模拟验证；不把 mock 结果当作实时 gRPC 验收。"""
import hashlib
import importlib.util
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))
from sandbox_model import demo
spec = importlib.util.spec_from_file_location("host_demo", ROOT / "scripts/demo.py")
host_demo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host_demo)


class FakePB:
    @staticmethod
    def TaskRequest(**fields):
        return SimpleNamespace(inputs=[], network_domains=[], dependencies=[], **fields)

    InputFile = staticmethod(lambda **fields: SimpleNamespace(**fields))
    JobRef = staticmethod(lambda **fields: SimpleNamespace(**fields))


class DemoTests(unittest.TestCase):
    def artifact(self, path="result.json", data=b'{"value":5}'):
        return SimpleNamespace(path=path, data=data, sha256=hashlib.sha256(data).hexdigest())

    def test_task_payloads_and_synthetic_inputs(self):
        for case in demo.CASES:
            request = demo.make_request(case, FakePB)
            for source in request.inputs:
                self.assertEqual(source.sha256, hashlib.sha256(source.data).hexdigest())
        request = demo.make_request("skill", FakePB)
        self.assertEqual(request.entrypoint, "inputs/skill_ok/scripts/summarize.py")
        self.assertNotIn("permit.key", [value.path for value in request.inputs])
        gateway = demo.make_request("gateway", FakePB)
        self.assertEqual(gateway.kind, "skill")

    def test_digest_mismatch_refused(self):
        artifact = self.artifact()
        artifact.sha256 = "0" * 64
        with self.assertRaisesRegex(ValueError, "摘要"):
            demo.checked_artifacts(SimpleNamespace(artifacts=[artifact]))

    def test_remote_path_traversal_refused(self):
        with self.assertRaisesRegex(ValueError, "路径"):
            demo.checked_artifacts(SimpleNamespace(artifacts=[self.artifact("../outside.json")]))

    def test_hash_checked_before_acknowledge(self):
        status = SimpleNamespace(outcome="success", cleanup_done=True, phase="finished", error_code="", elapsed_ms=10, events=[])
        bad = self.artifact()
        bad.sha256 = "0" * 64
        result = SimpleNamespace(status=status, artifacts=[bad])
        calls = []
        stub = SimpleNamespace(Submit=lambda *a, **k: calls.append("submit"), Status=lambda *a, **k: status,
                               Result=lambda *a, **k: result, Cancel=lambda *a, **k: calls.append("cancel"),
                               Acknowledge=lambda *a, **k: calls.append("ack"))
        with self.assertRaisesRegex(ValueError, "摘要"):
            demo.run_job("python", stub, FakePB)
        self.assertNotIn("ack", calls)
        self.assertIn("cancel", calls)

    def test_cancel_calls_cancel_and_requires_cleanup(self):
        statuses = iter([SimpleNamespace(phase="running", outcome=""),
                         SimpleNamespace(phase="finished", outcome="cancelled", cleanup_done=True, error_code="CANCELLED", elapsed_ms=20, events=[])])
        done = SimpleNamespace(cleanup_done=True, delivery_done=True)
        result = SimpleNamespace(status=done, artifacts=[])
        calls = []
        stub = SimpleNamespace(Submit=lambda *a, **k: calls.append("submit"), Status=lambda *a, **k: next(statuses),
                               Result=lambda *a, **k: result, Cancel=lambda *a, **k: calls.append("cancel"),
                               Acknowledge=lambda *a, **k: (calls.append("ack") or done))
        _, record = demo.run_job("cancel", stub, FakePB)
        self.assertEqual(calls, ["submit", "cancel", "ack"])
        self.assertTrue(record["cleanup_done"])
        self.assertTrue(record["delivery_done"])

    def test_host_rejects_symlink_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "outside").mkdir()
            outputs = root / "sandbox_smokescreen_outputs"
            outputs.symlink_to(root / "outside", target_is_directory=True)
            with patch.object(host_demo, "OUTPUTS", outputs):
                with self.assertRaisesRegex(ValueError, "符号链接"):
                    host_demo.destination_path(outputs / "manual/python", "result.json")

    def test_host_rejects_output_traversal(self):
        with self.assertRaisesRegex(ValueError, "路径"):
            host_demo.destination_path(host_demo.OUTPUTS / "manual/python", "../outside.json")


if __name__ == "__main__":
    unittest.main()
