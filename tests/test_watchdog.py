"""回收守护程序离线检查，不操作真实 Docker 或宿主进程。"""
import builtins
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest

from sandbox_model.opensandbox_process import RegistryNetwork
from sandbox_model.watchdog import Watchdog, atomic_json, pid_alive, read_private_json


class Container:
    def __init__(self, job, project="true"):
        self.id = job + "-id"
        self.name = "sb-task-" + job
        self.labels = {"lazyx.sb": project, "lazyx.job": job}
        self.removed = False

    def remove(self, force):
        self.removed = True


class Containers:
    def __init__(self, values, ignore_filter=False):
        self.values = values
        self.ignore_filter = ignore_filter

    def list(self, all, filters):
        labels = dict(value.split("=", 1) for value in filters["label"])
        return [value for value in self.values if not value.removed and
                (self.ignore_filter or builtins.all(value.labels.get(k) == v for k, v in labels.items()))]


class Network:
    def __init__(self):
        self.calls = []
        self.remaining = {"networks": 0, "rules": 0}

    def restore_context(self, values):
        self.calls.append(("restore", values["job_id"]))

    def revoke(self, job):
        self.calls.append(("revoke", job))

    def release(self, job):
        self.calls.append(("release", job))

    def remaining_resources(self, job):
        return self.remaining


class WatchdogTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.leases = self.root / "leases.json"
        self.report = self.root / "reaped.json"
        self.a, self.b = Container("a"), Container("b")
        self.other = Container("a", project="other")
        self.values = [self.a, self.b, self.other]
        self.containers = Containers(self.values)
        self.network = Network()
        self.clock = 100.0
        self.worker = Watchdog(SimpleNamespace(containers=self.containers),
                               leases=self.leases, report=self.report,
                               clock=lambda: self.clock, alive=lambda pid: pid == 1,
                               network_manager=self.network)
        self.snapshot = {"manager_pid": 1, "opensandbox_pid": 1, "heartbeat": 100,
                         "jobs": {"a": {"deadline": 200, "network": {"job_id": "a"}},
                                  "b": {"deadline": 200, "network": {"job_id": "b"}}}}
        self.save()

    def tearDown(self):
        self.tmp.cleanup()

    def save(self):
        atomic_json(self.leases, self.snapshot)

    def test_healthy_service_does_not_remove_jobs(self):
        self.assertEqual(self.worker.step(), {})
        self.assertFalse(self.a.removed)

    def test_heartbeat_timeout_reaps_only_project_resources(self):
        self.clock = 104
        results = self.worker.step()
        self.assertTrue(self.a.removed and self.b.removed)
        self.assertFalse(self.other.removed)
        self.assertTrue(results["a"]["cleaned"])
        self.assertIn("heartbeat_expired", results["a"]["reason"])
        self.assertEqual(self.report.stat().st_mode & 0o777, 0o600)

    def test_server_death_reaps_even_when_manager_heartbeat_fresh(self):
        self.snapshot["opensandbox_pid"] = 2
        self.save()
        result = self.worker.step()
        self.assertIn("opensandbox_lost", result["a"]["reason"])
        self.assertTrue(self.a.removed)

    def test_manager_death_reaps_even_when_server_alive(self):
        self.snapshot["manager_pid"] = 2
        self.save()
        result = self.worker.step()
        self.assertIn("manager_lost", result["a"]["reason"])

    def test_deadline_expires_one_job_only(self):
        self.snapshot["jobs"]["a"]["deadline"] = 99
        self.save()
        result = self.worker.step()
        self.assertTrue(self.a.removed)
        self.assertFalse(self.b.removed)
        self.assertEqual(result["a"]["reason"], "deadline_expired")

    def test_late_created_container_is_removed_next_pass(self):
        self.clock = 104
        self.worker.step()
        late = Container("a")
        self.values.append(late)
        self.worker.step()
        self.assertTrue(late.removed)

    def test_network_or_firewall_residue_is_not_cleaned(self):
        for kind in ("networks", "rules"):
            with self.subTest(kind=kind):
                self.network.remaining = {"networks": 0, "rules": 0} | {kind: 1}
                result = self.worker.reap("a", self.snapshot["jobs"]["a"], "synthetic")
                self.assertEqual(result["remaining_containers"], 0)
                self.assertFalse(result["cleaned"])
                self.assertEqual(result["remaining_" + kind], 1)

    def test_unconfirmed_disconnect_keeps_proxy_and_address_for_retry(self):
        proxy = Container("a")
        proxy.name = "sb-smokescreen-a"
        self.values.append(proxy)

        def failed_revoke(job):
            raise RuntimeError("synthetic reset failure")

        self.network.revoke = failed_revoke
        result = self.worker.reap("a", self.snapshot["jobs"]["a"], "synthetic")
        self.assertTrue(self.a.removed)
        self.assertFalse(proxy.removed)
        self.assertNotIn(("release", "a"), self.network.calls)
        self.assertFalse(result["cleaned"])

        self.network.revoke = lambda job: None
        result = self.worker.reap("a", self.snapshot["jobs"]["a"], "synthetic")
        self.assertTrue(proxy.removed)
        self.assertIn(("release", "a"), self.network.calls)
        self.assertTrue(result["cleaned"])

    def test_late_network_adds_missing_context_to_orphan_tombstone(self):
        network = SimpleNamespace(attrs={"Labels": {"lazyx.sb": "true", "lazyx.job": "orphan"}})
        self.worker.client.networks = SimpleNamespace(list=lambda **kwargs: [network])
        self.network.orphan_context = lambda network: {"job_id": "orphan"}
        self.worker.expired["orphan"] = ({"network": None}, "orphaned")
        result = self.worker.step()
        self.assertEqual(self.worker.expired["orphan"][0]["network"], {"job_id": "orphan"})
        self.assertIn(("restore", "orphan"), self.network.calls)
        self.assertIn(("release", "orphan"), self.network.calls)
        self.assertTrue(result["orphan"]["cleaned"])

    def test_docker_filter_is_not_only_ownership_check(self):
        self.containers.ignore_filter = True
        self.snapshot["jobs"].pop("b")
        self.snapshot["jobs"]["a"]["deadline"] = 99
        self.save()
        self.worker.step()
        self.assertTrue(self.a.removed)
        self.assertFalse(self.other.removed)
        self.assertFalse(self.b.removed)

    def test_corrupt_metadata_stops_previously_known_jobs(self):
        self.worker.step()
        self.leases.write_text("{")
        self.worker.step()
        self.assertTrue(self.a.removed and self.b.removed)

    def test_lease_permissions_and_symlink_are_rejected(self):
        self.leases.chmod(0o644)
        with self.assertRaises(ValueError):
            read_private_json(self.leases)
        target = self.root / "link.json"
        target.symlink_to(self.leases)
        with self.assertRaises(ValueError):
            read_private_json(target)

    def test_orphan_scan_respects_startup_grace_and_fixture_exclusion(self):
        self.worker.client.networks = SimpleNamespace(list=lambda **kwargs: [])
        orphan = Container("orphan")
        fixture = Container("fixture")
        fixture.labels["lazyx.sb.fixture"] = "true"
        self.values.extend([orphan, fixture])
        self.worker.step()
        self.assertFalse(orphan.removed)
        self.clock = 102.1
        self.snapshot["heartbeat"] = self.clock
        self.save()
        self.worker.step()
        self.assertTrue(orphan.removed)
        self.assertFalse(fixture.removed)
        self.assertFalse(self.a.removed or self.b.removed)

    def test_zombie_is_not_alive(self):
        proc = self.root / "proc"
        folder = proc / "7"
        folder.mkdir(parents=True)
        stat = folder / "stat"
        stat.write_text("7 (name with ) inside) Z 1 2 3")
        self.assertFalse(pid_alive(7, proc))
        stat.write_text("7 (normal) S 1 2 3")
        self.assertTrue(pid_alive(7, proc))
        self.assertFalse(pid_alive(8, proc))


class RegistryTests(unittest.TestCase):
    def test_each_read_sees_new_metadata_and_missing_job_is_denied(self):
        class API:
            def create_endpoint_config(self, **values):
                return values

            def create_networking_config(self, value):
                return value

        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "network.json"
            values = {"a": {"network_mode": "sb-job-0000-ca978112", "guest_ip": "172.28.0.3",
                            "trusted_peer": "172.28.0.1"}}
            atomic_json(path, values)
            registry = RegistryNetwork(path, SimpleNamespace(api=API()))
            self.assertEqual(registry.create_config("a")["trusted_peer"], "172.28.0.1")
            atomic_json(path, {})
            with self.assertRaises(KeyError):
                registry.create_config("a")

    def test_host_network_and_inconsistent_peer_are_rejected(self):
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "network.json"
            values = {"a": {"network_mode": "host", "guest_ip": "172.28.0.3",
                            "trusted_peer": "172.28.0.1"}}
            atomic_json(path, values)
            registry = RegistryNetwork(path, SimpleNamespace(api=None))
            with self.assertRaises(ValueError):
                registry.create_config("a")


if __name__ == "__main__":
    unittest.main()
