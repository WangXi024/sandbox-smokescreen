"""网络模块离线检查；不启动 Docker 或修改防火墙。Linux 真机验证另行执行。"""
import importlib.util
import hashlib
import json
import shlex
from pathlib import Path
from tempfile import TemporaryDirectory
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from sandbox_model.network import NetworkManager, NetworkOperationError, domains, smokescreen_config


class FakeNetwork:
    def __init__(self, name):
        self.name = name
        self.attrs = {"Containers": {}, "IPAM": {"Config": [{"Subnet": "172.27.250.0/24"}]}}
        self.removed = False

    def connect(self, proxy, ipv4_address=None):
        proxy.attrs["NetworkSettings"]["Networks"][self.name] = {
            "IPAddress": "", "RequestedIPAddress": ipv4_address or "172.27.250.2"}

    def reload(self):
        pass

    def remove(self):
        self.removed = True


class FakeNetworks:
    def __init__(self):
        self.items = {"sb-out": FakeNetwork("sb-out")}

    def create(self, name, **kwargs):
        obj = FakeNetwork(name)
        obj.kwargs = kwargs
        obj.attrs["Labels"] = kwargs.get("labels", {})
        obj.attrs["IPAM"] = kwargs.get("ipam", obj.attrs["IPAM"])
        self.items[name] = obj
        return obj

    def get(self, name):
        from docker.errors import NotFound
        if name not in self.items or self.items[name].removed:
            raise NotFound("synthetic missing network")
        return self.items[name]

    def list(self, filters):
        labels = dict(value.split("=", 1) for value in filters["label"])
        return [network for network in self.items.values() if not network.removed
                and all_match(network.attrs.get("Labels", {}), labels)]


class FakeProxy:
    def __init__(self, kwargs):
        self.kwargs = kwargs
        self.name = kwargs["name"]
        self.labels = kwargs["labels"]
        self.attrs = {"NetworkSettings": {"Networks": {kwargs["network"]: {}}}}
        self.removed = False

    def reload(self):
        pass

    def start(self):
        for config in self.attrs["NetworkSettings"]["Networks"].values():
            if config.get("RequestedIPAddress"):
                config["IPAddress"] = config["RequestedIPAddress"]

    def exec_run(self, args):
        return SimpleNamespace(exit_code=0)

    def remove(self, force):
        self.removed = True


def all_match(labels, expected):
    return all(labels.get(key) == value for key, value in expected.items())


class FakeContainers:
    def list(self, all, filters):
        expected = dict(item.split("=", 1) for item in filters["label"])
        return [obj for obj in self.created if not obj.removed
                and all_match(obj.labels, expected)]

    def __init__(self):
        self.created = []

    def create(self, image, **kwargs):
        obj = FakeProxy(kwargs)
        self.created.append(obj)
        return obj


class FakeAPI:
    @staticmethod
    def create_endpoint_config(**kwargs):
        return kwargs

    @staticmethod
    def create_networking_config(endpoints):
        return endpoints


class PolicyTests(unittest.TestCase):
    def test_exact_domains_and_duplicates(self):
        self.assertEqual(domains(["EXAMPLE.com.", "example.com", "second.test"]),
                         ("example.com", "second.test"))

    def test_reject_configuration_injection(self):
        for value in ("*.example.com", ".example.com", "a\nhttp_access allow all",
                      "example.com:443", "https://example.com", "a..b", "-a.test",
                      "127.0.0.1", "100.100.100.200"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                domains([value])
        with self.assertRaises(ValueError):
            domains("example.com")

    def test_offline_policy_has_no_allow_to_upstream(self):
        config = json.loads(smokescreen_config("172.28.0.3", []))
        self.assertEqual(config["allowed_domains"], [])
        self.assertEqual(config["guest_ip"], "172.28.0.3")
        self.assertEqual(config["fixture_ip"], "")

    def test_missing_chain_exit_two_is_idempotent_but_permission_is_not(self):
        missing = SimpleNamespace(returncode=2, stderr="No chain/target/match by that name", stdout="")
        with patch("sandbox_model.network.subprocess.run", return_value=missing):
            self.assertEqual(NetworkManager._command(["iptables", "-I"], missing_ok=True), "")
        forbidden = SimpleNamespace(returncode=1, stderr="Permission denied", stdout="")
        with patch("sandbox_model.network.subprocess.run", return_value=forbidden):
            with self.assertRaises(NetworkOperationError) as result:
                NetworkManager._command(["conntrack", "-D"], missing_ok=True)
            self.assertEqual(result.exception.category, "permission")

    def test_policy_has_only_exact_domains_and_finite_capacity(self):
        config = json.loads(smokescreen_config("172.28.0.3", ["allowed.test"]))
        self.assertEqual(config["allowed_domains"], ["allowed.test"])
        self.assertEqual(config["max_tunnels"], 32)
        self.assertIn("100.64.0.0/10", config["deny_ranges"])

    def test_private_exception_is_narrow(self):
        config = json.loads(smokescreen_config("172.28.0.3", ["allowed.test"],
                                              "172.27.250.53", "172.27.250.10"))
        self.assertEqual(config["fixture_ip"], "172.27.250.10")
        self.assertIn("172.16.0.0/12", config["deny_ranges"])


class ProxyResetTests(unittest.TestCase):
    def setUp(self):
        ident = "a" * 64
        proxy = SimpleNamespace(id=ident, name="sb-smokescreen-0000-" + hashlib.sha256(b"job-a").hexdigest()[:8],
                                labels={"lazyx.sb": "true", "lazyx.job": "job-a"},
                                attrs={"State": {"Pid": 42, "Running": True}}, reload=lambda: None,
                                exec_run=lambda _: SimpleNamespace(exit_code=0, output=b"REVOKED\n"))
        self.ctx = SimpleNamespace(job_id="job-a", slot=0, proxy=proxy)
        self.open = self.enterContext(patch("sandbox_model.network.os.open", return_value=73))
        self.close = self.enterContext(patch("sandbox_model.network.os.close"))
        self.enterContext(patch("sandbox_model.network.Path.read_text", return_value="0::/docker-" + ident + ".scope"))
        self.enterContext(patch("sandbox_model.network.os.fstat", return_value=SimpleNamespace(st_dev=1, st_ino=200)))
        self.stat = self.enterContext(patch("sandbox_model.network.os.stat", side_effect=[
            SimpleNamespace(st_dev=1, st_ino=200), SimpleNamespace(st_dev=1, st_ino=100)]))
        self.run = self.enterContext(patch("sandbox_model.network.subprocess.run", return_value=SimpleNamespace(returncode=0)))

    def test_reset_uses_fixed_verified_namespace_descriptor(self):
        NetworkManager._reset_proxy(self.ctx)
        args, kwargs = self.run.call_args
        self.assertEqual(args[0], ["nsenter", "--net=/proc/self/fd/73", "ss", "-K", "-t"])
        self.assertEqual(kwargs["pass_fds"], (73,))
        self.assertEqual(kwargs["timeout"], 2)
        self.close.assert_called_once_with(73)

    def test_host_namespace_is_never_entered(self):
        self.stat.side_effect = [SimpleNamespace(st_dev=1, st_ino=200)] * 2
        with self.assertRaisesRegex(ValueError, "PROXY_NAMESPACE_MISMATCH"):
            NetworkManager._reset_proxy(self.ctx)
        self.run.assert_not_called()
        self.close.assert_called_once_with(73)

    def test_reused_pid_with_foreign_cgroup_is_never_entered(self):
        with patch("sandbox_model.network.Path.read_text", return_value="0::/other-project"):
            with self.assertRaisesRegex(ValueError, "PROXY_NAMESPACE_MISMATCH"):
                NetworkManager._reset_proxy(self.ctx)
        self.run.assert_not_called()

    def test_changed_docker_pid_is_never_entered(self):
        calls = []
        def reload():
            calls.append(1)
            if len(calls) == 2:
                self.ctx.proxy.attrs["State"]["Pid"] = 43
        self.ctx.proxy.reload = reload
        with self.assertRaisesRegex(ValueError, "PROXY_NAMESPACE_MISMATCH"):
            NetworkManager._reset_proxy(self.ctx)
        self.run.assert_not_called()

    def test_foreign_proxy_is_rejected_before_opening_namespace(self):
        self.ctx.proxy.labels["lazyx.job"] = "job-b"
        with self.assertRaisesRegex(ValueError, "PROXY_IDENTITY_MISMATCH"):
            NetworkManager._reset_proxy(self.ctx)
        self.open.assert_not_called()

    def test_stopped_proxy_has_no_live_sockets_to_reset(self):
        self.ctx.proxy.attrs["State"] = {"Pid": 0, "Running": False}
        NetworkManager._reset_proxy(self.ctx)
        self.open.assert_not_called()
        self.run.assert_not_called()

    def test_socket_reset_failure_closes_descriptor(self):
        self.run.return_value.returncode = 1
        with self.assertRaises(NetworkOperationError):
            NetworkManager._reset_proxy(self.ctx)
        self.close.assert_called_once_with(73)

    def test_unsupported_kernel_requires_proxy_ack_even_with_zero_exit(self):
        self.run.return_value = SimpleNamespace(returncode=0, stderr="SOCK_DESTROY answers: Operation not supported")
        self.ctx.proxy.exec_run = self.enterContext(patch.object(FakeProxy, "exec_run", return_value=SimpleNamespace(exit_code=0, output=b"REVOKED\n")))
        NetworkManager._reset_proxy(self.ctx)
        self.ctx.proxy.exec_run.assert_called_once_with(["/egress", "--revoke"])
        self.close.assert_called_once_with(73)

    def test_unsupported_kernel_without_ack_is_not_cleanup_success(self):
        self.run.return_value = SimpleNamespace(returncode=0, stderr="Operation not supported")
        self.ctx.proxy.exec_run = lambda _: SimpleNamespace(exit_code=1, output=b"")
        with self.assertRaises(NetworkOperationError):
            NetworkManager._reset_proxy(self.ctx)
        self.close.assert_called_once_with(73)

    def test_silent_ss_success_still_requires_proxy_ack(self):
        self.run.return_value = SimpleNamespace(returncode=0, stderr="")
        self.ctx.proxy.exec_run = lambda _: SimpleNamespace(exit_code=0, output=b"")
        with self.assertRaises(NetworkOperationError):
            NetworkManager._reset_proxy(self.ctx)

    def test_paused_proxy_is_resumed_only_to_confirm_disconnect(self):
        self.ctx.proxy.attrs["State"]["Paused"] = True
        resumed = []
        self.ctx.proxy.unpause = lambda: resumed.append(True)
        def acknowledge(args):
            self.assertEqual(resumed, [True])
            self.assertEqual(args, ["/egress", "--revoke"])
            return SimpleNamespace(exit_code=0, output=b"REVOKED\n")
        self.ctx.proxy.exec_run = acknowledge
        NetworkManager._reset_proxy(self.ctx)


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.commands = []
        self.rules = {}
        self.client = SimpleNamespace(
            networks=FakeNetworks(), containers=FakeContainers(), api=FakeAPI())
        self.manager = NetworkManager(self.client, run_dir=self.tmp.name,
                                      command=self.command)
        self.manager._reset_proxy = lambda ctx: None

    def tearDown(self):
        self.tmp.cleanup()

    def command(self, args, missing_ok=False):
        self.commands.append(tuple(args))
        if args[0] == "iptables":
            operation, *parts = args[3:]
            if operation == "-S":
                selected = [parts[0]] if parts else list(self.rules)
                return "\n".join(line for chain in selected if chain in self.rules
                                 for line in ["-N " + chain] + [shlex.join(["-A", chain, *rule])
                                                               for rule in self.rules[chain]])
            chain, *rule = parts
            if operation == "-N":
                self.rules.setdefault(chain, [])
            elif operation in ("-A", "-I"):
                if operation == "-I" and rule[0].isdigit():
                    rule = rule[1:]
                self.rules.setdefault(chain, []).append(rule)
            elif operation == "-D":
                if rule in self.rules.get(chain, []):
                    self.rules[chain].remove(rule)
            elif operation == "-F":
                if chain in self.rules:
                    self.rules[chain].clear()
            elif operation == "-X":
                if any(rule[-2:] == ["-j", chain] for rules in self.rules.values() for rule in rules):
                    raise RuntimeError("synthetic chain still referenced")
                self.rules.pop(chain, None)
        return "tmpfs\n" if args[0] == "findmnt" else ""

    def test_two_tasks_have_distinct_identity_and_policies(self):
        a = self.manager.prepare("task-a", ["allowed.test"])
        b = self.manager.prepare("task-b", ["second.test"])
        self.assertNotEqual(a.subnet, b.subnet)
        self.assertNotEqual(a.proxy, b.proxy)
        self.assertEqual(self.manager.source_job(a.guest_ip), "task-a")
        self.assertEqual(self.manager.source_job(b.guest_ip), "task-b")
        self.assertIsNone(self.manager.source_job("172.27.250.2"))
        self.assertEqual(self.manager.create_config("task-a")["trusted_peer"], a.gateway)
        self.assertIn(a.name, self.manager.create_config("task-a")["networking_config"])
        self.assertIn("LAZYX_GATEWAY", a.env)
        self.assertNotIn("second.test", (a.policy_dir / "policy.json").read_text())

    def test_firewall_protection_precedes_container_creation(self):
        a = self.manager.prepare("task-a", ["allowed.test"])
        self.assertIn(("iptables", "-w", "5", "-A", a.forward_chain, "-j", "REJECT"),
                      self.commands)
        rules = [" ".join(command) for command in self.commands]
        self.assertTrue(any(f"-s {a.guest_ip} -d {a.gateway} -p tcp --dport 18600"
                            in rule for rule in rules))
        self.assertFalse(any("--dport 18080 -j ACCEPT" in rule for rule in rules))
        self.assertFalse(any("--dport 44772 -j ACCEPT" in rule for rule in rules))
        self.assertTrue(a.proxy.kwargs["read_only"])
        self.assertEqual(a.proxy.kwargs["log_config"]["Type"], "none")

    def test_revoke_closes_proxy_and_does_not_revoke_other_task(self):
        a = self.manager.prepare("task-a", ["allowed.test"])
        b = self.manager.prepare("task-b", ["second.test"])
        proxy = a.proxy
        self.manager.revoke("task-a")
        self.assertTrue(proxy.removed)
        self.assertFalse(a.active)
        self.assertIsNone(self.manager.source_job(a.guest_ip))
        self.assertEqual(self.manager.source_job(b.guest_ip), "task-b")
        with self.assertRaises(ValueError):
            self.manager.prepare("task-a", ["allowed.test"])

    def test_failed_socket_reset_retains_proxy_and_context_for_retry(self):
        a = self.manager.prepare("task-a", [])
        proxy = a.proxy
        def fail(ctx):
            raise NetworkOperationError("ss", "reset", 1, "tool_failed")
        self.manager._reset_proxy = fail
        with self.assertRaises(NetworkOperationError):
            self.manager.revoke("task-a")
        self.assertFalse(proxy.removed)
        self.assertIs(a.proxy, proxy)
        self.assertIn("task-a", self.manager.jobs)
        self.assertFalse(a.active)

    def test_address_is_not_recycled_while_guest_remains(self):
        a = self.manager.prepare("task-a", ["allowed.test"])
        net = self.client.networks.get(a.name)
        net.attrs["Containers"]["guest"] = {}
        with self.assertRaises(RuntimeError):
            self.manager.release("task-a")
        self.assertIn("task-a", self.manager.jobs)
        b = self.manager.prepare("task-b", ["second.test"])
        self.assertNotEqual(a.guest_ip, b.guest_ip)
        net.attrs["Containers"].clear()
        self.manager.release("task-a")
        c = self.manager.prepare("task-c", [])
        self.assertEqual(a.guest_ip, c.guest_ip)
        self.assertFalse(c.allowed_domains)
        self.assertIsNone(self.manager.source_job("not-an-ip"))

    def test_failed_conntrack_cleanup_holds_address(self):
        a = self.manager.prepare("task-a", [])
        original = self.manager.command

        def fail(args, missing_ok=False):
            if args[0] == "conntrack":
                raise RuntimeError("synthetic cleanup failure")
            return original(args, missing_ok)

        self.manager.command = fail
        with self.assertRaises(RuntimeError):
            self.manager.release("task-a")
        self.assertIn("task-a", self.manager.jobs)
        self.assertFalse(self.client.networks.get(a.name).removed)

    def test_private_fixture_requires_explicit_test_mode(self):
        self.manager.fixture_ip = "172.27.250.10"
        self.manager.dns_server = "172.27.250.53"
        with self.assertRaises(ValueError):
            self.manager.prepare("production", ["allowed.test"])
        a = self.manager.prepare("synthetic", ["allowed.test"], test_mode=True)
        self.assertTrue(a.active)
        self.assertEqual(json.loads((a.policy_dir / "policy.json").read_text())["fixture_ip"], "172.27.250.10")

    def test_doh_is_node_controlled_and_test_dns_stays_synthetic(self):
        self.manager.dns_over_https=True
        normal=self.manager.prepare('public-doh',['example.com'])
        policy=json.loads((normal.policy_dir/'policy.json').read_text())
        self.assertTrue(policy['dns_over_https'])
        self.assertEqual(policy['fixture_ip'],'')
        synthetic=self.manager.prepare('synthetic-dns',['allowed.test'],test_mode=True)
        policy=json.loads((synthetic.policy_dir/'policy.json').read_text())
        self.assertNotIn('dns_over_https',policy)

    def test_high_level_docker_keeps_network_ip_and_mac(self):
        from docker.models.containers import _create_container_args
        from docker.types import EndpointConfig
        a = self.manager.prepare("task-a", [])
        config = a.proxy.kwargs["networking_config"]
        self.assertIn(a.name, config)
        mac = "02:42:ac:1c:00:00"
        real_endpoint = EndpointConfig("1.52", ipv4_address=a.proxy_ip, mac_address=mac)
        converted = _create_container_args({"version": "1.52", "network": a.name, "networking_config": {a.name: real_endpoint}})
        retained = converted["networking_config"]["EndpointsConfig"][a.name]
        self.assertEqual(retained["MacAddress"], mac)
        self.assertEqual(retained["IPAMConfig"]["IPv4Address"], a.proxy_ip)

    def test_static_uplink_ip_exists_before_proxy_start_and_cannot_collide(self):
        self.client.networks.get("sb-out").attrs["Containers"]["existing"] = {"IPv4Address": "172.27.250.100/24"}
        a = self.manager.prepare("task-a", [])
        b = self.manager.prepare("task-b", [])
        self.assertEqual(a.proxy_out_ip, "172.27.250.101")
        self.assertEqual(b.proxy_out_ip, "172.27.250.102")
        self.assertFalse(any(command[index + 1] == ""
                             for command in self.commands for index, arg in enumerate(command[:-1])
                             if arg == "-s"))

    def test_prepare_preserves_failure_when_cleanup_also_fails(self):
        def fail_create(*args, **kwargs):
            raise ValueError("ORIGINAL_FAILURE")
        def fail_cleanup(job):
            raise RuntimeError("SECOND_FAILURE")
        self.client.containers.create = fail_create
        self.manager.revoke = fail_cleanup
        with self.assertRaises(ValueError) as error:
            self.manager.prepare("task-a", [])
        self.assertEqual(str(error.exception), "ORIGINAL_FAILURE")

    def test_old_reaper_rescan_cannot_touch_reused_address(self):
        a = self.manager.prepare("task-a", ["allowed.test"])
        old = self.manager.export_context("task-a")
        self.manager.release("task-a")
        b = self.manager.prepare("task-b", ["second.test"])
        self.assertEqual(a.guest_ip, b.guest_ip)
        self.assertNotEqual(a.name, b.name)
        self.assertNotEqual(a.forward_chain, b.forward_chain)
        self.assertLessEqual(len(b.bridge), 15)
        count = len(self.commands)
        self.manager.restore_context(old)
        self.manager.release("task-a")
        tail = self.commands[count:]
        self.assertFalse(any(command[0] == "conntrack" for command in tail))
        self.assertFalse(any(b.forward_chain in command for command in tail))
        self.assertFalse(b.proxy.removed)
        self.assertEqual(self.manager.source_job(b.guest_ip), "task-b")

    def test_two_cleanup_callers_are_idempotent(self):
        self.manager.prepare("task-a", [])
        context = self.manager.export_context("task-a")
        self.manager.release("task-a")
        self.manager.restore_context(context)
        self.manager.release("task-a")
        self.assertNotIn("task-a", self.manager.jobs)

    def test_orphan_proxy_missing_recovers_source_and_removes_all_rules(self):
        a = self.manager.prepare("task-a", [])
        network = self.client.networks.get(a.name)
        a.proxy.remove(force=True)
        values = self.manager.orphan_context(network)
        self.assertEqual(values["proxy_out_ip"], a.proxy_out_ip)
        self.manager.jobs.clear()
        self.manager.restore_context(values)
        self.manager.release("task-a")
        self.assertEqual(self.manager.remaining_resources("task-a"), {"networks": 0, "rules": 0})
        self.assertFalse(any(a.proxy_out_ip in rule for rule in self.rules["INPUT"]))

    def test_orphan_rejects_multiple_source_addresses(self):
        a = self.manager.prepare("task-a", [])
        a.proxy.remove(force=True)
        self.rules["DOCKER-USER"].append(["-s", "172.27.250.222/32", "-j", a.proxy_chain])
        with self.assertRaises(ValueError):
            self.manager.orphan_context(self.client.networks.get(a.name))

    def test_network_remove_without_effect_keeps_slot(self):
        a = self.manager.prepare("task-a", [])
        network = self.client.networks.get(a.name)
        network.remove = lambda: None
        with self.assertRaisesRegex(RuntimeError, "NETWORK_RESOURCES_REMAIN"):
            self.manager.release("task-a")
        self.assertIn("task-a", self.manager.jobs)

    def test_chain_remove_without_effect_keeps_slot(self):
        a = self.manager.prepare("task-a", [])
        original = self.manager.command
        self.manager.command = lambda args, missing_ok=False: "" if args[3:5] == ["-X", a.proxy_chain] else original(args, missing_ok)
        with self.assertRaisesRegex(RuntimeError, "NETWORK_RESOURCES_REMAIN"):
            self.manager.release("task-a")
        self.assertIn("task-a", self.manager.jobs)

    def test_proxy_input_rule_remove_without_effect_keeps_slot(self):
        a = self.manager.prepare("task-a", [])
        original = self.manager.command
        self.manager.command = lambda args, missing_ok=False: "" if args[3:7] == ["-D", "INPUT", "-s", a.proxy_out_ip] else original(args, missing_ok)
        with self.assertRaisesRegex(RuntimeError, "NETWORK_RESOURCES_REMAIN"):
            self.manager.release("task-a")
        self.assertIn("task-a", self.manager.jobs)
        self.manager.command = original
        self.manager.release("task-a")
        self.assertNotIn("task-a", self.manager.jobs)
        self.assertFalse(any(a.proxy_out_ip in rule for rule in self.rules["INPUT"]))

    def test_old_reaper_cannot_delete_reused_proxy_input_rule(self):
        a = self.manager.prepare("task-a", [])
        old = self.manager.export_context("task-a")
        self.manager.release("task-a")
        b = self.manager.prepare("task-b", [])
        self.assertEqual(a.proxy_out_ip, b.proxy_out_ip)
        self.manager.restore_context(old)
        self.manager.release("task-a")
        self.assertIn(["-s", b.proxy_out_ip, "-m", "conntrack", "--ctstate", "NEW", "-j", "REJECT"],
                      self.rules["INPUT"])

    def test_slow_prepare_does_not_block_other_identity_or_heartbeat(self):
        a = self.manager.prepare("task-a", [])
        original = self.client.networks.create
        entered, proceed = threading.Event(), threading.Event()

        def slow(*args, **kwargs):
            entered.set()
            proceed.wait(2)
            return original(*args, **kwargs)

        self.client.networks.create = slow
        thread = threading.Thread(target=self.manager.prepare, args=("task-b", []))
        thread.start()
        self.assertTrue(entered.wait(1))
        start = time.monotonic()
        self.assertEqual(self.manager.source_job(a.guest_ip), "task-a")
        self.manager.export_context("task-a")
        self.assertLess(time.monotonic() - start, .2)
        proceed.set()
        thread.join(2)
        self.assertFalse(thread.is_alive())

    def test_policy_mutation_and_invalid_job_are_rejected(self):
        self.manager.prepare("task-a", ["allowed.test"])
        with self.assertRaises(ValueError):
            self.manager.prepare("task-a", ["second.test"])
        with self.assertRaises(ValueError):
            self.manager.prepare("../escape", [])


class DNSFixtureTests(unittest.TestCase):
    def test_dns_records_can_change_to_private_without_disk(self):
        path = Path(__file__).parents[1] / "tests" / "support" / "dns_fixture.py"
        spec = importlib.util.spec_from_file_location("dns_fixture", path)
        fixture = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fixture)
        wire = bytes.fromhex("000101000001000000000000") + b"\x07allowed\x04test\0\0\x01\0\x01"
        first = fixture.response(wire)
        self.assertEqual(first[-4:], bytes((172, 27, 250, 10)))
        fixture.MAPPING["allowed.test"] = "169.254.169.254"
        second = fixture.response(wire)
        self.assertEqual(second[-4:], bytes((169, 254, 169, 254)))
        self.assertEqual(len(fixture.QUERIES), 2)


if __name__ == "__main__":
    unittest.main()
