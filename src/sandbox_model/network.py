"""每任务独立网络与外部 Smokescreen；仅在专用 Linux 沙箱节点运行。"""
from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import threading
import time

NONPUBLIC = (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
    "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
)
LABELS = {"lazyx.sb": "true"}


class NetworkOperationError(RuntimeError):
    """只暴露预定义类别与退出码，不包含原始工具输出。"""
    def __init__(self, program, operation, exit_code, category):
        self.program, self.operation = program, operation
        self.exit_code, self.category = exit_code, category
        super().__init__(f"NETWORK_TOOL_ERROR:{program}:{operation}:{exit_code}:{category}")


def stderr_category(stderr):
    lower = stderr.lower()
    if any(text in lower for text in ("no chain/target/match", "does a matching rule exist",
                                     "does not exist", "cannot find device", "0 flow entries")):
        return "missing_resource"
    if "already exists" in lower:
        return "already_exists"
    if any(text in lower for text in ("host/network", "bad source address", "bad ip address",
                                     "invalid ipv4 address")):
        return "invalid_address"
    if any(text in lower for text in ("permission denied", "must be root")):
        return "permission"
    if any(text in lower for text in ("xtables lock", "resource temporarily unavailable")):
        return "busy"
    if any(text in lower for text in ("bad argument", "unknown option", "invalid argument",
                                     "index of insertion too big")):
        return "invalid_rule"
    return "tool_failed"


def domains(values):
    """仅接受精确 DNS 域名，拒绝通配符、IP、端口和配置注入。"""
    if not isinstance(values, (list, tuple)):
        raise ValueError("允许域名必须为列表")
    if len(values) > 32:
        raise ValueError("允许域名最多 32 个")
    result = []
    for value in values:
        if not isinstance(value, str):
            raise ValueError("域名必须为字符串")
        host = value.lower().rstrip(".")
        if len(host) > 253 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host):
            raise ValueError("域名格式错误")
        if any(not part or len(part) > 63 or part.startswith("-") or part.endswith("-")
               for part in host.split(".")):
            raise ValueError("域名格式错误")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise ValueError("网络许可必须使用域名")
        if host not in result:
            result.append(host)
    return tuple(result)


def smokescreen_config(guest_ip, allowed, dns_server="1.1.1.1", fixture_ip=None,
                       upload_bytes=8*1024*1024, download_bytes=32*1024*1024):
    """每任务固定策略；仅 test-mode 可提供一个合成源站 IP 例外。"""
    return json.dumps({
        "guest_ip": str(ipaddress.IPv4Address(guest_ip)),
        "allowed_domains": list(domains(allowed)),
        "dns_server": str(ipaddress.IPv4Address(dns_server)),
        "deny_ranges": list(NONPUBLIC) + ["::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8"],
        "fixture_ip": str(ipaddress.IPv4Address(fixture_ip)) if fixture_ip else "",
        "max_tunnels": 32,
        "upload_bytes": upload_bytes,
        "download_bytes": download_bytes,
    }, indent=2) + "\n"


@dataclass
class TaskNetwork:
    """单任务网络身份与清理元数据；active 只在代理健康后置为真。"""
    job_id: str
    slot: int
    name: str
    bridge: str
    subnet: str
    gateway: str
    proxy_ip: str
    guest_ip: str
    forward_chain: str
    input_chain: str
    proxy_chain: str
    policy_dir: Path
    allowed_domains: tuple
    proxy: object = None
    proxy_out_ip: str = ""
    active: bool = False

    @property
    def env(self):
        """提供不含凭据的代理地址；底层防火墙同时阻断脚本绕开代理直连。"""
        url = f"http://{self.proxy_ip}:3128"
        return {key: url for key in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy")} | {
            "NO_PROXY": "", "no_proxy": "",
            "LAZYX_GATEWAY": f"http://{self.gateway}:18600",
        }


class NetworkManager:
    """创建前装保护；撤权后立即拒绝网关；确认资源消失后才回收地址。"""

    def __init__(self, client=None, *, proxy_image="sandbox-smokescreen-egress:7d0ddfa-tls1",
                 run_dir="/run/sandbox-model", dns_server="1.1.1.1", fixture_ip=None,
                 pool="172.28.0.0/16", uplink="sb-out", command=None, dns_over_https=False):
        if client is None:
            import docker
            client = docker.from_env()
        self.client = client
        self.proxy_image = proxy_image
        self.run_dir = Path(run_dir)
        self.dns_server = str(ipaddress.IPv4Address(dns_server))
        self.dns_over_https = dns_over_https
        self.fixture_ip = str(ipaddress.IPv4Address(fixture_ip)) if fixture_ip else None
        self.pool = ipaddress.IPv4Network(pool)
        self.uplink = uplink
        self.jobs = {}
        self.lock = threading.RLock()
        self.command = command or self._command

    @staticmethod
    def _command(args, missing_ok=False):
        """执行有超时的网络工具；只对确实不存在的资源容许幂等清理。"""
        program = Path(args[0]).name
        operation = next((arg for arg in args[1:] if arg in ("-N", "-I", "-D", "-F", "-X")), "query")
        try:
            result = subprocess.run(args, capture_output=True, text=True, timeout=20)
        except subprocess.TimeoutExpired:
            raise NetworkOperationError(program, operation, None, "timeout") from None
        category = stderr_category(result.stderr)
        absent = category == "missing_resource"
        if result.returncode and not (missing_ok and absent):
            raise NetworkOperationError(program, operation, result.returncode, category)
        return result.stdout

    def _iptables(self, *args, missing_ok=False):
        return self.command(["iptables", "-w", "5", *args], missing_ok=missing_ok)

    def _ensure_ram(self):
        """网络策略与锁必须写入 tmpfs，不能悄悄退回节点磁盘。"""
        self.run_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        kind = self.command(["findmnt", "-n", "-o", "FSTYPE", "-T", str(self.run_dir)]).strip()
        if kind != "tmpfs":
            raise RuntimeError("网络运行目录必须位于 tmpfs")

    @contextmanager
    def _slot_lock(self, slot):
        # 管理服务与独立回收器共用内存元数据锁，防止清conntrack时IP已被复用。
        fd = os.open(self.run_dir / f"slot-{slot:04x}.lock", os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def source_job(self, source_ip):
        """HTTP 网关使用 TCP 源地址绑定身份，不读取来客自报的身份头。"""
        with self.lock:
            return next((job for job, ctx in self.jobs.items()
                         if ctx.active and ctx.guest_ip == source_ip), None)

    def export_context(self, job_id):
        with self.lock:
            ctx = self.jobs[job_id]
            # 手动排除 Docker 对象，避免 dataclasses 深拷贝客户端或泄露配置。
            values = {name: getattr(ctx, name) for name in ctx.__dataclass_fields__ if name != "proxy"}
            values["policy_dir"] = str(ctx.policy_dir)
            values["allowed_domains"] = list(ctx.allowed_domains)
            values["proxy_name"] = f"sb-smokescreen-{ctx.slot:04x}-{hashlib.sha256(ctx.job_id.encode()).hexdigest()[:8]}"
            return values

    def restore_context(self, values):
        """独立回收进程恢复仅元数据的上下文，限定本项目网络与资源标签。"""
        slot = values["slot"]
        if not isinstance(slot, int) or not 0 <= slot < 8192:
            raise ValueError("网络槽位错误")
        job_id = values["job_id"]
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", job_id):
            raise ValueError("任务编号格式错误")
        generation = hashlib.sha256(job_id.encode()).hexdigest()[:8]
        suffix = f"{slot:04x}-{generation}"
        expected = {"name": f"sb-job-{suffix}", "bridge": f"sbj{slot:04x}{generation}",
                    "forward_chain": f"SB_F_{suffix}", "input_chain": f"SB_I_{suffix}",
                    "proxy_chain": f"SB_P_{suffix}"}
        if any(values.get(key) != value for key, value in expected.items()):
            raise ValueError("不能恢复项目范围外的网络")
        subnet = ipaddress.IPv4Network(values["subnet"])
        if subnet.prefixlen != 29:
            raise ValueError("网络范围错误")
        hosts = tuple(str(address) for address in subnet.hosts())
        if (values["gateway"], values["proxy_ip"], values["guest_ip"]) != hosts[:3]:
            raise ValueError("网络身份与地址不一致")
        if values.get("proxy_out_ip"):
            ipaddress.IPv4Address(values["proxy_out_ip"])
        directory = Path(values["policy_dir"])
        if directory != self.run_dir / job_id:
            raise ValueError("运行目录错误")
        data = {name: values[name] for name in TaskNetwork.__dataclass_fields__ if name != "proxy"}
        data["policy_dir"] = directory
        data["allowed_domains"] = domains(values["allowed_domains"])
        data["active"] = False
        ctx = TaskNetwork(**data)
        for container in self.client.containers.list(all=True, filters={
                "label": ["lazyx.sb=true", f"lazyx.job={job_id}"]}):
            labels = container.labels or {}
            if (container.name == f"sb-smokescreen-{suffix}" and labels.get("lazyx.sb") == "true"
                    and labels.get("lazyx.job") == job_id):
                ctx.proxy = container
                break
        self.jobs[job_id] = ctx
        return ctx

    def orphan_context(self, network):
        """从本项目 Docker 网络恢复缺少租约的清理元数据，不读取任务内容。"""
        network.reload()
        labels = network.attrs.get("Labels") or {}
        job_id = labels.get("lazyx.job", "")
        match = re.fullmatch(r"sb-job-([0-9a-f]{4})-([0-9a-f]{8})", network.name)
        if (labels.get("lazyx.sb") != "true" or labels.get("lazyx.sb.fixture")
                or not match or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", job_id)):
            raise ValueError("不是本项目任务网络")
        generation = hashlib.sha256(job_id.encode()).hexdigest()[:8]
        if generation != match[2]:
            raise ValueError("任务网络代次不匹配")
        slot = int(match[1], 16)
        suffix = f"{slot:04x}-{generation}"
        configs = network.attrs.get("IPAM", {}).get("Config") or []
        subnet = ipaddress.IPv4Network(configs[0]["Subnet"])
        if subnet.prefixlen != 29:
            raise ValueError("网络范围错误")
        hosts = tuple(str(address) for address in subnet.hosts())
        values = dict(job_id=job_id, slot=slot, name=network.name,
                      bridge=f"sbj{slot:04x}{generation}", subnet=str(subnet),
                      gateway=hosts[0], proxy_ip=hosts[1], guest_ip=hosts[2],
                      forward_chain=f"SB_F_{suffix}", input_chain=f"SB_I_{suffix}",
                      proxy_chain=f"SB_P_{suffix}", policy_dir=str(self.run_dir / job_id),
                      allowed_domains=[], proxy_out_ip="", active=False)
        for container in self.client.containers.list(all=True, filters={
                "label": ["lazyx.sb=true", f"lazyx.job={job_id}"]}):
            if (container.name == f"sb-smokescreen-{suffix}" and container.labels.get("lazyx.sb") == "true"
                    and container.labels.get("lazyx.job") == job_id):
                container.reload()
                values["proxy_out_ip"] = (container.attrs.get("NetworkSettings", {}).get("Networks", {})
                    .get(self.uplink, {}).get("IPAddress", ""))
        if not values["proxy_out_ip"]:
            sources = set()
            for line in self._iptables("-S", "DOCKER-USER").splitlines():
                rule = shlex.split(line)
                if len(rule) == 6 and rule[:3] == ["-A", "DOCKER-USER", "-s"] and rule[4:] == ["-j", values["proxy_chain"]]:
                    address = ipaddress.IPv4Network(rule[3])
                    if address.prefixlen != 32:
                        raise ValueError("代理规则来源不是唯一地址")
                    sources.add(str(address.network_address))
            if len(sources) > 1:
                raise ValueError("代理规则来源不唯一")
            values["proxy_out_ip"] = next(iter(sources), "")
        return values

    def remaining_resources(self, job_id):
        """按项目标签和任务代次检查网络与防火墙规则残留。"""
        generation = hashlib.sha256(job_id.encode()).hexdigest()[:8]
        chain = re.compile(r"SB_[FIP]_[0-9a-f]{4}-" + generation)
        networks = [network for network in self.client.networks.list(filters={
            "label": ["lazyx.sb=true", f"lazyx.job={job_id}"]})
            if (network.attrs.get("Labels") or {}).get("lazyx.sb") == "true"
            and (network.attrs.get("Labels") or {}).get("lazyx.job") == job_id]
        rules = sum(any(chain.fullmatch(token) for token in shlex.split(line))
                    for line in self._iptables("-S").splitlines())
        return {"networks": len(networks), "rules": rules}

    def create_config(self, job_id):
        """供运行适配器读取已分配身份；创建任务时不能自行选择地址或网络。"""
        with self.lock:
            ctx = self.jobs[job_id]
            endpoint = self.client.api.create_endpoint_config(ipv4_address=ctx.guest_ip)
            return {
                "network_mode": ctx.name,
                "networking_config": self.client.api.create_networking_config({ctx.name: endpoint}),
                "trusted_peer": ctx.gateway,
            }

    def prepare(self, job_id, allowed_domains, test_mode=False, *, public_build=False,
                upload_bytes=8*1024*1024, download_bytes=32*1024*1024):
        """先装拒绝规则再建内部网络和代理，健康检查通过后才开放任务使用。"""
        approved = domains(allowed_domains)
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", job_id):
            raise ValueError("任务编号格式错误")
        if not test_mode and (not ipaddress.IPv4Address(self.dns_server).is_global or self.fixture_ip):
            raise ValueError("生产网络不能启用合成私网 DNS 或源站")
        with self.lock:
            if job_id in self.jobs:
                ctx = self.jobs[job_id]
                if ctx.allowed_domains != approved or not ctx.active:
                    raise ValueError("任务网络不能复用或变更策略")
                return ctx
            self._ensure_ram()
            used = {ctx.slot for ctx in self.jobs.values()}
            slot = next(i for i in range(self.pool.num_addresses // 8) if i not in used)
            subnet = ipaddress.IPv4Network((int(self.pool.network_address) + slot * 8, 29))
            generation = hashlib.sha256(job_id.encode()).hexdigest()[:8]
            suffix = f"{slot:04x}-{generation}"
            addresses = tuple(subnet.hosts())
            ctx = TaskNetwork(
                job_id, slot, f"sb-job-{suffix}", f"sbj{slot:04x}{generation}", str(subnet),
                str(addresses[0]), str(addresses[1]), str(addresses[2]),
                f"SB_F_{suffix}", f"SB_I_{suffix}", f"SB_P_{suffix}",
                self.run_dir / job_id, approved,
            )
            # 创建和启动失败也保留上下文，避免半成品地址被其他任务重用。
            self.jobs[job_id] = ctx
        try:
            with self._slot_lock(ctx.slot):
                self._prepare_rules(ctx)
                import docker
                labels = LABELS | {"lazyx.job": job_id}
                self.client.networks.create(
                    ctx.name, driver="bridge", internal=True, enable_ipv6=False,
                    check_duplicate=True, labels=labels,
                    options={"com.docker.network.bridge.name": ctx.bridge,
                             "com.docker.network.bridge.enable_icc": "false"},
                    ipam=docker.types.IPAMConfig(pool_configs=[
                        docker.types.IPAMPool(subnet=ctx.subnet, gateway=ctx.gateway)]),
                )
                ctx.policy_dir.mkdir(mode=0o700)
                policy = ctx.policy_dir / "policy.json"
                resolver = '1.1.1.1' if public_build else self.dns_server
                policy_data = json.loads(smokescreen_config(ctx.guest_ip, approved, resolver,
                                              self.fixture_ip if test_mode and not public_build else None,
                                              upload_bytes, 128*1024*1024 if public_build else download_bytes))
                if public_build or self.dns_over_https and not test_mode:
                    policy_data['dns_over_https'] = True
                policy.write_text(json.dumps(policy_data))
                policy.chmod(0o644)
                volumes = {str(policy): {"bind": "/etc/egress/policy.json", "mode": "ro"}}
                ctx.proxy = self.client.containers.create(
                    self.proxy_image, name=f"sb-smokescreen-{suffix}", labels=labels,
                    network=ctx.name,
                    # 高层 containers.create 接受直接网络名映射，不能传低层 EndpointsConfig 包装。
                    networking_config={
                        ctx.name: self.client.api.create_endpoint_config(
                            ipv4_address=ctx.proxy_ip,
                            mac_address=f"02:42:ac:1c:{slot // 256:02x}:{slot % 256:02x}")},
                    read_only=True, cap_drop=["ALL"], user="65532:65532",
                    security_opt=["no-new-privileges:true"],
                    mem_limit="192m", pids_limit=32,
                    log_config=docker.types.LogConfig(type="none"),
                    tmpfs={"/tmp": "rw,nosuid,nodev,size=8m,mode=1777"},
                    volumes=volumes,
                )
                uplink = self.client.networks.get(self.uplink)
                self._reserve_uplink_ip(ctx, uplink)
                uplink.connect(ctx.proxy, ipv4_address=ctx.proxy_out_ip)
                # 容器未start时IPAddress可能为空，规则始终用可信预分配的地址。
                self._proxy_rules(ctx, test_mode and not public_build, resolver)
                if public_build:
                    # 包下载的硬字节上限；配额耗尽后不能落入已有放行规则。
                    match = ('-s', ctx.proxy_ip, '-d', ctx.guest_ip, '-p', 'tcp', '--sport', '3128')
                    self._iptables('-I', ctx.forward_chain, '1', *match, '-j', 'REJECT')
                    self._iptables('-I', ctx.forward_chain, '1', *match, '-m', 'quota',
                                   '--quota', str(128 * 1024 * 1024), '-j', 'ACCEPT')
                ctx.proxy.start()
                ctx.proxy.reload()
                assigned = ctx.proxy.attrs["NetworkSettings"]["Networks"][self.uplink]["IPAddress"]
                if assigned != ctx.proxy_out_ip:
                    raise ValueError("PROXY_IDENTITY_MISMATCH")
                for _ in range(80):
                    result = ctx.proxy.exec_run(["/egress", "--healthcheck"])
                    if result.exit_code == 0:
                        ctx.active = True
                        return ctx
                    time.sleep(.1)
                raise RuntimeError("Smokescreen 启动超时")
        except Exception:
            try:
                self.revoke(job_id)
            except Exception:
                pass  # 原始装配失败保留；独立回收器继续处理残留。
            raise

    def _prepare_rules(self, ctx):
        """任务只允许访问自己的代理及受限网关，拒绝其他转发和节点入口。"""
        for chain in (ctx.forward_chain, ctx.input_chain, ctx.proxy_chain):
            self._iptables("-N", chain)
            self._iptables("-A", chain, "-j", "REJECT")
        # 空链末尾已拒绝，再绑定父链；保护先于任何容器创建。
        self._iptables("-I", "DOCKER-USER", "1", "-i", ctx.bridge, "-j", ctx.forward_chain)
        self._iptables("-I", "INPUT", "1", "-i", ctx.bridge, "-j", ctx.input_chain)
        self._iptables("-I", ctx.forward_chain, "1", "-s", ctx.guest_ip, "-d", ctx.proxy_ip,
                       "-p", "tcp", "--dport", "3128", "-j", "ACCEPT")
        self._iptables("-I", ctx.forward_chain, "1", "-s", ctx.proxy_ip, "-d", ctx.guest_ip,
                       "-p", "tcp", "--sport", "3128", "-m", "conntrack",
                       "--ctstate", "ESTABLISHED", "-j", "ACCEPT")
        self._iptables("-I", ctx.input_chain, "1", "-s", ctx.guest_ip, "-d", ctx.gateway,
                       "-p", "tcp", "--dport", "18600", "-j", "ACCEPT")
        self._iptables("-I", ctx.input_chain, "1", "-s", ctx.guest_ip, "-m", "conntrack",
                       "--ctstate", "ESTABLISHED", "-j", "ACCEPT")

    def _reserve_uplink_ip(self, ctx, uplink):
        # 专用 sb-out 的高地址段，避开网关和合成 DNS/源站；只做本节点小规模分配。
        uplink.reload()
        configs = uplink.attrs.get("IPAM", {}).get("Config") or []
        subnet = next(ipaddress.IPv4Network(value["Subnet"]) for value in configs
                      if ":" not in value["Subnet"])
        occupied = {value.get("IPv4Address", "").split("/")[0]
                    for value in (uplink.attrs.get("Containers") or {}).values()}
        occupied.update((self.dns_server, self.fixture_ip))
        with self.lock:
            occupied.update(value.proxy_out_ip for value in self.jobs.values())
            for offset in range(100, 241):
                address = subnet.network_address + offset
                if address in subnet and address != subnet.broadcast_address and str(address) not in occupied:
                    ctx.proxy_out_ip = str(address)
                    return
        raise ValueError("UPLINK_CAPACITY")

    def _proxy_rules(self, ctx, test_mode, resolver=None):
        """代理可访问获准解析器和公网 HTTP/HTTPS，域名规则由代理再次检查。"""
        self._iptables("-I", "DOCKER-USER", "1", "-s", ctx.proxy_out_ip, "-j", ctx.proxy_chain)
        self._iptables("-I", "INPUT", "1", "-s", ctx.proxy_out_ip, "-m", "conntrack",
                       "--ctstate", "NEW", "-j", "REJECT")
        # DNS 只通向登记的可信解析器；实际代理连接地址另受私网规则保护。
        for protocol in ("udp", "tcp"):
            self._iptables("-I", ctx.proxy_chain, "1", "-d", resolver or self.dns_server,
                           "-p", protocol, "--dport", "53", "-j", "ACCEPT")
        offset = 3
        if test_mode and self.fixture_ip:
            self._iptables("-I", ctx.proxy_chain, str(offset), "-d", self.fixture_ip,
                           "-p", "tcp", "--dport", "443", "-j", "ACCEPT")
            offset += 1
        for cidr in NONPUBLIC:
            self._iptables("-I", ctx.proxy_chain, str(offset), "-d", cidr, "-j", "REJECT")
            offset += 1
        self._iptables("-I", ctx.proxy_chain, str(offset), "-p", "tcp",
                       "-m", "multiport", "--dports", "80,443", "-j", "ACCEPT")

    @staticmethod
    def _reset_proxy(ctx):
        """核对代理进程与网络命名空间后断连，要求代理确认已有连接已关闭。"""
        proxy = ctx.proxy
        proxy.reload()
        expected = f"sb-smokescreen-{ctx.slot:04x}-{hashlib.sha256(ctx.job_id.encode()).hexdigest()[:8]}"
        if (proxy.name != expected or proxy.labels.get("lazyx.sb") != "true"
                or proxy.labels.get("lazyx.job") != ctx.job_id):
            raise ValueError("PROXY_IDENTITY_MISMATCH")
        pid = proxy.attrs.get("State", {}).get("Pid")
        if pid == 0 and proxy.attrs["State"].get("Running") is False:
            return
        if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 1 or not re.fullmatch(r"[0-9a-f]{64}", proxy.id):
            raise ValueError("PROXY_RESET_NOT_READY")
        descriptor = os.open(f"/proc/{pid}/ns/net", os.O_RDONLY | os.O_CLOEXEC)
        try:
            proxy.reload()
            owned = proxy.attrs.get("State", {}).get("Pid") == pid and proxy.id in Path(f"/proc/{pid}/cgroup").read_text()
            namespace = os.fstat(descriptor)
            current = os.stat(f"/proc/{pid}/ns/net")
            host = os.stat("/proc/self/ns/net")
            identity = (namespace.st_dev, namespace.st_ino)
            if (not owned or identity != (current.st_dev, current.st_ino)
                    or identity == (host.st_dev, host.st_ino)):
                raise ValueError("PROXY_NAMESPACE_MISMATCH")
            try:
                result = subprocess.run(["nsenter", f"--net=/proc/self/fd/{descriptor}", "ss", "-K", "-t"],
                                        pass_fds=(descriptor,), stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                        text=True, timeout=2)
            except subprocess.TimeoutExpired:
                raise NetworkOperationError("ss", "reset", None, "timeout") from None
            # ss 可能返回 0 却没有断连；无论内核是否支持，都要求代理主动关连接并确认。
            unsupported = "Operation not supported" in (getattr(result, "stderr", "") or "")
            if result.returncode and not unsupported:
                raise NetworkOperationError("ss", "reset", result.returncode, "tool_failed")
            if proxy.attrs["State"].get("Paused"):
                proxy.unpause()
            reset = proxy.exec_run(["/egress", "--revoke"])
            if reset.exit_code or reset.output.strip() != b"REVOKED":
                raise NetworkOperationError("ss", "reset", None, "proxy_reset_unconfirmed")
        finally:
            os.close(descriptor)

    def revoke(self, job_id):
        """终止式撤权：阻止新流量，并杀死此任务代理关闭现存 TLS splice。"""
        with self.lock:
            ctx = self.jobs.get(job_id)
            if not ctx:
                return
            ctx.active = False
        # 撤权不等待prepare的槽位锁，启动过程异常时也能立即封网与终止代理。
        self._iptables("-I", ctx.forward_chain, "1", "-j", "REJECT", missing_ok=True)
        self._iptables("-I", ctx.input_chain, "1", "-j", "REJECT", missing_ok=True)
        proxy = ctx.proxy
        if proxy:
            from docker.errors import NotFound
            try:
                self._reset_proxy(ctx)
                proxy.remove(force=True)
            except NotFound:
                pass
            ctx.proxy = None

    def quota_error(self, job_id):
        """读取代理累计流量的超限标记，供管理服务将任务判为额度失败。"""
        ctx = self.jobs.get(job_id)
        if ctx and ctx.proxy:
            try:
                result = ctx.proxy.exec_run(['/egress', '--quota-status'])
                code = result.output.decode().strip()
                if result.exit_code == 0 and code in ('NETWORK_UPLOAD_LIMIT','NETWORK_DOWNLOAD_LIMIT'):
                    return code
            except Exception:
                pass  # 代理不可达时不会产生放行路径；仍由超时和回收器终止任务。
        return None

    def release(self, job_id):
        """调用方先销毁执行沙箱；清理失败保留槽位，禁止地址复用。"""
        with self.lock:
            ctx = self.jobs.get(job_id)
        if not ctx:
            return
        self.revoke(job_id)
        with self._slot_lock(ctx.slot):
            from docker.errors import NotFound
            try:
                network = self.client.networks.get(ctx.name)
                network.reload()
                labels = network.attrs.get("Labels") or {}
                if labels.get("lazyx.sb") != "true" or labels.get("lazyx.job") != job_id:
                    raise ValueError("拒绝清理其他工程的网络")
            except NotFound:
                network = None
            if network is not None and network.attrs.get("Containers"):
                raise RuntimeError("执行沙箱仍连接网络，不能回收任务地址")
            if network is not None:
                for address in (ctx.guest_ip, ctx.proxy_ip, ctx.proxy_out_ip):
                    if address:
                        for field in ("--orig-src", "--reply-src"):
                            self.command(["conntrack", "-D", field, address], missing_ok=True)
            if network is not None:
                try:
                    network.remove()
                except NotFound:
                    pass
            references = [shlex.split(line) for line in self._iptables("-S").splitlines()]
            proxy_reused = ctx.proxy_out_ip and any(
                len(rule) == 6 and rule[:3] == ["-A", "DOCKER-USER", "-s"]
                and rule[4] == "-j" and rule[5] != ctx.proxy_chain
                and re.fullmatch(r"SB_P_[0-9a-f]{4}-[0-9a-f]{8}", rule[5])
                and ipaddress.IPv4Network(rule[3]) == ipaddress.IPv4Network(ctx.proxy_out_ip)
                for rule in references)
            input_rules = []
            for rule in references:
                if rule[:1] == ["-A"] and len(rule) >= 4 and rule[-2:] in (
                        ["-j", ctx.forward_chain], ["-j", ctx.input_chain], ["-j", ctx.proxy_chain]):
                    self._iptables("-D", *rule[1:], missing_ok=True)
            if ctx.proxy_out_ip and not proxy_reused:
                for rule in references:
                    if (len(rule) == 10 and rule[:3] == ["-A", "INPUT", "-s"]
                            and rule[4:] == ["-m", "conntrack", "--ctstate", "NEW", "-j", "REJECT"]
                            and ipaddress.IPv4Network(rule[3]) == ipaddress.IPv4Network(ctx.proxy_out_ip)):
                        input_rules.append(rule)
                        self._iptables("-D", *rule[1:], missing_ok=True)
            for chain in (ctx.forward_chain, ctx.input_chain, ctx.proxy_chain):
                self._iptables("-F", chain, missing_ok=True)
                self._iptables("-X", chain, missing_ok=True)
            remaining_input = [shlex.split(line) for line in self._iptables("-S", "INPUT").splitlines()]
            if any(self.remaining_resources(job_id).values()) or any(rule in remaining_input for rule in input_rules):
                raise RuntimeError("NETWORK_RESOURCES_REMAIN")
            try:
                shutil.rmtree(ctx.policy_dir)
            except FileNotFoundError:
                pass
            with self.lock:
                self.jobs.pop(job_id, None)
