"""通过真实 gRPC 任务执行网络探针；可信测试侧仅驱动 RAM 控制文件和合成故障。"""
import asyncio
from datetime import timedelta
import hashlib
import io
import ipaddress
import json
import socket
import ssl
import tarfile
from pathlib import Path
import time
import tomllib
import urllib.request
import uuid

from opensandbox import Sandbox
from opensandbox.config import ConnectionConfig
from opensandbox.models import WriteEntry

RUN = Path("/run/sandbox_model")
HERE = Path(__file__).resolve().parent
DOMAINS = {"allowed.test": "172.27.250.10", "second.test": "172.27.250.10",
           "blocked.test": "172.27.250.10"}


def require(value, message="网络检查条件不满足"):
    if not value:
        raise AssertionError(message)


def fixture_json(address, path="/_evidence", body=None):
    data = None if body is None else json.dumps(body).encode()
    method = "GET" if body is None else "PUT"
    request = urllib.request.Request(f"http://{address}{path}", data=data, method=method,
                                     headers={"Content-Type": "application/json"})
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=3) as reply:
        value = reply.read(1024 * 1024)
        return json.loads(value) if value else None


def dns(mapping):
    fixture_json("172.27.250.53:8053", "/", mapping)


class Session:
    def __init__(self, suite, allowed=("allowed.test",), owner="alice"):
        self.suite, self.owner, self.index = suite, owner, 0
        self.nonce = uuid.uuid4().hex
        from sandbox_model.proto import sandbox_pb2 as pb
        import hashlib
        probe = (HERE / "network_probe.py").read_bytes()
        file = pb.InputFile(path="network_probe.py", data=probe,
                            sha256=hashlib.sha256(probe).hexdigest())
        code = b"""import hashlib,json,runpy,time
from pathlib import Path
probe=runpy.run_path('/workspace/inputs/network_probe.py')
index=0
while not Path('/workspace/finish-probe').exists():
    action=Path('/workspace/action-'+str(index)+'.json')
    if not action.exists():
        time.sleep(.05)
        continue
    wire=action.read_bytes()
    try:message=json.loads(wire)
    except (ValueError,UnicodeError):
        time.sleep(.01)
        continue
    result=probe['run'](message)
    Path('/workspace/out/probe-result.json').write_text(json.dumps({
        'index':index,'action_sha256':hashlib.sha256(wire).hexdigest(),'data':result}))
    index+=1
"""
        self.req = suite.request(owner=owner, code=code, inputs=[file], network_domains=list(allowed),
                                 timeout_seconds=120)
        suite.submit(self.req, owner)
        self.guest = suite.guest(self.req)
        proxies = suite.docker.containers.list(all=True, filters={
            "label": ["lazyx.sb=true", f"lazyx.job={self.req.request_id}"]})
        proxies = [container for container in proxies if container.name.startswith("sb-smokescreen-")]
        require(len(proxies) == 1, "没有找到唯一任务代理")
        self.proxy = proxies[0]
        self.proxy.reload()
        self.front_network = next(name for name in self.proxy.attrs["NetworkSettings"]["Networks"]
                                  if name.startswith("sb-job-"))
        endpoint = self.proxy.attrs["NetworkSettings"]["Networks"][self.front_network]
        self.proxy_mac, self.proxy_ip = endpoint["MacAddress"], endpoint["IPAddress"]
        self.sid = self.guest.labels["opensandbox.io/id"]
        self.policy = RUN / self.req.request_id
        self.domains = allowed

    def io(self, path, value=None):
        async def operation():
            # 仅测试可信侧读取合成服务凭据，不打印、不传入任务代码。
            config = tomllib.loads((RUN / "opensandbox.toml").read_text())
            connection = ConnectionConfig(domain="127.0.0.1:18080", api_key=config["server"]["api_key"],
                use_server_proxy=False, disable_metrics=True, request_timeout=timedelta(seconds=5))
            sandbox = await Sandbox.connect(self.sid, connection_config=connection,
                                            connect_timeout=timedelta(seconds=5))
            try:
                if value is None:
                    return await sandbox.files.read_bytes(path)
                await sandbox.files.write_files([WriteEntry(path=path, data=value, mode=644)])
            finally:
                await sandbox.close()
        return asyncio.run(operation())

    def action(self, action, seconds=65):
        index = self.index
        self.index += 1
        payload = json.dumps(dict(action) | {"_session": self.nonce}).encode()
        digest = hashlib.sha256(payload).hexdigest()
        self.io(f"/workspace/action-{index}.json", payload)
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            try:
                value = json.loads(self.io("/workspace/out/probe-result.json"))
                if value["index"] == index and value.get("action_sha256") == digest:
                    return value["data"]
            except Exception:
                pass
            from sandbox_model.proto import sandbox_pb2 as pb
            status = self.suite.stubs[self.owner].Status(pb.JobRef(request_id=self.req.request_id),timeout=5)
            if status.phase=='finished':
                import re
                result = self.suite.stubs[self.owner].Result(pb.JobRef(request_id=self.req.request_id),timeout=5)
                kinds = re.findall(r'([A-Za-z_.]*(?:Error|Exception)):',result.stderr)
                detail = kinds[-1].split('.')[-1] if kinds else status.error_code
                raise AssertionError('网络探针提前退出：'+detail)
            time.sleep(.1)
        raise AssertionError("网络探针未在期限内返回")

    def restart(self):
        self.proxy.reload()
        if self.proxy.status == "running":
            self.proxy.restart(timeout=1)
        else:
            self.proxy.start()
        for _ in range(80):
            result = self.proxy.exec_run(["/egress", "--healthcheck"])
            if result.exit_code == 0:
                self.proxy.reload()
                endpoint = self.proxy.attrs["NetworkSettings"]["Networks"][self.front_network]
                same_mac = endpoint["MacAddress"] == self.proxy_mac
                same_ip = endpoint["IPAddress"] == self.proxy_ip
                self.suite.runtime_evidence.setdefault("network_proxy_restarts", []).append(
                    {"mac_unchanged": same_mac, "address_unchanged": same_ip})
                require(same_mac and same_ip, "代理重启改变网卡身份，故障探针没有有效基础")
                return
            time.sleep(.1)
        raise AssertionError("合成故障后的代理无法启动")

    def finish(self):
        # 普通验收必须以成功结果结束；任务失败不能靠取消兜底变成通过。
        try:
            self.io("/workspace/finish-probe", b"1")
        except Exception:
            from sandbox_model.proto import sandbox_pb2 as pb
            self.suite.stubs[self.owner].Cancel(pb.JobRef(request_id=self.req.request_id), timeout=10)
            self.suite.result(self.req, self.owner, success=False)
            raise
        self.suite.result(self.req, self.owner, success=True)


def normal_checks(suite):
    dns(DOMAINS)
    session = Session(suite)
    try:
        allowed = session.action({"path": "/network-positive-" + uuid.uuid4().hex})
        require(allowed.get("tls") and allowed.get("fixture"), "允许域名没有实际访问源站")
        origin = suite.docker.containers.get("sb-origin")
        archive, _ = origin.get_archive("/fixtures/cert.pem")
        with tarfile.open(fileobj=io.BytesIO(b"".join(archive))) as bundle:
            cert = bundle.extractfile("cert.pem").read().decode()
        expected = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert)).hexdigest()
        require(allowed["certificate"] == expected, "代理替换了源站TLS证书")
        require(not session.action({"mode": "plain"})["origin_reached"], "CONNECT明文到达源站")
        require(not session.action({"mode": "ech"})["tls_record"], "ECH类型扩展被放行")
        hello = session.io("/workspace/out/ech.bin")
        with socket.create_connection(("172.27.250.10", 443), 3) as control:
            control.sendall(hello)
            response = control.recv(8192)
        require(len(response) >= 5 and response[0] == 22, "ECH拒绝用例缺少源站正对照")
        require(not session.action({"host": "second.test"}).get("tls"), "跨域名策略被放行")
        require(not session.action({"sni": "blocked.test"}).get("tls"), "CONNECT/SNI不一致被放行")
        require(not session.action({"sni": None}).get("tls"), "缺少SNI被放行")
        require(not any(session.action({"mode": "direct"}).values()), "直连旁路被放行")
        require(not any(session.action({"mode": "raw"})["raw_sockets"]), "可伪造源IP的原始套接字被允许")
        require(not session.action({"mode": "ipv6"})["connected"], "IPv6可旁路")
        marker = "dns-" + uuid.uuid4().hex + ".unapproved.test"
        session.action({"host": marker})
        queries = fixture_json("172.27.250.53:8053", "/")["queries"]
        require(not any(item["name"] == marker for item in queries), "未批准域名被代理解析")
        direct_name = "direct-" + uuid.uuid4().hex + ".test"
        session.action({"mode": "dns", "name": direct_name})
        queries = fixture_json("172.27.250.53:8053", "/")["queries"]
        require(not any(item["name"] == direct_name for item in queries), "任务可直接接触可信DNS")
    finally:
        session.finish()


def fault_check(suite, fault):
    """注入真实代理停止、挂起、策略损坏和 DNS 故障；不在产品代码留故障开关。"""
    dns(DOMAINS)
    session = Session(suite)
    path = session.policy / "policy.json"
    original = path.read_text()
    marker = uuid.uuid4().hex
    paused = False
    try:
        require(session.action({}).get("fixture"), "故障前正常访问没有通过")
        if fault == "stopped":
            session.proxy.kill()
        elif fault == "paused":
            session.proxy.pause()
            paused = True
        elif fault in ("invalid_policy", "missing_policy"):
            path.write_text("{" if fault == "invalid_policy" else "{}")
            session.proxy.restart(timeout=1)
            time.sleep(.3)
            session.proxy.reload()
            require(session.proxy.status == "exited", "无有效策略的代理仍在运行")
        elif fault == "dns_unavailable":
            config = json.loads(original)
            config["dns_server"] = "192.0.2.1"
            path.write_text(json.dumps(config))
            session.restart()
        values = session.action({"mode": "batch", "actions": [
            {"path": "/fault-"+marker+"-"+str(i), "timeout": 6,
             "sni": "allowed.test" if i == 0 else "blocked.test"} for i in range(2)]})
        require(all(not item.get("tls") for item in values), "代理故障时建立了 TLS")
        hits = fixture_json("172.27.250.10")["requests"]
        count = sum("/fault-"+marker in item["path"] for item in hits)
        require(count == 0, "故障请求到达了源站")
        if paused:
            session.proxy.unpause(); paused = False
        path.write_text(original)
        session.restart()
        require(session.action({"path": "/recovered-"+marker}).get("fixture"), "恢复后不能访问")
        suite.runtime_evidence.setdefault("network_faults", []).append({
            "proxy": "smokescreen", "fault": fault, "requests": len(values),
            "origin_requests": count, "recovered": True,
            "client_errors": [item.get("error") for item in values]})
    finally:
        if paused:
            session.proxy.unpause()
        if path.parent.exists():path.write_text(original)
        session.finish()


def capacity_check(suite):
    dns(DOMAINS)
    session = Session(suite)
    try:
        policy = session.policy / "policy.json"
        config = json.loads(policy.read_text())
        config["max_tunnels"] = 1
        policy.write_text(json.dumps(config))
        session.restart()
        value = session.action({"mode": "capacity"})
        require(value.get("overflow_denied") and value.get("recovered"), "连接过载拒绝或容量恢复失败")
        suite.runtime_evidence["proxy_capacity"] = {"injected_limit": 1, "overflow_denied": True, "recovered": True}
    finally:
        session.finish()


def dns_check(suite):
    dns(DOMAINS)
    session = Session(suite)
    try:
        require(session.action({}).get("fixture"), "DNS变更前允许源站不可达")
        for address in ("172.27.250.11", "169.254.169.254", "100.100.100.200"):
            mapping = DOMAINS | {"allowed.test": address}
            dns(mapping)
            time.sleep(2)
            marker = "/dns-private-" + uuid.uuid4().hex
            denied = session.action({"path": marker})
            require(not denied.get("tls"), "DNS切到私网后仍放行")
            queries = fixture_json("172.27.250.53:8053", "/")["queries"]
            require(any(item["name"] == "allowed.test" and item["address"] == address
                        for item in queries), "没有看到新的DNS解析")
            if address == "172.27.250.11":
                hits = fixture_json("172.27.250.11")["requests"]
                require(not any(item["path"] == marker for item in hits), "DNS私网请求到达内部源站")
        dns(DOMAINS)
        time.sleep(2)
        require(session.action({}).get("fixture"), "DNS恢复后允许请求未恢复")
    finally:
        dns(DOMAINS)
        session.finish()


def isolation_and_reuse(suite):
    dns(DOMAINS)
    a, b = Session(suite), Session(suite, ("second.test",), "bob")
    a_ip = next(net["IPAddress"] for net in a.guest.attrs["NetworkSettings"]["Networks"].values())
    try:
        require(a.action({}).get("fixture"), "A允许域名访问失败")
        require(b.action({"host": "second.test"}).get("fixture"), "B允许域名访问失败")
        require(not a.action({"host": "second.test"}).get("tls"), "A继承了B域名权限")
        require(not b.action({}).get("tls"), "B继承了A域名权限")
        b_ip = next(net["IPAddress"] for net in b.guest.attrs["NetworkSettings"]["Networks"].values())
        require(not any(a.action({"mode": "direct", "addresses": [[b_ip, 44772], [b_ip, 8080]]}).values()),
                "任务之间可以直接互访")
        marker = "/stream-revoke-" + uuid.uuid4().hex
        a.io(f"/workspace/action-{a.index}.json", json.dumps({"path": marker}).encode())
        a.index += 1
        for _ in range(50):
            events = fixture_json("172.27.250.10")["events"]
            if any(event.get("stream_id") == marker and event["event"] == "start" for event in events):
                break
            time.sleep(.1)
        else:
            raise AssertionError("长连接未实际建立")
        from sandbox_model.proto import sandbox_pb2 as pb
        lease = json.loads((RUN / "leases.json").read_text())
        old_context = lease["jobs"][a.req.request_id]["network"]
        started = time.monotonic()
        suite.stubs["alice"].Cancel(pb.JobRef(request_id=a.req.request_id), timeout=10)
        suite.result(a.req, success=False)
        for _ in range(50):
            ends = [event for event in fixture_json("172.27.250.10")["events"]
                    if event.get("stream_id") == marker and event["event"] == "end"]
            if ends:
                break
            time.sleep(.1)
        require(ends and ends[-1]["reason"] == "peer_disconnect"
                and ends[-1]["chunks_sent"] < 200, "撤权没有主动关闭源站长连接")
        require(time.monotonic() - started < 8, "撤权清理超过测试期限")
        require(b.action({"host": "second.test"}).get("fixture"), "撤权A影响了B")
        c = Session(suite, ("second.test",))
        try:
            c_ip = next(net["IPAddress"] for net in c.guest.attrs["NetworkSettings"]["Networks"].values())
            require(c_ip == a_ip, "没有实际复用旧任务地址")
            # 真实执行旧上下文回收逻辑，再检查同IP新任务的规则与连接。
            from sandbox_model.watchdog import Watchdog
            reaper = Watchdog(suite.docker, run_dir=str(RUN))
            result = reaper.reap(a.req.request_id, {"network": old_context}, "test_old_generation")
            require(result["cleaned"], "旧代次重复回收不幂等")
            time.sleep(.5)
            require(c.action({"host": "second.test"}).get("fixture"), "复用地址的新任务被旧回收影响")
            require(not c.action({}).get("tls"), "新任务继承了旧任务域名权限")
        finally:
            c.finish()
    finally:
        b.finish()


def public_check(suite):
    """真实公网验收；只增加公开 A 记录，结束后恢复合成 DNS。应串行调用。"""
    request = urllib.request.Request(
        "https://cloudflare-dns.com/dns-query?name=example.com&type=A",
        headers={"Accept": "application/dns-json"})
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=15) as reply:
        record = json.loads(reply.read(65536))
    require(record.get("Status") == 0, "官方HTTPS DNS查询失败")
    addresses = [str(ipaddress.IPv4Address(answer["data"])) for answer in record.get("Answer", [])
                 if answer.get("type") == 1 and ipaddress.IPv4Address(answer["data"]).is_global]
    require(addresses, "没有取得真实公网地址")
    previous = fixture_json("172.27.250.53:8053", "/")["mapping"]
    session = None
    try:
        dns(previous | {"example.com": addresses[0]})
        session = Session(suite, ("example.com",))
        result = session.action({"host": "example.com", "path": "/", "verify": True})
        require(result.get("http_status") == 200 and result.get("tls_verified")
                and result.get("example_domain"), "真实公网HTTPS内容或证书验证失败")
        suite.runtime_evidence["public_https"] = {"http_status": 200, "tls_verified": True,
                                                  "example_domain": True, "public_ip_verified": True}
    finally:
        try:
            if session is not None:
                session.finish()
        finally:
            dns(previous)


def partial_control_message_check(suite):
    # 确定性重现 SDK 写入完成前，任务已观察到文件存在的时序。
    dns(DOMAINS)
    session = Session(suite)
    try:
        session.io('/workspace/action-0.json',b'{')
        time.sleep(.2)
        require(session.action({}).get('fixture'),'测试控制文件分段写入导致探针退出')
    finally:
        session.finish()


def run_network_checks(suite):
    suite.check("网络探针控制文件分段写入后正常执行",lambda:partial_control_message_check(suite))
    suite.check("网络正常访问、TLS限制、直连/DNS/IPv6/源IP旁路阻断", lambda: normal_checks(suite))
    suite.check("两任务策略隔离、长连接撤权、地址复用", lambda: isolation_and_reuse(suite))
    suite.check("真实DNS变更到私网、元数据地址被阻断并可恢复", lambda: dns_check(suite))
    for fault in ("stopped", "paused", "invalid_policy", "missing_policy", "dns_unavailable"):
        suite.check(f"Smokescreen {fault}真实故障拒绝与恢复",
                    lambda fault=fault: fault_check(suite, fault))
    suite.check("Smokescreen 并发隧道限额、过载拒绝与恢复", lambda: capacity_check(suite))
    suite.check("真实公网HTTPS系统证书验证与内容", lambda: public_check(suite))
