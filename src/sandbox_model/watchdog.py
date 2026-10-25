"""独立于管理服务和 OpenSandbox 的任务回收进程，仅操作本项目标签。"""
import argparse
import json
import os
from pathlib import Path
import signal
import tempfile
import time

from .network import NetworkManager


def pid_alive(pid, proc_root="/proc"):
    """kill(0) 会把僵尸算存活，Linux /proc 状态必须一起检查。"""
    if not isinstance(pid, int) or pid <= 0:
        return False
    try:
        stat = (Path(proc_root) / str(pid) / "stat").read_text()
        state = stat.rsplit(") ", 1)[1].split()[0]
        return state not in ("Z", "X", "x")
    except (OSError, IndexError):
        return False


def read_private_json(path):
    """拒绝符号链接、其他用户和可被他人读写的清理元数据，并限制文件大小。"""
    path = Path(path)
    info = path.lstat()
    if path.is_symlink() or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("回收元数据文件必须归当前用户所有且权限为 0600")
    if info.st_size > 1_048_576:
        raise ValueError("回收元数据过大")
    return json.loads(path.read_text())


def atomic_json(path, value):
    """先写私有临时文件再原子替换，管理服务和回收器不会读到半份 JSON。"""
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix=".meta-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, ensure_ascii=False, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


class Watchdog:
    """依租约、进程存活及项目标签回收资源，不依赖管理服务继续响应。"""
    def __init__(self, client, *, leases="/run/sandbox_model/leases.json",
                 report="/run/sandbox_model/reaped.json", run_dir="/run/sandbox_model",
                 heartbeat_timeout=3, clock=time.time, alive=pid_alive, network_manager=None):
        self.client = client
        self.leases = Path(leases)
        self.report = Path(report)
        self.heartbeat_timeout = heartbeat_timeout
        self.clock = clock
        self.alive = alive
        self.network = network_manager or NetworkManager(client, run_dir=run_dir)
        self.expired = {}
        self.results = {}
        self.cleaned_at = {}
        self.last_snapshot = None
        self.orphan_seen = {}
        self.started = self.clock()

    def step(self):
        """保留过期任务墓碑并持续重扫，处理失联前发起但迟到的创建。"""
        try:
            snapshot = read_private_json(self.leases)
            if not isinstance(snapshot, dict) or not isinstance(snapshot.get("jobs"), dict):
                raise ValueError("租约结构错误")
            float(snapshot.get("heartbeat", 0))
            self.last_snapshot = snapshot
        except FileNotFoundError:
            if self.last_snapshot is None:
                snapshot = {"manager_pid": 0, "opensandbox_pid": 0, "heartbeat": 0, "jobs": {}}
            else:
                snapshot = self.last_snapshot
        except (ValueError, OSError):
            # 元数据损坏时沿用已知清理身份，但将心跳视为失联，避免继续放行。
            snapshot = (self.last_snapshot or {"jobs": {}}) | {"heartbeat": 0}
        now = self.clock()
        reasons = []
        if not self.alive(snapshot.get("manager_pid")):
            reasons.append("manager_lost")
        if not self.alive(snapshot.get("opensandbox_pid")):
            reasons.append("opensandbox_lost")
        if now - float(snapshot.get("heartbeat", 0)) > self.heartbeat_timeout:
            reasons.append("heartbeat_expired")
        jobs = snapshot.get("jobs", {})
        if not isinstance(jobs, dict):
            jobs = {}
        for job_id, entry in jobs.items():
            if not isinstance(entry, dict):
                continue
            reason = ",".join(reasons) if reasons else ""
            if now >= float(entry.get("deadline", 0)):
                reason = reason or "deadline_expired"
            if reason:
                self.expired[job_id] = (entry, reason)
        self.scan_orphans(jobs, now)
        for job_id, (entry, reason) in tuple(self.expired.items()):
            if job_id in self.cleaned_at:
                continue
            self.results[job_id] = self.reap(job_id, entry, reason)
            if self.results[job_id]['cleaned']:
                self.cleaned_at[job_id] = now
        # 已确认清理的记录有界保留；迟到的资源仍由每轮标签扫描重新发现。
        for job_id, stamp in sorted(self.cleaned_at.items(), key=lambda item:item[1]):
            if now-stamp > 600 or len(self.cleaned_at) > 128:
                self.cleaned_at.pop(job_id, None)
                self.expired.pop(job_id, None)
                self.results.pop(job_id, None)
        if self.expired:
            atomic_json(self.report, {"checked_at": now, "jobs": self.results})
        return self.results

    def scan_orphans(self, active_jobs, now):
        """给尚未写入租约的创建留短暂窗口，再将无主资源加入重复清理队列。"""
        contexts = {}
        observed = set()
        networks = self.client.networks.list(filters={"label": "lazyx.sb=true"}) if hasattr(self.client, "networks") else []
        for network in networks:
            labels = network.attrs.get("Labels") or {}
            job_id = labels.get("lazyx.job")
            if not job_id or labels.get("lazyx.sb.fixture"):
                continue
            observed.add(job_id)
            if job_id not in active_jobs or (job_id in self.expired and self.expired[job_id][0].get("network") is None):
                contexts[job_id] = self.network.orphan_context(network)
        for container in self.client.containers.list(all=True, filters={"label": ["lazyx.sb=true"]}):
            labels = container.labels or {}
            job_id = labels.get("lazyx.job")
            if job_id and labels.get("lazyx.sb") == "true" and not labels.get("lazyx.sb.fixture"):
                observed.add(job_id)
        for job_id in observed:
            self.cleaned_at.pop(job_id, None)
            if job_id in self.expired and self.expired[job_id][0].get("network") is None and job_id in contexts:
                entry, reason = self.expired[job_id]
                self.expired[job_id] = (entry | {"network": contexts[job_id]}, reason)
            if job_id in active_jobs or job_id in self.expired:
                self.orphan_seen.pop(job_id, None)
                continue
            first = self.orphan_seen.setdefault(job_id, now)
            if now - first >= 2:
                self.expired[job_id] = ({"network": contexts.get(job_id)}, "orphaned")
        for job_id in tuple(self.orphan_seen):
            if job_id not in observed:
                self.orphan_seen.pop(job_id, None)

    def reap(self, job_id, entry, reason):
        """先确认撤权，再删容器、网络和规则；任何不确定项都不能报告清理成功。"""
        errors, removed = [], []
        revoked = True
        if entry.get("network") is not None:
            try:
                context = dict(entry["network"])
                if context["job_id"] != job_id:
                    raise ValueError("任务与网络不一致")
                self.network.restore_context(context)
                self.network.revoke(job_id)
            except Exception as exc:
                revoked = False
                errors.append(type(exc).__name__)
        try:
            owned = self.client.containers.list(all=True, filters={
                "label": ["lazyx.sb=true", f"lazyx.job={job_id}"]})
            for container in owned:
                # Docker 过滤之外再次检查标签，绝不扩大到其他工程容器。
                labels = container.labels or {}
                if labels.get("lazyx.sb") != "true" or labels.get("lazyx.job") != job_id:
                    continue
                if not revoked and container.name.startswith("sb-smokescreen-"):
                    continue  # 未确认断连时保留代理命名空间供重试，不提前回收地址。
                container.remove(force=True)
                removed.append(container.id)
        except Exception as exc:
            errors.append(type(exc).__name__)
        if entry.get("network") is not None and revoked:
            try:
                self.network.release(job_id)
            except Exception as exc:
                errors.append(type(exc).__name__)
        remaining = None
        network_remaining = {"networks": None, "rules": None}
        try:
            remaining = len(self.client.containers.list(all=True, filters={
                "label": ["lazyx.sb=true", f"lazyx.job={job_id}"]}))
        except Exception as exc:
            errors.append(type(exc).__name__)
        try:
            network_remaining = self.network.remaining_resources(job_id)
        except Exception as exc:
            errors.append(type(exc).__name__)
        return {"reason": reason, "containers_removed": removed, "remaining_containers": remaining,
                "remaining_networks": network_remaining["networks"], "remaining_rules": network_remaining["rules"],
                "cleaned": not errors and remaining == 0 and network_remaining == {"networks": 0, "rules": 0},
                "errors": sorted(set(errors))}


def main():
    """可信节点侧周期执行回收，成功检查后刷新自己的健康心跳。"""
    parser = argparse.ArgumentParser(description="独立任务回收守护进程")
    parser.add_argument("--leases", default="/run/sandbox_model/leases.json")
    parser.add_argument("--report", default="/run/sandbox_model/reaped.json")
    parser.add_argument("--run-dir", default="/run/sandbox_model")
    args = parser.parse_args()
    if os.geteuid() != 0 or not Path("/proc").is_dir():
        raise SystemExit("回收守护程序必须运行于专用 Linux 节点的可信 root 侧")
    import docker
    worker = Watchdog(docker.from_env(), leases=args.leases, report=args.report, run_dir=args.run_dir)
    running = True

    def stop(*_):
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while running:
        try:
            worker.step()
            atomic_json(Path(args.run_dir)/'watchdog-heartbeat.json', {'pid':os.getpid(), 'time':time.time()})
        except Exception:
            print("[回收] 检查失败，等待重试", flush=True)
        time.sleep(.25)


if __name__ == "__main__":
    main()
