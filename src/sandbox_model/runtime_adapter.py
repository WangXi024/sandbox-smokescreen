"""OpenSandbox 1.1.1 的小范围 Docker 适配；不改变 SDK 执行协议。

仅在专用 Linux 节点的 OpenSandbox Server 导入前调用 install()。
任务网络必须由可信 NetworkManager 预先创建，镜像必须预装 execd。
"""
from __future__ import annotations

import asyncio
from importlib.metadata import version
import ipaddress
import logging
from pathlib import Path
import re
import time
from collections.abc import Collection
from typing import Any

SERVER_VERSION = "1.1.1"
RUNTIME_LABEL = "sb0-v1"
WORKLOAD_UID = 1000
WORKLOAD_GID = 1000
# env 来自可信管理服务；也在底座拒绝可能注入凭据或替换启动组件的字段。
_ALLOWED_ENV = frozenset({"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy", "LANG", "LC_ALL", "TZ", "HOME", "TMPDIR", "PYTHONDONTWRITEBYTECODE", "LAZYX_GATEWAY", "LAZYX_TEST_TLS_SPKI"})
_INSTALLED = False


async def _test_create_response_gate(job_id: str) -> None:
    """仅专用测试模式：在真实创建完成、HTTP 响应返回前等待可信故障注入。"""
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", job_id):
        raise ValueError("TEST_GATE_INVALID")
    gate = Path("/run/sandbox_model/test-gates") / (job_id + ".create_response")
    if not gate.exists():
        return
    info = gate.lstat()
    if gate.is_symlink() or info.st_uid != 0 or info.st_mode & 0o077 or gate.read_text() != "hold":
        raise ValueError("TEST_GATE_INVALID")
    entered = Path(str(gate) + ".entered")
    entered.write_text("entered")
    entered.chmod(0o600)
    deadline = time.monotonic() + 20
    while gate.exists():
        if time.monotonic() >= deadline:
            raise RuntimeError("TEST_GATE_TIMEOUT")
        await asyncio.sleep(0.02)


def harden_host_config(config: dict[str, Any]) -> None:
    """固定隔离参数；所有任务可写路径在有界 tmpfs 中，超限不得落盘。"""
    if config.get("binds") or config.get("device_requests") or config.get("privileged"):
        raise ValueError("SB0 不允许宿主挂载、设备或特权模式")
    if not config.get("mem_limit") or int(config["mem_limit"]) <= 0:
        raise ValueError("任务必须指定内存上限")
    config.update(
        runtime="runsc", read_only=True, privileged=False,
        cap_drop=["ALL"], cap_add=["CHOWN", "SETUID", "SETGID", "DAC_OVERRIDE", "KILL"],
        security_opt=["no-new-privileges:true"],
        pids_limit=512, memswap_limit=config["mem_limit"],
        log_config={"type": "none"},
        # UID1000 先触及自己的上限；外层还容纳 gVisor 执行线程和可信控制进程。
        ulimits=[{"Name": "core", "Soft": 0, "Hard": 0}, {"Name": "nproc", "Soft": 128, "Hard": 128}],
        tmpfs={
            "/workspace": "rw,nosuid,nodev,size=64m,mode=0700,uid=1000,gid=1000",
            "/tmp": "rw,nosuid,nodev,size=32m,mode=1777",
            "/var/tmp": "rw,nosuid,nodev,size=16m,mode=1777",
            "/run": "rw,nosuid,nodev,size=16m,mode=0755",
            "/home/sandbox": "rw,nosuid,nodev,size=16m,mode=0700,uid=1000,gid=1000",
        },
    )
    # 控制端口只向节点本机发布；API 内部另核对真实 TCP 来源。
    config["port_bindings"] = {
        port: ("127.0.0.1", binding[1])
        for port, binding in (config.get("port_bindings") or {}).items()
    }


def validate_request(request: Any, images: Collection[str]) -> str:
    """在管理服务之外再次校验可信创建请求，拒绝挂载、凭据和未登记镜像。"""
    job_id = (request.metadata or {}).get("lazyx.job")
    if not isinstance(job_id, str) or not job_id:
        raise ValueError("缺少可信任务标记 lazyx.job")
    if request.image.uri not in images or request.image.auth:
        raise ValueError("环境不在登记镜像清单中")
    if request.network_policy or request.volumes or request.extensions or request.credential_proxy:
        raise ValueError("不允许内置 egress、挂载、扩展或凭据代理")
    if getattr(request, "snapshot_id", None):
        raise ValueError("每个任务必须使用新沙箱")
    if request.entrypoint not in (["sleep", "infinity"], ["/usr/bin/sleep", "infinity"]):
        raise ValueError("创建时仅允许平台可信等待程序")
    if set(request.env or {}) - _ALLOWED_ENV:
        raise ValueError("环境变量包含未允许字段")
    for key, value in (request.env or {}).items():
        if "proxy" in key.lower() and key.lower() != "no_proxy" and value:
            from urllib.parse import urlsplit
            proxy = urlsplit(value)
            if proxy.username or proxy.password:
                raise ValueError("代理地址不得包含凭据")
    return job_id


def install(network_manager: Any, runtime_images: Collection[str] = ("sandbox-model-runtime:sb0",), *, test_mode: bool = False, image_registry=None) -> None:
    """在导入官方 Server app 之前安装发行版本固定的可信 hook。

    network_manager.create_config(job_id) 是幂等纯读接口，返回
    network_mode、networking_config 和 trusted_peer（任务 bridge gateway）。
    """
    global _INSTALLED
    if _INSTALLED:
        raise RuntimeError("runtime adapter 已安装；一个进程只安装一次")
    if version("opensandbox-server") != SERVER_VERSION or version("opensandbox") != SERVER_VERSION:
        raise RuntimeError("仅支持经核查的 OpenSandbox Server/SDK 1.1.1")
    from opensandbox_server.services.docker import DockerSandboxService
    from opensandbox_server.services.docker.container_ops import DockerContainerOpsMixin
    from opensandbox_server.services.docker.runtime import DockerRuntimeMixin
    from opensandbox_server.services.docker.networking import DockerNetworkingMixin

    original_init = DockerSandboxService.__init__
    original_create = DockerSandboxService.create_sandbox
    original_start = DockerContainerOpsMixin._create_and_start_container
    original_endpoint = DockerNetworkingMixin.get_endpoint
    fixed_images = frozenset(runtime_images)

    def allowed_images():
        """每次重读私有镜像登记表，让已核验依赖环境可用而不开放任意镜像。"""
        if image_registry is None:return fixed_images
        from .watchdog import read_private_json
        images = read_private_json(image_registry)
        if not isinstance(images,list) or len(images)>8 or any(not isinstance(x,str) or not re.fullmatch(r'sha256:[0-9a-f]{64}',x) for x in images):
            raise ValueError('INVALID_ENVIRONMENT_REGISTRY')
        return fixed_images | frozenset(images)


    def init(self: Any, *args: Any, **kwargs: Any) -> None:
        original_init(self, *args, **kwargs)
        if self.network_mode in ("host", "none"):
            raise RuntimeError("Server 必须使用 bridge 端口解析模式")
        if self.app_config.docker.sandbox_env or self.app_config.docker.sandbox_binds:
            raise RuntimeError("禁止全局沙箱环境变量和宿主挂载")
        original_api_create = self.docker_client.api.create_container

        def api_create(*args: Any, **kwargs: Any) -> Any:
            job_id = (kwargs.get("labels") or {}).get("lazyx.job")
            if not job_id:
                raise ValueError("拒绝没有可信任务标记的容器")
            net = network_manager.create_config(job_id)
            kwargs["networking_config"] = net["networking_config"]
            return original_api_create(*args, **kwargs)

        # 创建前固定预分配的任务网络，不能让官方默认网络覆盖隔离边界。
        self.docker_client.api.create_container = api_create

    async def create(self: Any, request: Any, *args: Any, **kwargs: Any) -> Any:
        job_id = validate_request(request, allowed_images())
        response = await original_create(self, request, *args, **kwargs)
        if test_mode:
            await _test_create_response_gate(job_id)
        return response

    def start(self: Any, sandbox_id: str, image_uri: str, bootstrap_command: list[str], labels: dict[str, str], environment: list[str], host_config_kwargs: dict[str, Any], exposed_ports: Any, platform: Any, unconfine_system_paths: bool = False) -> Any:
        if unconfine_system_paths or image_uri not in allowed_images():
            raise ValueError("拒绝未登记运行环境")
        labels["lazyx.sb"] = "true"
        net = network_manager.create_config(labels["lazyx.job"])
        peer = str(ipaddress.IPv4Address(net["trusted_peer"]))
        if ipaddress.ip_address(peer).is_loopback:
            raise ValueError("控制来源不得为任务 loopback")
        host_config_kwargs["network_mode"] = net["network_mode"]
        harden_host_config(host_config_kwargs)
        image = self.docker_client.images.get(image_uri)
        if image.attrs.get("Config", {}).get("Labels", {}).get("lazyx.runtime") != RUNTIME_LABEL:
            raise ValueError("镜像缺少已验证运行组件标记")
        # 对本次实例固定镜像ID；不让可变tag在创建中途被换掉。
        image_uri = image.id
        env = [item for item in environment if not item.startswith("EXECD_")]
        env += [f"EXECD_TRUSTED_PEER={peer}", "EXECD_ENVS=/run/execd.env", "EXECD_LOG_FILE=/run/execd.log", "HOME=/home/sandbox", "TMPDIR=/run/execd-tmp", "PYTHONDONTWRITEBYTECODE=1"]
        return original_start(self, sandbox_id, image_uri, bootstrap_command, labels, env, host_config_kwargs, exposed_ports, platform, unconfine_system_paths=False)

    def endpoint(self: Any, sandbox_id: str, port: int, resolve_internal: bool = False, expires: int | None = None, use_proxy_host: bool = False) -> Any:
        # Docker internal bridge 不实际发布端口，SDK直连须使用节点可达的内网地址。
        # API仅限可信节点本机；执行沙箱无法调用管理接口或冒用其他任务。
        container = self._get_container_by_sandbox_id(sandbox_id)
        labels = container.attrs.get("Config", {}).get("Labels", {}) or {}
        if labels.get("lazyx.sb") != "true" or not labels.get("lazyx.job"):
            raise ValueError("拒绝非本服务管理的执行端点")
        net = network_manager.create_config(labels["lazyx.job"])
        if net["network_mode"] not in container.attrs.get("NetworkSettings", {}).get("Networks", {}):
            raise ValueError("执行端点与可信任务网络不匹配")
        return original_endpoint(self, sandbox_id, port, resolve_internal=True, expires=expires, use_proxy_host=False)

    def prepared_runtime(self: Any, container: Any, sandbox_id: str, platform: Any = None) -> None:
        # readonly rootfs 上不能 put_archive；组件已在固定可信镜像中。
        if container.attrs.get("Config", {}).get("Image") is None:
            raise RuntimeError("运行镜像校验失败")

    # 只替换已核查版本的创建和端点装配步骤，保留 SDK 命令及文件协议。
    DockerSandboxService.__init__ = init
    DockerSandboxService.create_sandbox = create
    DockerContainerOpsMixin._create_and_start_container = start
    DockerRuntimeMixin._prepare_sandbox_runtime = prepared_runtime
    DockerNetworkingMixin.get_endpoint = endpoint
    # HTTP/SDK日志可能含路径或代码错误；节点日志仅保留管理服务元数据事件。
    for name in ("opensandbox_server", "opensandbox", "httpx", "httpcore", "docker", "uvicorn.access"):
        logging.getLogger(name).disabled = True
    _INSTALLED = True
