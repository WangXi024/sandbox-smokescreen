"""使用官方 CLI 在独立进程启动 OpenSandbox，并装配可信逐任务运行配置。"""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sys

from .watchdog import read_private_json


class RegistryNetwork:
    """管理侧原子写入的 RAM 注册表；每次 create 重新读取以避免缓存旧策略。"""

    def __init__(self, path="/run/sandbox_model/network-registry.json", client=None):
        if client is None:
            import docker
            client = docker.from_env()
        self.path = Path(path)
        self.client = client

    def create_config(self, job_id):
        """核对网络名称、任务摘要和固定地址布局，再构造 Docker 网络参数。"""
        values = read_private_json(self.path)[job_id]
        mode = values["network_mode"]
        guest = ipaddress.IPv4Address(values["guest_ip"])
        peer = ipaddress.IPv4Address(values["trusted_peer"])
        subnet = ipaddress.IPv4Network((int(peer) & ~7, 29))
        hosts = tuple(subnet.hosts())
        if (not re.fullmatch(r"sb-job-[0-9a-f]{4}-" + hashlib.sha256(job_id.encode()).hexdigest()[:8], mode)
                or peer != hosts[0] or guest != hosts[2]):
            raise ValueError("任务网络配置错误")
        endpoint = self.client.api.create_endpoint_config(ipv4_address=str(guest))
        return {"network_mode": mode,
                "networking_config": self.client.api.create_networking_config({mode: endpoint}),
                "trusted_peer": str(peer)}


def main():
    """先装配固定版本运行适配，再进入官方 CLI；基础镜像按不可变 ID 登记。"""
    parser = argparse.ArgumentParser(description="独立 OpenSandbox 进程")
    parser.add_argument("--config", default="/run/sandbox_model/opensandbox.toml")
    parser.add_argument("--registry", default="/run/sandbox_model/network-registry.json")
    parser.add_argument("--catalog", default="/opt/sandbox_model/catalog.json")
    parser.add_argument("--test-mode", action="store_true")
    args = parser.parse_args()
    catalog = json.loads(Path(args.catalog).read_text())
    images = tuple(sorted(set(value["image_id"] for value in catalog.values())))
    if not images or any(not re.fullmatch(r"sha256:[0-9a-f]{64}", image) for image in images):
        raise SystemExit("目录必须包含固定运行镜像 ID")
    from .runtime_adapter import install
    install(RegistryNetwork(args.registry), runtime_images=images, test_mode=args.test_mode,
            image_registry="/run/sandbox_model/environment-images.json")
    from opensandbox_server.cli import main as official_main
    sys.argv = ["opensandbox-server", "--config", args.config]
    official_main()


if __name__ == "__main__":
    main()
