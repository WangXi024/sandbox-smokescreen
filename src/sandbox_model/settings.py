"""节点启动配置；调用方只能在这些上限内缩小单任务额度。"""
from dataclasses import dataclass, fields
import ipaddress
import json
import os
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    """节点可承受的固定上限；排队容量和同时执行容量分别配置。"""
    dns_server: str = "1.1.1.1"
    dns_over_https: bool = True
    proxy_image: str = "sandbox-smokescreen-egress:7d0ddfa-tls1"
    concurrency: int = 2
    max_inflight: int = 6
    max_memory_mb: int = 1024
    max_timeout_seconds: int = 120
    upload_bytes: int = 8 * 1024 * 1024
    download_bytes: int = 32 * 1024 * 1024
    history_seconds: int = 86400
    max_history: int = 4096

    @classmethod
    def load(cls):
        """启动时拒绝未知字段、错误类型和越界额度，避免配置错误降低保护。"""
        path = Path(os.environ.get("SANDBOX_CONFIG", "/opt/sandbox_model/deploy/settings.json"))
        data = json.loads(path.read_text())
        if not isinstance(data, dict) or set(data) - {field.name for field in fields(cls)}:
            raise ValueError("INVALID_NODE_CONFIG")
        value = cls(**data)
        limits = {"concurrency": (1, 2), "max_inflight": (1, 6), "max_memory_mb": (128, 1024),
                  "max_timeout_seconds": (1, 120), "upload_bytes": (1024, 128 * 1024 * 1024),
                  "download_bytes": (1024, 128 * 1024 * 1024), "history_seconds": (300, 604800),
                  "max_history": (16, 4096)}
        for key, (low, high) in limits.items():
            entry = getattr(value, key)
            if type(entry) is not int or not low <= entry <= high:
                raise ValueError("INVALID_NODE_CONFIG")
        if (type(value.dns_over_https) is not bool or value.max_inflight < value.concurrency or not isinstance(value.proxy_image, str)
                or not value.proxy_image or not ipaddress.IPv4Address(value.dns_server).is_global):
            raise ValueError("INVALID_NODE_CONFIG")
        return value
