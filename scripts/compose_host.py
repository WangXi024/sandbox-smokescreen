"""调用当前项目的 Compose；不会读取或管理 Lima 实例。"""
from pathlib import Path
import json
import subprocess

PROJECT = Path(__file__).resolve().parents[1]
OUTPUTS = PROJECT.parent / "sandbox_smokescreen_outputs"


def compose(*args, check=True, capture=False, timeout=None):
    # 固定项目目录和配置文件，避免从其他工作目录误操作相邻项目的容器。
    return subprocess.run(["docker", "compose", "--project-directory", str(PROJECT),
                           "-f", str(PROJECT / "compose.yaml"), *args],
                          check=check, text=True, capture_output=capture, timeout=timeout)


def node_command(*args, **options):
    # 不分配终端，保证 JSON 和二进制编码结果可以由调用方完整读取。
    return compose("exec", "-T", "sandbox", *args, **options)


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
    # 写完再替换，读取方不会看到只写入一半的报告。
    temporary.replace(path)
