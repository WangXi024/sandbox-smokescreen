"""可信侧产物导出：独立枚举和读取文件，不信任任务生成的文件路径或摘要。"""
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

MAX_FILES = 8
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 4 * 1024 * 1024
MAX_MANIFEST_BYTES = 256 * 1024


def read_artifacts(directory: Path, *, require_manifest: bool = True) -> dict:
    # 从目录描述符相对打开文件，避免任务用链接把读取引向工作目录外。
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    artifacts = []
    total = 0
    manifest = None
    visited_entries = 0

    def visit(directory_fd, prefix=""):
        nonlocal total, manifest, visited_entries
        names = []
        with os.scandir(directory_fd) as entries:
            for entry in entries:
                visited_entries += 1
                if visited_entries > 64:
                    raise ValueError("输出目录项超过 64 个")
                names.append(entry.name)
        for name in sorted(names):
            if len(name) > 255 or any(ord(char) < 32 for char in name):
                raise ValueError("产物文件名不合法")
            relative = prefix + name
            if len(relative) > 1024:
                raise ValueError("产物路径过长")
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                child = os.open(name, flags | os.O_DIRECTORY, dir_fd=directory_fd)
                try:
                    visit(child, relative + "/")
                finally:
                    os.close(child)
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError("产物包含符号链接、硬链接或特殊文件")
            is_manifest = relative == "manifest.json"
            limit = MAX_MANIFEST_BYTES if is_manifest else MAX_FILE_BYTES
            if info.st_size > limit:
                raise ValueError("单个产物超过大小限制")
            if not is_manifest and (len(artifacts) >= MAX_FILES or total + info.st_size > MAX_TOTAL_BYTES):
                raise ValueError("产物数量或总大小超过限制")
            descriptor = os.open(name, flags, dir_fd=directory_fd)
            try:
                before = os.fstat(descriptor)
                if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit:
                    raise ValueError("产物在读取前被替换")
                pieces = []
                remaining = limit + 1
                while remaining:
                    chunk = os.read(descriptor, min(65536, remaining))
                    if not chunk:
                        break
                    pieces.append(chunk)
                    remaining -= len(chunk)
                content = b"".join(pieces)
                after = os.fstat(descriptor)
                current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                # 对比打开文件与当前路径的身份，发现读取过程中替换或修改就拒绝。
                identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_nlink)
                if (len(content) > limit or len(content) != before.st_size
                        or identity(before) != identity(after) or identity(after) != identity(current)):
                    raise ValueError("产物在读取过程中发生变化")
            finally:
                os.close(descriptor)
            if is_manifest:
                # manifest 是执行状态和日志，不计入业务产物数量，但有单独大小上限。
                manifest = json.loads(content)
                if not isinstance(manifest, dict):
                    raise ValueError("产物清单必须为对象")
                for field in ("stdout", "stderr"):
                    value = manifest.get(field, "")
                    if not isinstance(value, str) or len(value.encode()) > 64 * 1024:
                        raise ValueError("任务日志超过限制")
            else:
                # 摘要依据实际读取内容计算，不能沿用任务自行声明的摘要。
                total += len(content)
                artifacts.append({"path": relative, "size": len(content),
                                  "sha256": hashlib.sha256(content).hexdigest(),
                                  "data_base64": base64.b64encode(content).decode("ascii")})

    directory_fd = os.open(directory, flags | os.O_DIRECTORY)
    try:
        visit(directory_fd)
    finally:
        os.close(directory_fd)
    if require_manifest and manifest is None:
        raise ValueError("缺少任务结果清单")
    return {"schema_version": 1, "manifest": manifest, "artifacts": artifacts}


if __name__ == "__main__":
    try:
        print(json.dumps(read_artifacts(Path("/workspace/out")), ensure_ascii=False))
    except Exception as error:
        print(f"[导出失败] {type(error).__name__}: {error}", file=sys.stderr)
        raise SystemExit(1)
