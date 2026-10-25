#!/usr/bin/env python3
"""通过已启动的 Compose 服务逐项复验，并把合成产物取回本机。"""
import argparse
import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import sys

sys.dont_write_bytecode = True

from compose_host import OUTPUTS, node_command, write_json

CASES = ("python", "node", "skill", "web", "parse", "png", "pdf", "audit", "gateway", "cancel", "deps-python", "deps-node", "deps-source")


def destination_path(base: Path, relative: str) -> Path:
    # 本机保存产物也要检查路径；不能把服务返回的名称直接拼成任意文件位置。
    value = PurePosixPath(relative)
    if (not relative or value.is_absolute() or ".." in value.parts or "\\" in relative
            or len(relative) > 1024 or any(ord(char) < 32 for char in relative)):
        raise ValueError("产物路径不合法")
    result = base / relative
    # 检查已存在的父目录，防止符号链接把产物导向输出目录外。
    for parent in (base, *result.parents):
        if parent.is_symlink():
            raise ValueError("本地产物目录包含符号链接")
        if parent == OUTPUTS:
            break
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", nargs="?", choices=CASES)
    parser.add_argument("--list", action="store_true", help="列出可逐项复验的项目")
    args = parser.parse_args()
    if args.list:
        print("\n".join(CASES))
        return 0
    if not args.case:
        parser.error("请选择一个人工复验项目")
    try:
        node_command("/opt/sandbox_model/.venv/bin/python", "-B", "/opt/sandbox_model/scripts/healthcheck.py", capture=True, timeout=10)
    except Exception:
        parser.error("服务尚未就绪；请先运行 docker compose up -d，等待节点准备完成")
    print(f"[执行] 通过 免认证 gRPC 人工复验：{args.case}", flush=True)
    # 节点内调用方通过 gRPC 执行样例；本机脚本负责取回并复核报告与产物。
    result = node_command("/opt/sandbox_model/.venv/bin/python", "-B", "-m",
                        "sandbox_model.demo", args.case, check=False, capture=True, timeout=720 if args.case.startswith("deps-") else 240)
    try:
        output = json.loads(result.stdout.splitlines()[-1])
        report_path = output["report_path"]
        prefix = f"/run/sandbox_model/manual/{args.case}/"
        # 远端读取只允许本用例的 RAM 报告目录，拒绝其他路径和过大的报告。
        if not report_path.startswith(prefix) or not report_path.endswith("/report.json") or ".." in PurePosixPath(report_path).parts:
            raise ValueError("远端报告路径不合法")
        data = node_command("cat", report_path, capture=True, timeout=15).stdout
        if len(data.encode()) > 65536:
            raise ValueError("远端报告过大")
        report = json.loads(data)
        for job in report.get('jobs',[]):
            if job.get('environment_id'):
                print(f"[环境] {job['environment_id']}；缓存命中：{'是' if job.get('environment_cache_hit') else '否（本次构建）'}",flush=True)
        base = OUTPUTS / "manual" / args.case
        destination_path(base, "report.json")
        base.mkdir(parents=True, exist_ok=True)
        total = 0
        if len(report.get("artifacts", [])) > 8:
            raise ValueError("远端产物过多")
        for artifact in report.get("artifacts", []):
            path = destination_path(base, artifact["path"])
            remote = str(PurePosixPath(report_path).parent / artifact["path"])
            if artifact["remote_path"] != remote or not 0 <= artifact["size"] <= 2 * 1024 * 1024:
                raise ValueError("远端产物路径或大小不合法")
            encoded = node_command("base64", "-w", "0", remote,
                                 capture=True, timeout=20).stdout
            if len(encoded) > 3 * 1024 * 1024:
                raise ValueError("远端产物编码超过限制")
            content = base64.b64decode(encoded, validate=True)
            total += len(content)
            # 先核对字节数和摘要再落盘，传输成功不等于产物完整。
            if (total > 4 * 1024 * 1024 or len(content) != artifact["size"]
                    or hashlib.sha256(content).hexdigest() != artifact["sha256"]):
                raise ValueError("取回产物摘要或大小不符合报告")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
            print(f"[产物] {path}", flush=True)
        write_json(base / "report.json", report)
        passed = result.returncode == 0 and report.get("passed") is True
        print(f"[完成] {'人工复验通过' if passed else '人工复验未通过'}；报告：{base / 'report.json'}", flush=True)
        return 0 if passed else 1
    except Exception as error:
        print(f"[失败] {type(error).__name__}: {error}", flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
