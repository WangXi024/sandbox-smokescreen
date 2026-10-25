#!/usr/bin/env python3
"""启动 Compose 并完整验收；取回报告后恢复服务，供人工继续测试。"""
import argparse
from datetime import datetime, timezone
import json
import os
import sys

sys.dont_write_bytecode = True
from compose_host import OUTPUTS, compose, node_command, write_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cleanup", action="store_true", help="停止本项目并删除专用数据卷")
    # 专项范围只能选一个，避免同一次运行混淆不同的验收报告。
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument("--operations", action="store_true", help="只验收免认证、流量、记录和故障恢复")
    scope.add_argument("--observability", action="store_true", help="只验收真实资源计量、基础指标和就绪状态")
    scope.add_argument("--files", action="store_true", help="只验收文件识别、图片规范化和 PDF 转图")
    args = parser.parse_args()
    if args.cleanup:
        return compose("down", "--volumes", "--remove-orphans").returncode
    directory = OUTPUTS / ("compose-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    summary = {"deployment": "compose", "passed": False, "restored": False}
    started = False
    original_mode=os.environ.get("SANDBOX_TEST_MODE", "0")
    # 合成源站和模拟连接器只在验收期间启用，结束时恢复调用前的模式。
    os.environ["SANDBOX_TEST_MODE"]="1"
    try:
        print("[启动] 构建并启动 Compose，等待 gVisor 运行节点就绪", flush=True)
        compose("up", "--build", "-d", "--wait", "--wait-timeout", "1800")
        started = True
        python = "/opt/sandbox_model/.venv/bin/python"
        print("[验证] 模块测试与真实沙箱验收", flush=True)
        node_command(python, "-B", "/opt/sandbox_model/tests/unit.py")
        # 模块测试检查实现边界；后续验收实际创建 gVisor 任务，二者分别记录。
        test = "file_acceptance.py" if args.files else "observability_acceptance.py" if args.observability else "operations_acceptance.py" if args.operations else "acceptance.py"
        node_command(python, "-B", "/opt/sandbox_model/tests/" + test)
        summary["passed"] = True
    except Exception as error:
        summary["error"] = type(error).__name__
    finally:
        if started:
            # 即使用例失败，也尽量取回已生成的证据，不能把缺失报告算成通过。
            for name in ("report.json", "unit-report.json", "versions.json"):
                try:
                    report = json.loads(node_command("cat", "/run/sandbox_model/" + name,
                                                    capture=True, timeout=15).stdout)
                    write_json(directory / name, report)
                    if name != "versions.json" and report.get("passed") is not True:
                        summary["passed"] = False
                except Exception:
                    summary["passed"] = False
                    summary["report_error"] = name
            try:
                os.environ["SANDBOX_TEST_MODE"]=original_mode
                # 恢复后另做计算和联网检查，恢复命令返回成功还不足以证明可调用。
                compose("up", "-d", "--wait", "--wait-timeout", "1800")
                node_command("/opt/sandbox_model/.venv/bin/python", "-B", "/opt/sandbox_model/tests/independent_acceptance.py")
                summary["restored"] = True
            except Exception:
                summary["passed"] = False
                summary["restore_error"] = True
        os.environ["SANDBOX_TEST_MODE"]=original_mode
        write_json(directory / "run.json", summary)
        print(f"[完成] {'验收通过' if summary['passed'] else '验收未通过'}；报告：{directory}", flush=True)
    return 0 if summary["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
