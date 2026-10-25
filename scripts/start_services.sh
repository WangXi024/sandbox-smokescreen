#!/bin/bash
# 启动监督进程；普通启动不启用合成测试设施。
set -euo pipefail
[[ $(id -u) == 0 ]]
[[ ${SANDBOX_DEPLOYMENT:-} == compose && -f /run/sandbox_model/compose-node ]]
cd /opt/sandbox_model
export PYTHONPATH=/opt/sandbox_model/src PYTHONDONTWRITEBYTECODE=1
# 复用仍存活的监督进程，避免重复启动两个任务管理器。
if ! .venv/bin/python - <<'PYTHON'
from pathlib import Path
from sandbox_model.watchdog import pid_alive
p=Path('/run/sandbox_model/supervisor.pid')
raise SystemExit(0 if p.exists() and pid_alive(int(p.read_text())) else 1)
PYTHON
then
    nohup .venv/bin/python -B -m sandbox_model.supervisor > >(.venv/bin/python -B -m sandbox_model.logs /run/sandbox_model/supervisor.log >/dev/null 2>&1) 2>&1 </dev/null &
fi
# 有界等待 gRPC 就绪；进程存在并不等于服务已经可以接单。
.venv/bin/python - <<'PYTHON'
import time
import grpc
from sandbox_model.client import connect
from sandbox_model.proto.sandbox_pb2 import Empty
channel,stub=connect()
try:
    end=time.monotonic()+120
    while time.monotonic()<end:
        try:
            if stub.Ready(Empty(),timeout=1).ready:
                print('[就绪] 独立服务与 OpenSandbox 已可调用（内网免认证）')
                break
        except grpc.RpcError:
            pass
        time.sleep(.5)
    else:raise SystemExit('[失败] 服务未就绪，诊断日志仅在 /run/sandbox_model')
finally:channel.close()
PYTHON
