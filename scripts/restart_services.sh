#!/bin/bash
# 由单一监督进程停止旧组件并重新对账，避免两个管理器同时接单。
set -euo pipefail
[[ $(id -u) == 0 && ${SANDBOX_DEPLOYMENT:-} == compose ]]
cd /opt/sandbox_model
# 写入重启请求并等待服务 PID 更换，实际停止和清理由监督程序执行。
.venv/bin/python - <<'PYTHON'
from pathlib import Path
import time
from sandbox_model.watchdog import pid_alive
root=Path('/run/sandbox_model')
path=root/'service.pid'
old=path.read_text() if path.exists() else ''
supervisor=root/'supervisor.pid'
if supervisor.exists() and pid_alive(int(supervisor.read_text())):
    (root/'restart-request').touch(mode=0o600)
    end=time.monotonic()+45
    while time.monotonic()<end:
        if path.exists() and path.read_text()!=old and not (root/'restart-request').exists():break
        time.sleep(.2)
    else:raise SystemExit('[失败] 服务重启未完成')
PYTHON
# 重启协调结束后继续等待服务就绪，必要时补启动监督进程。
bash scripts/start_services.sh
