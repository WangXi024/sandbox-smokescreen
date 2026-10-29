#!/bin/bash
set -euo pipefail
cd /opt/sandbox_model
umask 077
ulimit -c 0
mkdir -p /run/sandbox_model /var/lib/sandbox_model
# 启动前确认管理临时目录位于内存、交换禁用且桥接防火墙生效。
[[ $(findmnt -n -o FSTYPE -T /run/sandbox_model) == tmpfs ]]
[[ $(cat /sys/fs/cgroup/memory.swap.max) == 0 ]]
[[ $(cat /proc/sys/net/bridge/bridge-nf-call-iptables) == 1 ]]

# 先让监督程序协调服务退出，再停止内部 Docker，避免任务继续运行。
shutdown() {
    trap - TERM INT EXIT
    printf '[停止] 正在停止服务和本节点 Docker\n'
    if [[ -f /run/sandbox_model/supervisor.pid ]]; then
        pid=$(cat /run/sandbox_model/supervisor.pid)
        if [[ -r /proc/$pid/cmdline ]] && tr '\0' ' ' </proc/"$pid"/cmdline | grep -Fq sandbox_model.supervisor; then
            kill -TERM "$pid" 2>/dev/null || true
            for attempt in $(seq 1 200); do
                kill -0 "$pid" 2>/dev/null || break
                sleep .1
            done
        fi
    fi
    if [[ -n ${docker_pid:-} ]]; then
        kill -TERM "$docker_pid" 2>/dev/null || true
        wait "$docker_pid" 2>/dev/null || true
    fi
}
trap 'shutdown; exit 0' TERM INT
trap shutdown EXIT
# 代理仅用于本节点 Docker 的公共镜像拉取，不设置服务或任务的 HTTP_PROXY。
docker_proxy_args=()
if [[ -n ${SANDBOX_BUILD_PROXY:-} ]]; then
    docker_proxy_args=(--http-proxy "$SANDBOX_BUILD_PROXY" --https-proxy "$SANDBOX_BUILD_PROXY")
fi
# 该 Docker 属于本节点；日志经过有界收集器写入内存目录。
dockerd "${docker_proxy_args[@]}" > >(.venv/bin/python -B -m sandbox_model.logs /run/sandbox_model/docker.log) 2>&1 &
docker_pid=$!
# 在准备镜像前等待内部 Docker 可用，同时检测其提前退出。
for attempt in $(seq 1 100); do
    if docker info >/dev/null 2>&1; then break; fi
    kill -0 "$docker_pid" || { printf '[失败] 节点 Docker 启动失败\n'; exit 1; }
    sleep .2
done
docker info >/dev/null
# 标记当前环境为专用 Compose 节点，供后续操作脚本核验作用范围。
touch /run/sandbox_model/compose-node
printf '[启动] 独立 Docker 已就绪，准备 gVisor 和服务镜像\n'
bash scripts/prepare_node.sh 2>&1 | .venv/bin/python -B -m sandbox_model.logs /run/sandbox_model/setup.log --echo
bash scripts/start_services.sh
# 服务组件由监督进程恢复；监督进程失效则重启整个专用节点。
while kill -0 "$docker_pid" 2>/dev/null; do
    if ! kill -0 "$(cat /run/sandbox_model/supervisor.pid)" 2>/dev/null; then exit 1; fi
    sleep 1 & wait $! || true
done
exit 1
