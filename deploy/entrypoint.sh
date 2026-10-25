#!/bin/sh
# 可信等待程序先启动；管理服务完成保护核查后才上传任务并发命令。
set -eu
# 缺少可信控制来源时立即退出，不允许执行组件以宽松配置启动。
: "${EXECD_TRUSTED_PEER:?missing trusted control peer}"
: "${EXECD_ENVS:=/run/execd.env}"
: "${EXECD_LOG_FILE:=/run/execd.log}"
export EXECD_ENVS EXECD_LOG_FILE
# 控制环境文件和日志默认仅所属用户可读写。
umask 077
# 任务 /tmp 满时，execd 仍须创建可信停止/导出命令的输出文件。
mkdir -p /run/execd-tmp
chmod 0711 /run/execd-tmp
TMPDIR=/run/execd-tmp
export TMPDIR
: > "$EXECD_ENVS"
# 原版bootstrap创建.env、启动官方execd；EXECD_ACCESS_TOKEN始终为空。
# 清除这些认证变量后交给上游脚本，控制来源保护另由可信 peer 检查落实。
unset EXECD_ACCESS_TOKEN JUPYTER_TOKEN OPENSANDBOX_EGRESS_TOKEN
exec /opt/opensandbox/upstream-bootstrap.sh "$@"
