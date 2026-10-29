# 每次 Agent 操作独立工作区（阶段二 B）

新增 `lazyx.workspace.v1.WorkspaceService`，与原 `SandboxService` 共用节点的 18443 端口，原一次性任务协议保持不变。工作区由调用方操作 ID 唯一标识，Open 返回同 ID；同 ID 同请求去重、不同请求体冲突，Close 幂等。未知 ID 的 Close 也建立关闭墓碑，迟到 Open 不会重新创建。永久状态只保存 ID、请求摘要、截止时间与清理状态；文件、代码与 stdout/stderr 均不写状态卷。

一个工作区持有一只固定登记镜像的 gVisor 容器，直到 Close 或硬 TTL（默认 600 秒、最多 1800 秒），与旧任务共用准入和并发槽。代码 UID/GID 为 1000；只读根文件系统、无网络许可、无凭据、受限 capabilities、no-new-privileges 与 PID/CPU/内存/禁用交换限制保持启用。工作区 64 MiB、其他可写目录分别受 tmpfs 限额约束。每个文件可读写最多 8 MiB，gRPC 消息上限 32 MiB；每工作区最多 64 条命令、总缓存输出 8 MiB、单通道最多 1 MiB，命令最长 120 秒。正常完成命令的后台子进程可跨文件操作存活，Close 销毁整个容器和所有进程。

文件接口直接执行真实 POSIX 文件调用，包含权限、链接、目录、重命名与非严格 realpath；FIFO/设备不作为普通文件读取。返回值由镜像内固定的 root 控制 helper 经专用 FD3 管道产生，不使用用户 stdout 或用户 manifest 推断元数据。helper 保留 root 实/保存 UID/GID，将有效 UID/GID 降为 1000（内核相应将 FSUID/FSGID 设为 1000）、清空 capabilities 并设置 non-dumpable；不依赖 gVisor 返回 ENOSYS 的 setfsuid/setfsgid，因此文件权限仍按 UID1000 执行。协议拒绝 /proc、/sys、/dev 以及链接别名，read/write/list 另要求内核 openat2 RESOLVE_NO_MAGICLINKS。命令自己的 /proc 使用不受此文件协议限制。控制 HTTP 接口仍受原 trustedControlPeer、runtime-init 与令牌中间件约束。

命令输出由固定 execd 分别回传 stdout/stderr，退出码只采用 execd 的进程生命周期状态。超时、取消、输出截断与退出码可用性分别暴露，不能由用户输出中的数字或 JSON 覆盖。文件修改在独立后台 Task 中完成并保存请求回执，RPC 响应丢失后可用同 ID 重放原回执。节点重启会清理旧环境，不恢复旧正文，也不会把未知结果宣称成功。

## 验证与当前范围

无网络模块回归：`docker run --rm --network none --memory 512m --memory-swap 512m --cpus 2 --entrypoint /opt/sandbox_model/.venv/bin/python personal-agent-sandbox-node:workspace-candidate tests/unit.py`。

固定上游源码构建时运行 `go test -p 2 ./pkg/web -run 'TestTrustedControlPeer|TestWorkspace' -count=1`。覆盖真实 8 MiB 文件、权限、符号链接与缺失路径、目录错误、FIFO 及时拒绝、根目录保护、FD3 的直接/链接别名自引用，以及 UID1000 跨进程的 proc FD 与 ptrace 拒绝。测试二进制 `/build/workspace.test` 可在相同 gVisor/权限/tmpfs 配置下再次验收。

本地检查点只表示实现与独立 Linux 测试已保存；真实 gVisor 控制边界、官方 PydanticAI WorkspaceBackendSuite 与应用端 Coder 链路必须独立验证，验收前不宣称阶段二 B 完成。不向 Git 远端推送。
