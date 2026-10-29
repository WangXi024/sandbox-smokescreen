# 每次 Agent 操作独立工作区（阶段二 B）

新增 `lazyx.workspace.v1.WorkspaceService`，与原 `SandboxService` 共用节点的 18443 端口，原一次性任务协议保持不变。工作区由调用方操作 ID 唯一标识，Open 返回同 ID；关闭墓碑永久保留并受 4096 条上限约束，满额后拒绝新 Open，不提前复用旧 ID；同 ID 同请求去重、不同请求体冲突，Close 幂等。未知 ID 的 Close 也建立关闭墓碑，迟到 Open 不会重新创建。永久状态只保存 ID、请求摘要、截止时间与清理状态；文件、代码与 stdout/stderr 均不写状态卷。

一个工作区持有一只固定登记镜像的 gVisor 容器，直到 Close 或硬 TTL（默认 600 秒、最多 1800 秒），与旧任务共用准入和并发槽。代码 UID/GID 为 1000；只读根文件系统、无网络许可、无凭据、受限 capabilities、no-new-privileges 与 PID/CPU/内存/禁用交换限制保持启用。工作区 64 MiB、其他可写目录分别受 tmpfs 限额约束。每个文件可读写最多 8 MiB，gRPC 消息上限 32 MiB；每工作区最多 64 条命令、总缓存输出 8 MiB、单通道最多 1 MiB，命令最长 120 秒。正常完成命令的后台子进程可跨文件操作存活，Close 销毁整个容器和所有进程。正常清理立即执行；独立回收器保留最多 5 秒的清理宽限，且绝不延长原硬 TTL，宽限不随客户端重试重置。调用方必须等到 `cleanup_done=true` 才确认销毁；并发回收导致对象已不存在时仍核验容器、网络与规则实际归零。

文件接口直接执行真实 POSIX 文件调用，包含权限、链接、目录、重命名与非严格 realpath；FIFO/设备不作为普通文件读取。返回值由镜像内固定的 root 控制 helper 经专用 FD3 管道产生，不使用用户 stdout 或用户 manifest 推断元数据。helper 保留 root 实/保存 UID/GID，将有效 UID/GID 降为 1000（内核相应将 FSUID/FSGID 设为 1000）、清空所有 Go 线程的 P/E/I capabilities 并设置、读回 non-dumpable=0；不依赖 gVisor 返回 ENOSYS 的 setfsuid/setfsgid，因此文件权限仍按 UID1000 执行。协议拒绝 /proc、/sys、/dev 以及链接别名，read/write/list 另要求内核 openat2 RESOLVE_NO_MAGICLINKS。命令自己的 /proc 使用不受此文件协议限制。控制 HTTP 接口仍受原 trustedControlPeer、runtime-init 与令牌中间件约束。

命令输出由固定 execd 分别回传 stdout/stderr，退出码只采用 execd 的进程生命周期状态。字面 argv 命令通过固定的 `python -I` / `os.execvpe` trampoline 替换为目标进程；找不到程序和权限错误分别使该真实进程以 127/126 退出，再由 execd 读取内核退出码，客户端不猜测退出状态。超时、取消、输出截断与退出码可用性分别暴露，不能由用户输出中的数字或 JSON 覆盖。文件修改在独立后台 Task 中完成并保存请求回执，RPC 响应丢失后可用同 ID 重放原回执。节点重启会清理旧环境，不恢复旧正文，也不会把未知结果宣称成功。

## 工作区原始字节输出

固定 OpenSandbox 1.1.1 SDK 的输出回调是文本。`WorkspaceService` 为每个工作区复制公开的 `ConnectionConfig`，使用 `X-LazyX-Command-Output: base64-v1` 请求内部输出编码，并单独配置响应校验钩子；共享 Manager 连接的 headers、hooks 和 transport 所有权保持原样。execd 的 `/command` 控制器只在明确请求该编码时启用，未知编码在执行前返回 400；启用后在任何输出正文之前以同名 HTTP 响应头确认。工作区的成功命令响应必须为 200，且请求与响应编码标记均精确匹配；缺失、未知标记或其他成功状态会在读取输出正文前关闭响应并报错。空 stdout/stderr 也依靠此 HTTP 握手确认，不依靠用户 stdout 中的前缀、JSON 或替换字符判断。

execd 在 JSON 序列化之前按原始字节切分 stdout/stderr，每个原始帧最多 64 KiB，再分别编码为规范 Base64。节点严格检查 ASCII、Base64 格式、规范编码和解码后的帧大小，再将字节拼接进 gRPC 的 `bytes stdout/stderr`。每命令单通道最多 1 MiB、每工作区缓存合计最多 8 MiB 的原有限额仍按解码后的原始字节计算，不按 Base64 的文本长度计算。NUL、CR/LF、跨帧 UTF-8 和非法 UTF-8 字节均不会在此通道中先解码或替换；合法 U+FFFD 仍是合法文本。客户端若要求 UTF-8，应在收齐完整原始字节后严格校验，并保存原始回执与校验结果，不能把替换后的字符串当作原始输出。

本次只改变内部 stdout/stderr 传输；init、complete、error 和 command-status 事件的语义不变，退出码仍只来自 execd 的真实进程生命周期。原 `SandboxService` 不使用工作区的连接副本，也不发送此编码请求，保留原文本行为；gRPC 工作区方法与既有字段编号不变。`trustedControlPeer`、身份隔离、无网络许可、tmpfs 与关闭清理规则保持启用。

## 验证与当前范围

无网络模块回归：`docker run --rm --network none --memory 512m --memory-swap 512m --cpus 2 --entrypoint /opt/sandbox_model/.venv/bin/python personal-agent-sandbox-node:amd64 tests/unit.py`。

固定上游源码构建时运行 `CGO_ENABLED=0 go test -p 2 ./pkg/web -run 'TestTrustedControlPeer|TestWorkspace' -count=1`。覆盖真实 8 MiB 文件、权限、符号链接与缺失路径、目录错误、FIFO 及时拒绝、根目录保护、FD3 的直接/链接别名自引用，以及 UID1000 跨进程的 fd0/fd3/mem、ptrace 与信号权限拒绝、所有 Go 线程能力集清零。测试二进制 `/build/workspace.test` 可在相同 gVisor/权限/tmpfs 配置下再次验收。

## 2026-10-29 Windows AMD64 验收记录

本机 Docker Desktop / WSL2，节点 Docker 29.1.3、gVisor release-20261005.0；Compose 项目 `personal-agent-sandbox`，节点 3 GiB、2 CPU、禁用 swap，本机 Windows 配置并发 1 / 在途 2 / 单工作区最多 512 MiB。端口仍为 `127.0.0.1:18443`，无全局 Docker/DNS 修改。

| 验证 | 实际结果 |
|---|---|
| 隔离的完整 Python 模块回归 | 186/186 通过，无网络、512 MiB 临时容器 |
| 真实 gVisor 控制边界 | 7 组全通过，含原 trustedControlPeer 子项、8 MiB、root0600/owner000 权限、魔法链接自引用、跨 UID proc/mem/ptrace/信号、all-thread cap 清零与 dumpable 读回 |
| 官方 PydanticAI 2.57.0 WorkspaceBackendSuite | 38/38 通过，无 skip、无 teardown 错误；完整第二轮 108.05 秒 |
| POSIX 进程与文件互通 | 直接父进程 0.271 秒返回；持有 stdout 的后台子进程继续运行，可用后续写文件释放并读出产物；运行时可并发读 PID，原生 cancel 后进程不再存在；Close 确认 |
| 官方 Coder + 真实 Temporal 成功链路 | 官方 read_file/write_file、真实命令退出码 [7,0]、两文件导出、清理确认与回放均通过；5 次合成模型响应 |
| 同链路运行中取消 | 1 次合成模型响应，清理与回放通过，原学习提交/评估记录保持一致 |
| 原 SandboxService 四场景 | 成功、异常、超时、取消全部完成保存、接收确认与资源清理 |
| ARM64 兼容 | 新原生 helper 的 Linux ARM64 交叉编译通过；本轮运行验收限定 Windows AMD64，未替代 ARM64 实机验收 |

应用验收由 MyPersonalAgent 的 `backend/tests/test_workspace_conformance.py` 及隔离的真实 Temporal 测试执行；使用独立任务队列与临时测试数据库，不产生实际模型服务费用，不写生产学习记录。首轮真实 Suite 暴露的 missing-program 与 Close 并发回收问题已修复后完整重跑，未跳过失败用例。

最终候选镜像已仅在本地标记为 `personal-agent-sandbox-node:amd64`，与运行中候选镜像 ID 相同；此标记操作未重启节点。原 Windows Compose override 后续可继续使用原镜像名；旧节点回滚镜像仍保留为 `personal-agent-sandbox-node:pre-workspace-20261029`。节点最终 `healthy`、`Ready=true`，`inflight=0`、`cleanup_pending=0`，OOM/oom_kill 为 0；29 项生产源码/配置 SHA 与本机文件一致，配置按 Windows override 核对。

## 2026-10-29 原始字节修复验收状态

上面的阶段二 B 验收表是已保存的基线记录，不替代本轮输出编解码补丁的重新验收。本轮 Go 补丁 `deploy/execd-workspace-output.patch` 的 SHA-256 为 `e63a3b39a2f4b8286f6ad79b4e48b18fd71dccf5ef8d2d0ec4248f95c58e91f9`。

| 本轮验证 | 当前实际状态 |
|---|---|
| Python 离线回归 | 198/198 通过；包含真实固定 SDK 配合合成 HTTP 输出的编码、握手拒绝和旧连接兼容测试 |
| Go 输出控制器回归 | 5/5 通过；固定源码在无网络临时构建器中实际编译执行，使用合成 runner，未执行 guest 任务 |
| 真实节点原始字节通道 | 通过；stdout 131361 字节、stderr 269 字节逐字节一致，覆盖全部 256 种字节、非法 UTF-8、合法 U+FFFD、中文跨帧和长行；原生 exit 7，清理后在途与待清理均为 0 |
| 官方 WorkspaceBackendSuite 38 项 | 本轮 38/38 通过，107.82 秒，无 skip；并非沿用旧基线结果 |
| 旧 SandboxService 四场景 | 本轮成功、异常、超时、取消 4/4 通过；均 result_saved=true、ACK 与 cleanup 确认，无模型调用 |
| 学习材料五场景 | 真实节点加真实 Temporal 5/5 通过；text.pdf、table.docx 为 succeeded，scanned.pdf 为 no_text，损坏 PDF 与 DOCX 为 parse_failed；五场景均确认 result_saved、ACK、cleanup 与回放 |
| 应用样例验证八场景 | 8/8 通过；真实非法 UTF-8 保留 2 字节并判定 inconclusive/tests_verified=false，输出截断至 65536 字节同样不认定已验证；API 取消和目标撤销均确认清理；回放不重复 RPC，无真实模型调用，正式学习记录未修改 |

本轮已验收节点镜像为 `sha256:604bef8edc0c60cf744708852fd1b4bd713354e50182004369a904f41ee9b5f6`，32 项源码/配置 SHA 匹配；节点健康，限额 3 GiB、2 CPU、禁用 swap，OOM 为 0。验收结束时在途与待清理均为 0，无付费模型调用，未写入生产数据库。

该镜像已提升为本机 `personal-agent-sandbox-node:amd64`，只调整镜像标签，未重启节点。回退标签 `pre-binary-stdio-20261029` 保留旧镜像 `0fb8729b73fa`，原 `pre-workspace` 标签未改。本轮真实节点由根代理独占并串行完成验收。学习应用的 0009 数据库迁移和应用部署由主项目单独记录，本文记录节点镜像及隔离验收结果。

所有阶段检查点只保存到本地 Git，未推送远端。
