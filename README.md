# 独立沙箱服务

Python 管理服务通过 OpenSandbox 执行任务，使用 Docker + gVisor 隔离，Smokescreen 与宿主规则限制出网。原 `SandboxService` 每次任务创建新环境，结束后销毁；`WorkspaceService` 让同一次 Agent 操作的多次命令与文件访问复用工作区，操作结束或 TTL 到期销毁。代码、输入、输出、临时文件及脚本日志只在执行节点内存中处理；公共软件镜像和不含正文的状态记录可以保存在磁盘。

接口为内网免认证 gRPC，Agent 作为调用方提交代码和数据，服务负责执行、回传结果和清理。模型调用、业务权限、带 API Key 的第三方调用和长期存储由 Agent 后端负责。正常启动不运行合成网站或模拟连接器，模拟模型与工具通道只在显式测试模式开放。

独立服务保留原 ARM64 Docker Desktop 验收记录，并于 2026-10-29 在 Windows Docker Desktop / WSL2 AMD64 完成 MyPersonalAgent 的官方 Coder + Temporal 实际接入、工作区与旧协议回归。工作区协议和本次证据见 [Agent 工作区与验收](docs/workspace-session.md)；目标服务器仍需在实际机器上分别验收。原测试证据见 [验证报告](docs/验证报告.md)，完整报告及产物位于 [外部产物目录](../sandbox_smokescreen_outputs/)。

工作区命令输出新增 `base64-v1` 内部传输协商，用于保留任意 stdout/stderr 原始字节；原 `SandboxService` 继续使用原文本通道。本轮 198 项 Python、5 项 Go 离线回归，以及真实节点原始字节通道、八项应用样例验证、官方工作区 38 项、旧协议四场景和学习材料五场景均已通过，节点镜像已提升到本机 `amd64` 标签。学习应用部署由主项目单独记录。协议、限额和本轮状态见 [工作区原始字节输出](docs/workspace-session.md#工作区原始字节输出)。

## 提供的能力

| 内容 | 当前范围 |
|---|---|
| 代码与脚本 | 固定 Python 3.12、Node.js 22 环境；执行生成代码和指定 Skill 脚本 |
| 网页 | 获准域名的公开 HTTPS 页面；使用 Chromium 读取和解析，不接收账号登录态 |
| 文件 | 按内容核对文件类型；TXT、CSV、JSON、PDF、DOCX、XLSX、有限 ZIP 解包；PNG/JPEG/WebP 规范化、PDF 按页转 PNG；损坏或超范围输入明确失败 |
| 渲染 | 在断网环境中把样例 HTML 渲染为中文长图或 PDF |
| 静态审核 | 断网运行样例规则，不执行待审核脚本；上架决定与正式规则由市场模块负责 |
| 测试请求通道 | 仅测试模式提供模拟模型/工具响应；正常使用由外部 Agent 后端调用 API，再把业务数据交给沙箱 |
| 生命周期 | 提交、状态、取消、结果、送达确认、中文阶段日志；独立回收器处理失联和孤立资源 |
| 环境 | 登记镜像缺失时按固定摘要拉取；Python/npm 公共依赖自动隔离安装、封装和缓存 |
| Agent 工作区 | 一次操作内共享真实 POSIX 文件、命令与后台进程；独立硬 TTL；幂等关闭及清理确认 |

以下任务输入、产物和保留期限制适用于原一次性任务；工作区采用独立的 [协议与限额](docs/workspace-session.md)，两种模式共用准入、并发槽与节点硬限额。

默认两任务并发，总在途任务最多六个。单任务代码与输入文件合计最多 1 MiB、输入文件最多 32 个；产物最多八个，单个 2 MiB、合计 4 MiB；stdout/stderr 各 64 KiB。结果留在内存中最多 180 秒，调用方校验后确认送达；总缓存与在途预留受限。节点限额见 [settings.json](deploy/settings.json)，任务只能缩小额度。结果正文清理后，状态与防重复提交记录默认保留 24 小时，最多 4096 条；达到上限返回 `HISTORY_FULL`，不提前淘汰尚在保留期的记录。超过保留期后原编号不再保证去重，调用方应为新任务生成新 UUID。清理未完成的记录不会被过期删除。

图片规范化支持单帧 PNG/JPEG/WebP，校正方向、保留透明度、移除输入元数据并输出 PNG；输入最多 1600 万像素、单边最多 16384 像素。输出最长边默认 2048，可设为 64–2048，不放大图片。PDF 默认提取文字，指定转图后最多输出 7 页，超过页数上限明确失败；加密 PDF、动图和 OCR 不在当前范围内。所有文件转换仍受上述产物额度限制。

依赖自动准备支持精确版本的 Python/npm 公共包；暂不接收私有包源、Git/URL 依赖、自定义 Dockerfile 或任意系统库，具体范围见 [自动环境准备与验收](docs/SB3人工验收.md)。

任务用户的进程/线程限制为 `RLIMIT_NPROC=128`，容器的宿主 PID 限制为 512，给可信控制与清理程序留出容量。任务临时目录 `/tmp` 与可信控制临时目录分开；填满任务目录仍可清理和导出。网页及子资源下载合计最多 4 MiB，含密码登录表单的页面明确停止。

## 启动和停止

已验收的平台是 Apple Silicon Mac 的 Docker Desktop。2026-10-29 在 Windows Docker Desktop / WSL2 AMD64 上完成了节点启动、Python/Node 标准库、重复提交、取消、产物校验保存与接收确认的基础离线验收；浏览器联网、文件处理和动态依赖的 Windows 完整验收仍需分别执行。构建支持 Linux AMD64 与 ARM64，两种架构均使用固定版本 gVisor 及独立的官方 SHA512 校验。架构支持不等于部署验收，ARM64 Linux Docker Engine 与阿里云目标服务器需在实际机器上分别验收。运行节点内部固定使用 Docker 29.1.3、gVisor `release-20261005.0` 和 Smokescreen。 功能镜像使用 [Debian 官方快照](https://snapshot.debian.org/) `20261013T000000Z`，保留 Chromium `155.0.8059.39-1~deb13u1`；APT 保持 Debian archive-keyring 签名及包哈希验证，仅对固定快照关闭元数据有效期检查。Mac 使用 Docker Desktop 提供的 Linux 环境，无需另建 Lima 实例。

先启动 Docker Desktop，确认 `docker compose version` 可用。可信镜像准备需要代理时，可在本项目的 Compose override 中设置 `SANDBOX_BUILD_PROXY`；它只用于节点内部 Docker 拉取与预构建，不写入任务环境，任务出网仍受 Smokescreen 控制。节点需要 4 核、6 GiB 内存，请为 Docker Desktop 留足资源。服务本身通过 Compose 部署；运行本机调用示例需要 Python 3.10 或更高版本，本机已使用 Python 3.12 验收。

```bash
cd /Users/wx/LazyX/sandbox_smokescreen
docker compose up --build -d --wait --wait-timeout 1800
docker compose ps
```

首次启动会下载依赖并构建节点和任务镜像，需等待数分钟；`healthy` 表示服务就绪。后续直接用 `docker compose up -d` 启动，修改源码后使用上面的构建命令。Mac 运行任务及验收时保持唤醒，避免合盖；睡眠会暂停 Docker Desktop，可能触发超时与失联清理。

下面的命令应逐项执行。若在 zsh 粘贴带 `#` 的注释行，先执行 `setopt INTERACTIVE_COMMENTS`；只对当前终端会话生效。

Compose 中只有一个可信运行节点 `sandbox`，内部运行独立 Docker、gVisor、OpenSandbox、Python 管理服务和每任务 Smokescreen。节点需要 `privileged`，任务沙箱仍为非特权 gVisor，不挂载外层 Docker socket。它与独立虚拟机的隔离边界不同；不要把这个运行节点交给任务代码直接操作。

节点通过 cgroup 禁止节点及子进程使用 swap；任务文件与日志在有界 tmpfs。启动时核验必要条件，不满足会失败，不降级为普通 Docker。免认证 gRPC 默认发布到 `127.0.0.1:18443`。其他内网机器调用时，可用 `SANDBOX_BIND_IP='<服务器内网IP>' docker compose up -d` 绑定指定内网地址，替换占位符后执行；后续 Compose 操作保持相同的绑定设置。有端口访问权限的调用方都能提交、查询和取消任务。内部 Docker API 不发布端口。

```bash
# 查看首次环境准备进度、管理服务日志
docker compose exec sandbox tail -n 80 /run/sandbox_model/setup.log
docker compose exec sandbox tail -n 80 /run/sandbox_model/service.log
```

停止服务并保留公共镜像缓存和任务状态元数据：

```bash
docker compose down
```

仅在需要完全清理本项目时执行下列命令；会同时删除专用数据卷中的公共镜像缓存与状态元数据：

```bash
docker compose down -v
```

任务输入、输出不会跨节点重建保留。管理、OpenSandbox、回收器、监督进程、Docker 和启动日志都在 `/run`，各最多两份、合计 2 MiB，自动轮转。外部产物目录不随 `down -v` 删除。

## 外部调用快速开始

服务就绪后，在项目目录安装调用方的最小依赖并运行一次计算：

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r examples/requirements.txt
.venv/bin/python examples/call.py python
```

命令应返回 `success`、清理完成和已确认接收；打印目录中的 `report.json` 包含计算结果 `5`。产物保存在 `../sandbox_smokescreen_outputs/external/<用例-随机编号>/artifacts/`，报告位于同级 `report.json`。

[examples/call.py](examples/call.py) 直接连接 `localhost:18443`，不调用 Docker 命令、不导入管理服务。外部 Agent 可参考它实现 `Ready → Submit → Status → Result → Acknowledge`，用户停止时调用 `Cancel`。跨机器调用时，在用例名称前加 `--address '<服务内网IP>:18443'`，并先按部署说明配置服务的绑定地址。

调用方只需 gRPC 依赖及 [协议文件](src/sandbox_model/proto/sandbox.proto)；示例会在临时目录生成协议代码，不写入源码目录。现有 [client.py](src/sandbox_model/client.py) 是服务包内的简单封装，使用前需生成对应协议模块；首次外部接入可直接参考 `examples/call.py`。

常用调用与预期结果：

| 命令 | 应观察到的结果 |
|---|---|
| `.venv/bin/python examples/call.py parse tests/fixtures/photo.jpg --max-long-edge 256` | `normalized.png` 为 128×256，方向正确，EXIF 已移除 |
| `.venv/bin/python examples/call.py parse tests/fixtures/two-pages.pdf --pdf-images --max-long-edge 512` | 两张 480×240 PNG，分别为红色和蓝色 |
| `.venv/bin/python examples/call.py parse tests/fixtures/fake.pdf` | 预期失败：扩展名为 PDF，实际内容为 PNG；具体原因在报告中 |
| `.venv/bin/python examples/call.py staged` | 两个新任务通过显式输入衔接，最终结果 106.0 |
| `.venv/bin/python examples/call.py cancel` | 返回 `cancelled`，资源清理完成 |

分段示例的第一段返回调用需求和中间数据；调用方检查请求后提供合成税率 0.06，再提交第二段。示例不调用真实 API，也不使用真实 Key。接入产品时，由 Agent 后端在两段之间调用 API；脚本需主动保存中间结果，不支持任意进程暂停恢复。文件处理参数与完整步骤见 [文件处理与外部调用验收](docs/文件处理与外部调用验收.md)。

## 人工与自动验收

`scripts/demo.py` 是部署环境的验收辅助程序，通过 `docker compose exec` 在节点内运行 gRPC 测试调用方，再取回产物，因此需要本机有 Docker 访问权限。实际 Agent 接入使用上面的直接 gRPC 调用方式。

以下 `web` 和 `gateway` 样例需要测试模式，其他样例可在正常模式运行。逐项执行，不要在有其他任务运行时切换模式。

| 命令 | 应观察到的结果 |
|---|---|
| `python3 scripts/demo.py python` | 返回计算值 5，任务资源已清理 |
| `python3 scripts/demo.py node` | Node 脚本运行并返回产物 |
| `python3 scripts/demo.py skill` | 上传样例技能脚本，CSV 汇总结果正确 |
| `python3 scripts/demo.py web` | 获取合成公开网页的标题和正文 |
| `python3 scripts/demo.py parse` | CSV 文件解析结果正确 |
| `python3 scripts/demo.py png` | 生成可打开的中文长图 |
| `python3 scripts/demo.py pdf` | 生成可打开、可提取中文文字的 PDF |
| `python3 scripts/demo.py audit` | 正常包通过样例规则，问题包被发现；待审脚本没有执行 |
| `python3 scripts/demo.py gateway` | 模型与工具模拟请求返回各自结果，返回值没有凭据 |
| `python3 scripts/demo.py cancel` | 运行中的任务取消，执行与清理状态正确 |
| `python3 scripts/demo.py deps-python` | 自动安装 requests，返回版本；再次运行命中缓存 |
| `python3 scripts/demo.py deps-node` | npm 安装脚本、esbuild 二进制、CJS 与 ESM 均可用 |
| `python3 scripts/demo.py deps-source` | netifaces 源码 C 扩展编译后可运行 |

执行 `web`、`gateway` 前，用 `SANDBOX_TEST_MODE=1 docker compose up -d --wait --wait-timeout 1800` 启用合成网站与模拟连接器。测试结束执行 `SANDBOX_TEST_MODE=0 docker compose up -d --wait --wait-timeout 1800` 恢复正常模式。正常模式下的公开网页访问不依赖这些合成设施。

合成产物取回本机相邻的 `../sandbox_smokescreen_outputs/manual/<case>/`；这是调用方保存最终产物，执行节点内仍只使用 `/run`。

依赖安装和缓存见 [自动环境准备与验收](docs/SB3人工验收.md)，清理与故障恢复见 [运行维护验收](docs/运行维护验收.md)，计量和就绪状态见 [资源计量与指标验收](docs/资源计量与指标验收.md)。专项自动验收分别使用 `python3 scripts/run.py --operations`、`--observability` 或 `--files`；每次只选一个选项，均会运行模块测试并重建、切换服务。

完整自动验收会清理本项目动态公共镜像缓存、运行故障测试，期间服务不可供其他调用方使用，结束后恢复服务：

```bash
SANDBOX_TEST_MODE=0 python3 scripts/run.py
```

入口自动启用测试模式，执行 Compose 构建和启动、模块测试、真实链路验收及报告取回，最后恢复调用前的 `SANDBOX_TEST_MODE` 设置。上面的命令显式指定 0，恢复成功后为正常模式；专项验收也可加同样的前缀。报告保存在 `../sandbox_smokescreen_outputs/compose-<时间>/`，检查 `run.json` 中的 `passed` 和 `restored` 均为 `true`。报告失败或缺失不能当作通过。`python3 scripts/run.py --cleanup` 和 `python3 scripts/cleanup.py` 等同于本项目的 `docker compose down -v --remove-orphans`，会删除专用数据卷。

## 调用接口与模块职责

原一次性任务以 [sandbox.proto](src/sandbox_model/proto/sandbox.proto) 为接口契约。持久工作区使用独立的 [workspace.proto](src/sandbox_model/proto/workspace.proto)，提供 `Open/Status/Close/Filesystem/StartCommand/PollCommand/CancelCommand`；两个服务共用 18443 端口。服务端与调用方使用相同版本的对应协议。

Agent 在沙箱外解释 Skill 和决定步骤，沙箱只执行指定脚本；业务 API Key 留在 Agent 后端。脚本执行中需要 API 数据时，先返回请求说明和中间产物，调用方检查并取得数据后提交一个新任务继续。本版本不提供真实密钥代调用或进程暂停恢复。

| 接口 | 用途 |
|---|---|
| `Submit` | 直接提交任务；同编号同内容返回原任务，同编号不同内容拒绝 |
| `Status` | 查询执行阶段、结果、资源清理和送达状态 |
| `Cancel` | 幂等取消，覆盖排队和执行阶段 |
| `Result` | 获取有限的日志、产物和需批准的提议 |
| `Acknowledge` | 调用方确认已接收并校验结果 |
| `Ready` | 查询服务就绪原因、是否还能接单和登记环境 |
| `Metrics` | 查询任务数量、结果缓存、依赖构建和环境缓存的基础指标 |

`TaskRequest.dependencies` 声明依赖，例如 Python 的 `requests==2.32.3` 或 Node 的 `esbuild@0.25.0`；必须精确指定版本，依赖声明也参与重复提交的内容校验。`JobStatus.environment_id` 返回锁定环境编号，`environment_cache_hit` 表示是否复用。调用方给出获准输入、域名和限额。服务准备环境、执行限制、回传结果和回收资源；产品的业务批准、计费、模型选择、第三方连接器及长期存储由外部模块负责。

每个新任务使用新编号，同一请求重试时沿用原编号和原内容。`Status` 的执行结果、`cleanup_done` 和 `delivery_done` 分别表示执行、资源清理和接收确认；获取产物后先校验 SHA-256、保存，再调用 `Acknowledge`。连接断开不代表任务已停止，应按原编号查询状态或取消，避免直接换编号重复执行。

`JobStatus` 返回执行容器的真实 `cpu_usage_usec` 和 `peak_memory_bytes`，包括 gVisor 与执行组件开销，不含依赖构建和代理。必须同时查看对应的 `*_available`；`resource_usage_final: false` 表示运行中或没有取得完整的销毁前快照。计量数字随任务元数据保留，任务内容仍只在内存中。

运行 `python3 scripts/status.py` 查看基础指标，增加 `--job <任务编号>` 查看单个任务。`Ready.ready` 与 `Ready.accepting_tasks` 分别表示服务健康和此刻是否能接收新任务，队列满不会导致健康检查失败。详见 [资源计量与指标验收](docs/资源计量与指标验收.md)。

仅在测试模式，模型请求与工具提议可通过有限 HTTP 模拟通道发送。通道依据实际任务网络来源确定任务，不信任脚本自报的编号；需批准时回传提议并销毁沙箱，真实动作由外部产品执行。审核、网页、解析和渲染任务禁止调用该通道。它不是已接入真实 API 的连接器，正常模式使用前述分段执行方式。

## 目录与验证边界

代码根目录只保留源码、部署文件、脚本、测试、文档和配置。运行报告和人工产物放在代码目录外的 `../sandbox_smokescreen_outputs/`；执行节点内的 `/run` 使用内存文件系统。

| 目录或文件 | 作用 |
|---|---|
| `src/sandbox_model/` | gRPC 服务、依赖构建与缓存、网络、任务执行与导出、独立回收、客户端和 OpenSandbox 适配 |
| `src/egress/` | Smokescreen 的 Go 入口、TLS 握手检查与对应测试；管理服务仍为 Python |
| `deploy/` | Dockerfile、execd 控制来源补丁和启动入口 |
| `scripts/` | Compose 环境准备、人工调用、验收和产物取回 |
| `tests/` | 模块测试与真实验收；`fixtures/` 为合成输入，`support/` 为测试 DNS 和源站 |
| `examples/` | 外部 gRPC 调用方及最小依赖；支持文件处理、取消和分段执行示例 |
| `docs/` | [验证报告](docs/验证报告.md)及验证边界 |
| `requirements.txt` | Python 依赖版本 |
| `compose.yaml` | 专用运行节点、资源限制、接口端口和数据卷 |
| `../sandbox_smokescreen_outputs/` | `compose-<时间>/` 保存自动验收报告，`manual/` 保存部署验收产物，`external/` 保存独立调用结果 |

当前验收结论仅覆盖本机 ARM64 Docker Desktop。真实产品接入及阿里云目标机型需另行验收；业务权限、连接器和计费由产品侧负责。

合成 DNS、私网源站例外及限定证书 SPKI 只用于显式测试模式。正常公网访问保持源站 TLS，代理不解密业务内容；域名限制无法代替业务授权。需要真实 `API_KEY` 的 SDK 放在 Agent 后端调用，沙箱只接收业务数据。

镜像与关键组件版本固定，实际版本和摘要记录在验收证据中。execd 保留控制来源补丁；Smokescreen 使用扩展接口，不修改上游源码。本项目不自动更新为 `latest`，升级需要重新验证。

## 出网代理

此副本使用 [Smokescreen（MIT）](https://github.com/stripe/smokescreen/blob/7d0ddfa7589936fc0117b89cddb7e3a4ef72fba8/LICENSE.txt)，固定提交 `7d0ddfa7589936fc0117b89cddb7e3a4ef72fba8`。Go 依赖固定在 `src/egress/go.mod` 和 `go.sum`；代理镜像从 scratch 构建，包含静态程序、用于构建 DNS 验证的公共 CA 证书和 `/licenses` 第三方许可证，不安装 Squid。依赖各自保留原许可证，包括 BSD，并非全部都是 MIT。

每任务独立代理，策略由管理器写入只读 RAM 文件。Smokescreen 检查任务来源、精确域名及解析后的 IP；本地扩展在转发前检查有界 TLS ClientHello，要求 SNI 与 CONNECT 域名一致，拒绝无 SNI、ECH/ESNI、明文和损坏握手。保持源站 TLS，不生成代理 CA。每任务最多 32 条隧道，握手检查最多 5 秒、通过后的隧道最多 20 秒。

宿主规则继续阻止直连、私网、元数据及替代 DNS；撤权时先封网，再要求可信代理停止新连接、关闭现存上游连接并确认，最后销毁资源。这样不依赖 Docker Desktop 内核是否支持 `ss -K` 强制断连；未确认时保留待清理状态，不提前复用地址。Squid 外部 helper 的故障机制已移除，新版验收覆盖真实代理停止、挂起、策略损坏/缺少必填字段、DNS 不可达和连接过载。原版保留在相邻的 `sandbox_squid/`，本副本的 Compose 项目、数据卷和报告目录独立。

### 查看出网诊断日志

代理默认记录中文诊断：启动、来源/域名拒绝、DNS 失败或超时、连接失败或超时、TLS 检查失败、并发超限，以及隧道开启和关闭。仅记录时间、固定错误码和中文说明，不记录域名、URL、请求头、正文、凭据或原始错误文本。任务对应关系由代理容器的 `lazyx.job` 标签查询。

在项目目录中，趁任务还在执行时查看；第二条命令中的容器名替换为第一条查到的名称：

```bash
docker compose exec sandbox docker ps --filter name=sb-smokescreen- --format '{{.Names}}  任务={{.Label "lazyx.job"}}'
docker compose exec sandbox docker exec '<上面查到的代理容器名>' /egress --logs
```

日志保存在代理容器 `/tmp/egress-diagnostics/` 的 tmpfs 中，最多两份、合计 128 KiB，循环覆盖；任务销毁后不保留。Docker 日志驱动仍为 `none`，所以不能用 `docker logs` 查看。这里的“隧道开启”表示 TLS 检查通过，不表示网站业务请求成功。外部强制停止或挂起进程时，它无法自行记录停机原因。

更新源码后运行 `docker compose up --build -d`，节点会重建代理镜像；新任务使用新版。

## 运行配置与故障排查

- 普通任务默认累计上传 8 MiB、下载 32 MiB。`TaskRequest.network_upload_bytes` / `network_download_bytes` 为 0 时使用节点默认值，也可指定更小的上限。计量是隧道转发的 TLS 字节，包含握手；不解密业务内容。任一方向达到上限会关闭该任务所有连接、拒绝新连接，任务返回 `NETWORK_UPLOAD_LIMIT` 或 `NETWORK_DOWNLOAD_LIMIT`。网页原有 4 MiB 内容限制仍然保留，依赖构建仍使用独立额度。
- 正常模式默认复用已有固定 DoH 解析端点 `https://1.1.1.1/dns-query`，校验公共证书且不允许重定向，避免本机透明 DNS 返回 `198.18.x.x` 导致正常公网访问被拒。可在节点配置将 `dns_over_https` 设为 `false`，改用 `dns_server` 指定的公共解析器；任务本身不能改写解析器。
- `deploy/settings.json` 设置并发、排队、内存、时间、流量及历史保留上限。修改后执行 `docker compose restart sandbox` 生效；当前只允许在已验收的容量范围内调整。基础环境由部署脚本生成登记目录，正常模式缺失基础镜像时从节点保存的公共镜像归档恢复，不依赖测试镜像仓库。
- 管理服务、OpenSandbox、回收器退出或心跳停止时，停止接单，监督进程停止旧组件，再启动并对账清理。完成清理后恢复接单；无法确认清理完成时持续未就绪。旧任务不会自动重跑，执行结果不确定的任务保留 `unknown`，结果正文不会跨进程重启恢复。
- 外部接口通过 `grpc.insecure_channel` 或 `client.connect(address)` 免认证调用；执行节点到 OpenSandbox 的内部控制保护及第三方源站 HTTPS 校验保留。

| 现象 | 检查方式 |
|---|---|
| 首次启动等待很久或不健康 | 查看 `docker compose ps` 和前述 `setup.log`、`service.log`；核对下载网络、Docker Desktop 资源和机器是否睡眠 |
| 外部客户端连不上 | 确认服务为 `healthy`、地址端口正确；跨机器访问需配置 `SANDBOX_BIND_IP` |
| 服务健康但暂不接单 | 运行 `python3 scripts/status.py`，查看准入原因；队列满和历史记录满不等于服务进程故障 |
| 文件任务返回 `EXECUTION_FAILED` | 查看调用目录 `report.json` 的 `stderr`；类型不符、损坏、加密或转换超限会给出具体原因 |
| zsh 提示 `command not found: #` | 执行 `setopt INTERACTIVE_COMMENTS`，或只复制命令行，不复制注释 |
