# 平台维护的安装工具模板；动态包安装发生在 runsc 容器中。
FROM node:22-bookworm-slim@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392 AS node
FROM sandbox-model-features:sb1
# 从固定 Node 镜像复制 npm，结合编译工具支持需要源码构建的依赖。
COPY --from=node /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/npm
RUN ln -s /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && apt-get update && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip install --no-cache-dir pip==25.3 setuptools==80.9.0 wheel==0.45.1 \
    && python -m pip download --no-deps --only-binary=:all: -d /opt/build-wheels setuptools==80.9.0 wheel==0.45.1 \
    && mkdir -p /opt/env
# 安装脚本只处理依赖准备与导出，构建结果由管理服务检查后缓存。
COPY src/sandbox_model/build_guest.py /opt/platform/build_guest.py
LABEL lazyx.builder="sb3-v1"
