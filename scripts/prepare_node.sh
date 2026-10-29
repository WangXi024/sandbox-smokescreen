#!/bin/bash
# 在 Compose 专用运行节点内准备镜像与合成服务，不修改外层 Docker。
set -euo pipefail
# 核对节点标记、Docker 地址和版本，避免在外层宿主误构建或清理资源。
[[ $(id -u) == 0 && ${SANDBOX_DEPLOYMENT:-} == compose && -f /run/sandbox_model/compose-node ]]
[[ ${DOCKER_HOST:-} == unix:///run/docker.sock ]]
[[ $(docker version --format '{{.Server.Version}}') == 29.1.3 ]]
cd /opt/sandbox_model
umask 077
mkdir -p /run/sandbox_model/origin
[[ $(findmnt -n -o FSTYPE -T /run/sandbox_model) == tmpfs ]]

# 可选代理只传给可信镜像构建的隐式 build args；任务环境仍由服务逐项构造。
build_proxy_args=()
if [[ -n ${SANDBOX_BUILD_PROXY:-} ]]; then
    for name in HTTP_PROXY HTTPS_PROXY http_proxy https_proxy; do
        build_proxy_args+=(--build-arg "$name=$SANDBOX_BUILD_PROXY")
    done
fi
printf '[镜像] 构建固定运行与功能镜像\n'
docker build "${build_proxy_args[@]}" -q -f deploy/Dockerfile.runtime -t sandbox-model-runtime:sb0 .
docker build "${build_proxy_args[@]}" -q -f deploy/Dockerfile.features -t sandbox-model-features:sb1 .
docker build "${build_proxy_args[@]}" -q -f deploy/Dockerfile.builder -t sandbox-model-builder:sb3 .
printf '[镜像] 构建固定 Smokescreen 与 TLS 检查入口\n'
docker build "${build_proxy_args[@]}" -q -f deploy/Dockerfile.smokescreen -t sandbox-smokescreen-egress:7d0ddfa-tls1 .

# 固定出口网络只在带本项目标签时复用，避免误占其他网络。
if docker network inspect sb-out >/dev/null 2>&1; then
    [[ $(docker network inspect --format '{{index .Labels "lazyx.sb.fixture"}}' sb-out) == true ]]
else
    docker network create --label lazyx.sb.fixture=true --subnet 172.27.250.0/24 --opt com.docker.network.bridge.name=sb-fixture-out sb-out >/dev/null
fi
# 合成 DNS、源站和仓库仅在显式测试模式启用。
if [[ ${SANDBOX_TEST_MODE:-0} == 1 ]]; then
    bash tests/support/prepare_fixtures.sh
else
    # 旧测试实例只按固定名称和本项目 fixture 标签移除。
    for name in sb-dns sb-origin sb-private-origin sb-registry; do
        if docker container inspect "$name" >/dev/null 2>&1; then
            [[ $(docker inspect --format '{{index .Config.Labels "lazyx.sb.fixture"}}' "$name") == true ]]
            docker rm -f "$name" >/dev/null
        fi
    done
fi
# 登记固定镜像与版本证据：正常模式使用镜像归档，测试模式使用合成仓库。
.venv/bin/python - <<'PY'
import importlib.metadata
import hashlib
import json
from pathlib import Path
import platform
import os
import subprocess
import urllib.request
image_id = subprocess.check_output(['docker','image','inspect','sandbox-model-features:sb1','--format','{{.Id}}'], text=True).strip()
if os.environ.get('SANDBOX_TEST_MODE') == '1':
    request = urllib.request.Request('http://127.0.0.1:5000/v2/sandbox-model/features/manifests/sb1', headers={'Accept':'application/vnd.docker.distribution.manifest.v2+json,application/vnd.oci.image.manifest.v1+json'})
    with urllib.request.urlopen(request, timeout=30) as response:
        image_digest = response.headers['Docker-Content-Digest']
    entry = {'image_ref':'localhost:5000/sandbox-model/features@'+image_digest, 'image_id':image_id}
else:
    archive=Path('/var/lib/sandbox_model/base-image.tar')
    marker=archive.with_suffix('.id')
    if not archive.exists() or not marker.exists() or marker.read_text()!=image_id:
        subprocess.run(['docker','save','-o',str(archive.with_suffix('.new')),image_id],check=True)
        archive.with_suffix('.new').replace(archive)
        marker.write_text(image_id)
    entry = {'image_archive':str(archive), 'image_id':image_id}
catalog = {environment:dict(entry) for environment in ('python','node','browser','files')}
Path('/run/sandbox_model/catalog.json').write_text(json.dumps(catalog, indent=2)+'\n')
Path('/opt/sandbox_model/catalog.json').write_text(json.dumps(catalog, indent=2)+'\n')
versions = {
    'deployment':'compose', 'kernel':platform.release(), 'architecture':platform.machine(),
    'node_swap_max':Path('/sys/fs/cgroup/memory.swap.max').read_text().strip(),
    'docker':subprocess.check_output(['docker','version','--format','{{.Server.Version}}'],text=True).strip(),
    'gvisor':subprocess.check_output(['runsc','--version'],text=True).strip(),
    'opensandbox':importlib.metadata.version('opensandbox'),
    'opensandbox_server':importlib.metadata.version('opensandbox-server'),
    'python_dependencies':subprocess.check_output(['/opt/sandbox_model/.venv/bin/pip','freeze'],text=True).splitlines(),
    'catalog':catalog,
    'images':{name:subprocess.check_output(['docker','image','inspect',name,'--format','{{.Id}}'],text=True).strip() for name in ('sandbox-model-runtime:sb0','sandbox-model-features:sb1','sandbox-model-builder:sb3','sandbox-smokescreen-egress:7d0ddfa-tls1')},
    'egress': subprocess.check_output(['docker','run','--rm','sandbox-smokescreen-egress:7d0ddfa-tls1','--version'],stderr=subprocess.STDOUT,text=True).strip(),
    'feature_versions':subprocess.check_output(['docker','run','--rm','--entrypoint','python','sandbox-model-features:sb1','-c','import importlib.metadata,json; print(json.dumps({k:importlib.metadata.version(k) for k in ["playwright","pypdf","python-docx","openpyxl","PyYAML","Pillow","pypdfium2"]}))'],text=True).strip(),
    'chromium':subprocess.check_output(['docker','run','--rm','--entrypoint','chromium','sandbox-model-features:sb1','--version'],text=True).strip(),
    'node':subprocess.check_output(['docker','run','--rm','--entrypoint','node','sandbox-model-features:sb1','--version'],text=True).strip(),
    'source_sha256':{name:hashlib.sha256(Path(name).read_bytes()).hexdigest() for name in ('src/sandbox_model/workspace_service.py','src/sandbox_model/proto/workspace.proto','src/execd_workspace/workspace_fs.go','deploy/execd-workspace-route.patch','src/sandbox_model/runtime_adapter.py','src/sandbox_model/architecture.py','deploy/execd-peer.patch','src/egress/main.go','src/egress/tls.go','src/egress/diagnostics.go','src/egress/revoke.go','src/egress/go.mod','src/egress/go.sum','src/sandbox_model/service.py','src/sandbox_model/guest.py','src/sandbox_model/network.py','src/sandbox_model/watchdog.py','src/sandbox_model/proto/sandbox.proto','src/sandbox_model/environments.py','src/sandbox_model/build_guest.py','deploy/Dockerfile.builder','deploy/Dockerfile.features','deploy/debian.snapshot.sources','src/egress/doh.go','src/egress/quota.go','src/sandbox_model/settings.py','src/sandbox_model/supervisor.py','src/sandbox_model/logs.py','deploy/settings.json')},
}
Path('/run/sandbox_model/versions.json').write_text(json.dumps(versions, indent=2)+'\n')
PY
printf '[完成] 节点运行环境准备完成；服务和验收由调用方启动\n'

