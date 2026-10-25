#!/bin/bash
# 仅完整验收显式启用，不参与正常运行。
set -euo pipefail
cd /opt/sandbox_model
printf '[验证] 准备节点内的合成 DNS、源站和镜像仓库\n'
PYTHON_IMAGE='python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1'
REGISTRY_IMAGE='registry:2.8.3@sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373'
docker pull -q "$PYTHON_IMAGE"
docker pull -q "$REGISTRY_IMAGE"
# 只重建本节点拥有的合成服务；镜像与登记仓库保留在专用卷中。
for name in sb-dns sb-origin sb-private-origin sb-registry; do
    if docker container inspect "$name" >/dev/null 2>&1; then
        [[ $(docker inspect --format '{{index .Config.Labels "lazyx.sb.fixture"}}' "$name") == true ]]
        docker rm -f "$name" >/dev/null
    fi
done
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=allowed.test -addext 'subjectAltName=DNS:allowed.test,DNS:second.test,DNS:blocked.test' -keyout /run/sandbox_model/origin/key.pem -out /run/sandbox_model/origin/cert.pem 2>/dev/null
chmod 600 /run/sandbox_model/origin/key.pem
chmod 644 /run/sandbox_model/origin/cert.pem
# SPKI 是公开证书公钥摘要；只给显式 test-mode 的合成源站验证使用。
openssl x509 -in /run/sandbox_model/origin/cert.pem -pubkey -noout | openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256 -binary | openssl base64 -A > /run/sandbox_model/test-spki.txt
docker run -d --name sb-dns --label lazyx.sb.fixture=true --network sb-out --ip 172.27.250.53 --read-only --cap-drop ALL --security-opt no-new-privileges:true --log-driver none --tmpfs /tmp:rw,nosuid,nodev,size=8m --memory 64m --pids-limit 32 --mount type=bind,src=/opt/sandbox_model/tests/support/dns_fixture.py,dst=/dns_fixture.py,readonly "$PYTHON_IMAGE" python /dns_fixture.py >/dev/null
for fixture in sb-origin:172.27.250.10:public-fixture sb-private-origin:172.27.250.11:private-fixture; do
    IFS=: read -r fixture_name fixture_ip fixture_kind <<< "$fixture"
    docker run -d --name "$fixture_name" --label lazyx.sb.fixture=true --network sb-out --ip "$fixture_ip" --read-only --cap-drop ALL --security-opt no-new-privileges:true --log-driver none --memory 64m --pids-limit 32 --env "ORIGIN_NAME=$fixture_kind" --env PYTHONDONTWRITEBYTECODE=1 --tmpfs /tmp:rw,nosuid,nodev,size=8m --shm-size=8m --mount type=bind,src=/run/sandbox_model/origin,dst=/fixtures,readonly --mount type=bind,src=/opt/sandbox_model/tests/support/origin.py,dst=/origin.py,readonly "$PYTHON_IMAGE" python /origin.py >/dev/null
done
mkdir -p /var/lib/sandbox_model/registry
docker run -d --name sb-registry --label lazyx.sb.fixture=true --publish 127.0.0.1:5000:5000 --read-only --cap-drop ALL --security-opt no-new-privileges:true --log-driver none --mount type=bind,src=/var/lib/sandbox_model/registry,dst=/var/lib/registry --memory 256m --pids-limit 64 "$REGISTRY_IMAGE" >/dev/null
for attempt in $(seq 1 60); do
    if curl -fsS http://127.0.0.1:5000/v2/ >/dev/null; then break; fi
    sleep 1
done
curl -fsS http://127.0.0.1:5000/v2/ >/dev/null
REMOTE_IMAGE=localhost:5000/sandbox-model/features:sb1
docker tag sandbox-model-features:sb1 "$REMOTE_IMAGE"
docker push -q "$REMOTE_IMAGE"
