"""完整验收后确认默认部署不依赖合成服务，仍可免认证执行任务。"""
import json
from pathlib import Path
import time
import uuid

import docker
from sandbox_model.client import connect
from sandbox_model.proto import sandbox_pb2 as pb

channel,stub=connect()
try:
    ready=stub.Ready(pb.Empty(),timeout=5)
    assert ready.ready
    if ready.mode=='independent':
        fixtures=docker.from_env().containers.list(filters={'label':'lazyx.sb.fixture=true'})
        assert not fixtures, '正常运行仍启动了测试源站、DNS 或镜像仓库'
        assert not Path('/run/sandbox_model/permit.key').exists()
        assert not Path('/run/sandbox_model/certs').exists()
    request=pb.TaskRequest(request_id='independent_'+uuid.uuid4().hex,kind='code',environment='python',code=b'print(2+3)')
    stub.Submit(request,timeout=10)
    reference=pb.JobRef(request_id=request.request_id)
    end=time.monotonic()+120
    while time.monotonic()<end:
        status=stub.Status(reference,timeout=5)
        if status.phase=='finished' and status.cleanup_done:break
        time.sleep(.2)
    else:raise AssertionError('独立任务未完成')
    result=stub.Result(reference,timeout=10)
    assert status.outcome=='success' and result.stdout.strip()=='5'
    assert stub.Acknowledge(reference,timeout=5).delivery_done
    print('[通过] '+ready.mode+' 模式免认证执行、返回 5、资源已清理')
    if ready.mode=='independent':
        request=pb.TaskRequest(request_id='public_'+uuid.uuid4().hex,kind='code',environment='python',
            code=b"import urllib.request\nwith urllib.request.urlopen('https://example.com/',timeout=10) as r:\n assert r.status==200 and b'Example Domain' in r.read(100000)\nprint('PUBLIC_HTTPS_OK')",
            network_domains=['example.com'])
        stub.Submit(request,timeout=10)
        reference=pb.JobRef(request_id=request.request_id)
        end=time.monotonic()+90
        while time.monotonic()<end:
            status=stub.Status(reference,timeout=5)
            if status.phase=='finished' and status.cleanup_done:break
            time.sleep(.2)
        else:raise AssertionError('真实公网任务未完成')
        result=stub.Result(reference,timeout=10)
        assert status.outcome=='success' and result.stdout.strip()=='PUBLIC_HTTPS_OK', status.error_code
        stub.Acknowledge(reference,timeout=5)
        print('[通过] 正常模式真实公网 HTTPS、系统证书验证及清理')
finally:
    channel.close()
