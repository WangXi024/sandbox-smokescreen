"""SB3 真实包源、gVisor 构建、缓存与故障验收；只使用合成任务数据。"""
import json
import subprocess
import time
from pathlib import Path
import uuid

import grpc
import docker
from acceptance import RUN, PROJECT, require, pb
from sandbox_model.environments import STATE, LOCKS
from sandbox_model.watchdog import atomic_json, read_private_json


def clear_environment_cache(test):
    jobs = json.loads(Path('/var/lib/sandbox_model/jobs.json').read_text())
    require(all(x['phase']=='finished' for x in jobs.values()),'SB3 验收需要没有在途任务')
    entries = read_private_json(STATE) if STATE.exists() else {}
    for entry in entries.values():
        if not entry['image_id']:
            (LOCKS/(entry['environment_id']+'.json')).unlink(missing_ok=True)
            continue
        try:
            image = test.docker.images.get(entry['image_id'])
        except docker.errors.ImageNotFound:
            continue
        require(image.labels.get('lazyx.environment')==entry['environment_id'],'缓存镜像身份不符')
        test.docker.images.remove(image.id,force=False,noprune=False)
        (LOCKS/(entry['environment_id']+'.json')).unlink(missing_ok=True)
    atomic_json(STATE,{})
    subprocess.run(['bash',str(PROJECT/'scripts/restart_services.sh')],check=True,timeout=150)


def run_sb3_checks(test):
    stub = test.stubs['alice']
    cache_result = {}

    def request(deps, *, node=False, code=None):
        req = test.request(environment='node' if node else 'python',code=code or b'import requests; print(requests.__version__)')
        req.dependencies.extend(deps)
        return req

    def result(req):
        test.wait(req,seconds=600)
        value = stub.Result(pb.JobRef(request_id=req.request_id),timeout=10)
        require(value.status.outcome=='success',value.status.error_code or '动态环境执行失败')
        require(value.status.environment_id and value.status.cleanup_done,'环境登记或清理未完成')
        stub.Acknowledge(pb.JobRef(request_id=req.request_id),timeout=5)
        return value

    def cold_python():
        marker = 'SYNTHETIC_SB3_PRIVATE_' + uuid.uuid4().hex
        req = request(['requests==2.32.3'],code=("import requests; print(requests.__version__); private='"+marker+"'\n").encode())
        test.submit(req);value=result(req)
        require(not value.status.environment_cache_hit,'冷启动没有实际构建')
        require('2.32.3' in value.stdout,'Python 包没有安装')
        cache_result.update(environment_id=value.status.environment_id,marker=marker)

    def warm_python():
        req=request(['requests==2.32.3']);test.submit(req);value=result(req)
        require(value.status.environment_cache_hit,'第二次没有命中缓存')
        require(value.status.environment_id==cache_result['environment_id'],'相同声明未复用环境')

    def lock_rebuild():
        entries=read_private_json(STATE)
        entry=next(x for x in entries.values() if x['environment_id']==cache_result['environment_id'])
        lock=read_private_json(LOCKS/(entry['environment_id']+'.json'))
        test.docker.images.remove(entry['image_id'],force=False,noprune=False)
        req=request(['requests==2.32.3']);test.submit(req);value=result(req)
        require(not value.status.environment_cache_hit,'镜像缺失未重建')
        require(value.status.environment_id==cache_result['environment_id'],'重建改变完整依赖锁')
        require(read_private_json(LOCKS/(entry['environment_id']+'.json'))==lock,'重建修改锁文件')

    def no_private_cache():
        entry=next(x for x in read_private_json(STATE).values() if x['environment_id']==cache_result['environment_id'])
        code="""import os,sys
from pathlib import Path
needle=sys.argv[1].encode()
assert not list(Path('/workspace').iterdir())
for root,dirs,files in os.walk('/opt/env',followlinks=False):
 for name in files:
  p=Path(root)/name
  if not p.is_symlink():assert needle not in p.read_bytes()
assert not Path('/run/docker.sock').exists()
"""
        subprocess.run(['docker','run','--rm','--runtime','runsc','--read-only','--network','none',
            '--memory','256m','--memory-swap','256m','--cap-drop','ALL','--security-opt','no-new-privileges:true',
            '--entrypoint','python',entry['image_id'],'-I','-c',code,cache_result['marker']],check=True,timeout=30)

    def demo(case):
        subprocess.run([str(PROJECT/'.venv/bin/python'),'-B','-m','sandbox_model.demo',case],check=True,timeout=600,stdout=subprocess.DEVNULL)

    def build_container(timeout=30):
        end=time.monotonic()+timeout
        while time.monotonic()<end:
            containers=test.docker.containers.list(filters={'label':'lazyx.build=true'})
            if containers:return containers[0]
            time.sleep(.05)
        raise AssertionError('没有观察到真实构建容器')

    def shared():
        a=request(['requests==2.32.3','six==1.17.0']);b=request(['six==1.17.0','requests==2.32.3'])
        test.submit(a);test.submit(b)
        seen=set()
        end=time.monotonic()+600
        while time.monotonic()<end:
            seen.update(c.id for c in test.docker.containers.list(filters={'label':'lazyx.build=true'})
                        if c.attrs['Config']['Image'].startswith('sha256:') and c.attrs['HostConfig']['Tmpfs'].get('/opt/env'))
            if all(stub.Status(pb.JobRef(request_id=r.request_id)).phase=='finished' for r in (a,b)):break
            time.sleep(.15)
        va,vb=result(a),result(b)
        require(len(seen)==1,'相同环境发生重复构建')
        require(va.status.environment_id==vb.status.environment_id,'共享环境不一致')

    def cancel_shared():
        a=request(['requests==2.32.3','six==1.16.0']);b=request(['six==1.16.0','requests==2.32.3'])
        test.submit(a);test.submit(b);build_container()
        stub.Cancel(pb.JobRef(request_id=a.request_id),timeout=30)
        require(test.wait(a).outcome=='cancelled','第一个等待者取消失败')
        result(b)

    def cancel_build():
        req=request(['requests==2.32.3','idna==3.7']);test.submit(req)
        container=build_container();ident=container.labels['lazyx.job']
        stub.Cancel(pb.JobRef(request_id=req.request_id),timeout=30)
        status=test.wait(req,seconds=60)
        require(status.outcome=='cancelled','构建取消失败')
        test.no_resources([ident,req.request_id])

    def failed(deps):
        before=set(read_private_json(STATE))
        req=request(deps);test.submit(req);status=test.wait(req,seconds=600)
        require(status.outcome=='failed' and status.error_code.startswith(('DEPENDENCY_','ENVIRONMENT_')),'失败没有明确结果')
        require(set(read_private_json(STATE))==before,'失败发布了半成品')
        test.no_resources([req.request_id])

    def invalid_decl():
        for deps in [['requests>=2'],['--extra-index-url=https://example.com'],['requests==2.32.3','requests==2.31.0']]:
            req=request(deps)
            try:stub.Submit(req,timeout=5)
            except grpc.RpcError as error:require(error.code()==grpc.StatusCode.INVALID_ARGUMENT,'声明拒绝类型不符')
            else:raise AssertionError('接受了不支持的依赖声明')

    def dependency_conflict():
        req=request(['requests==2.32.3']);test.submit(req);result(req)
        req.dependencies.append('six==1.17.0')
        test.denied(lambda:stub.Submit(req,timeout=10),{grpc.StatusCode.ALREADY_EXISTS})

    def build_isolation():
        req=request(['requests==2.32.3','idna==3.8']);test.submit(req)
        container=build_container();container.reload();host=container.attrs['HostConfig']
        require(host['Runtime']=='runsc' and host['ReadonlyRootfs'] and not host['Privileged'] and not host.get('Binds'),'构建隔离配置错误')
        code="""import os,socket,urllib.request,json
from pathlib import Path
assert os.getuid()==1000
assert not Path('/run/docker.sock').exists()
assert not Path('/workspace/inputs').exists()
assert not set(os.environ) & {'API_KEY','OPENAI_API_KEY','EXECD_ACCESS_TOKEN','JUPYTER_TOKEN','OPENSANDBOX_EGRESS_TOKEN','PERMIT','LAZYX_GATEWAY','DOCKER_HOST'}
assert not Path('/run/sandbox_model/permit.key').exists()
try:Path('/opt/platform/guest.py').write_text('changed')
except OSError:pass
else:raise AssertionError('platform writable')
for endpoint in [('1.1.1.1',443),('169.254.169.254',80)]:
 s=socket.socket();s.settimeout(1)
 try:s.connect(endpoint)
 except OSError:pass
 else:raise AssertionError('direct network allowed')
 finally:s.close()
try:urllib.request.urlopen('https://example.com',timeout=3)
except Exception:pass
else:raise AssertionError('unapproved domain allowed')
print('BUILD_ISOLATION_OK')
"""
        try:
            output=container.exec_run(['python','-I','-c',code],user='1000:1000')
            require(output.exit_code==0 and b'BUILD_ISOLATION_OK' in output.output,'构建隔离探针失败')
        finally:
            stub.Cancel(pb.JobRef(request_id=req.request_id),timeout=30);test.wait(req)

    def interrupted_build():
        before=set(read_private_json(STATE))
        req=request(['requests==2.32.3','idna==3.4']);test.submit(req)
        container=build_container();ident=container.labels['lazyx.job'];container.kill()
        status=test.wait(req,seconds=60)
        require(status.outcome=='failed','安装进程异常没有失败')
        require(set(read_private_json(STATE))==before,'安装中断后登记了镜像')
        test.no_resources([ident,req.request_id])

    def unsafe_export():
        before=set(read_private_json(STATE))
        req=request(['requests==2.32.3','idna==3.6']);test.submit(req)
        container=build_container()
        created=container.exec_run(['ln','-s','/etc/passwd','/opt/env/escape'],user='1000:1000')
        require(created.exit_code==0,'未建立真实不安全导出样本')
        status=test.wait(req,seconds=300)
        require(status.outcome=='failed','不安全链接进入镜像')
        require(set(read_private_json(STATE))==before,'不安全导出登记了镜像')

    def download_fault():
        before=set(read_private_json(STATE))
        req=request(['requests==2.32.3','idna==3.5']);test.submit(req)
        container=build_container();ident=container.labels['lazyx.job']
        proxies=[c for c in test.docker.containers.list(filters={'label':f'lazyx.job={ident}'}) if c.name.startswith('sb-smokescreen-')]
        require(len(proxies)==1,'未找到构建代理');proxies[0].stop(timeout=1)
        status=test.wait(req,seconds=90)
        require(status.outcome=='failed','下载代理故障时仍成功')
        require(set(read_private_json(STATE))==before,'下载失败污染缓存')
        test.no_resources([ident,req.request_id])

    def manager_lost():
        req=request(['requests==2.32.3','idna==3.3']);test.submit(req)
        container=build_container();ident=container.labels['lazyx.job']
        test.stop_process('service.pid',ident)
        subprocess.run(['bash',str(PROJECT/'scripts/restart_services.sh')],check=True,timeout=150)
        status=stub.Status(pb.JobRef(request_id=req.request_id),timeout=5)
        require(status.phase=='finished' and status.outcome!='success','失联后自动重做任务')
        test.no_resources([ident,req.request_id])

    def restart_cache():
        subprocess.run(['bash',str(PROJECT/'scripts/restart_services.sh')],check=True,timeout=150)
        warm_python()

    test.check('SB3 准备独立缓存验收',lambda:clear_environment_cache(test))
    test.check('SB3 Python 公共依赖冷构建并运行',cold_python)
    test.check('SB3 第二次复用相同环境',warm_python)
    test.check('SB3 镜像丢失按原依赖锁重建',lock_rebuild)
    test.check('SB3 共享镜像不含合成用户代码和输入',no_private_cache)
    test.check('SB3 Node 安装脚本、原生二进制、CJS 与 ESM',lambda:demo('deps-node'))
    test.check('SB3 Python 源码 C 扩展编译和执行',lambda:demo('deps-source'))
    test.check('SB3 同环境并发仅构建一次',shared)
    test.check('SB3 取消一个等待者不影响其他任务',cancel_shared)
    test.check('SB3 最后等待者取消后清理构建',cancel_build)
    test.check('SB3 版本不存在不登记半成品',lambda:failed(['requests==0.0.0']))
    test.check('SB3 间接依赖冲突明确失败',lambda:failed(['requests==2.32.3','urllib3==1.0']))
    test.check('SB3 拒绝任意来源、范围版本和重复冲突',invalid_decl)
    test.check('SB3 同编号变更依赖声明拒绝重做',dependency_conflict)
    test.check('SB3 构建权限、任务数据与网络隔离',build_isolation)
    test.check('SB3 安装进程中断不登记且回收',interrupted_build)
    test.check('SB3 不安全导出链接拒绝封装',unsafe_export)
    test.check('SB3 真实下载代理停止时失败并回收',download_fault)
    test.check('SB3 构建期间管理器失联由独立回收器清理',manager_lost)
    test.check('SB3 服务重启后缓存可复用',restart_cache)
    test.check('SB3 构建结束没有容器残留',lambda:require(not test.docker.containers.list(all=True,filters={'label':'lazyx.build=true'}),'构建容器残留'))
