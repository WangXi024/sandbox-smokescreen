"""四项完善的真实验收：免认证、流量上限、记录/日志边界、自动恢复。"""
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import time

import grpc
from acceptance import Acceptance, RUN, PROJECT, pb, require
from sandbox_model.watchdog import atomic_json


def poll(callback, seconds=90):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        try:
            if value:=callback():return value
        except grpc.RpcError as error:
            if error.code() not in (grpc.StatusCode.UNAVAILABLE,grpc.StatusCode.DEADLINE_EXCEEDED):raise
        time.sleep(.2)
    raise AssertionError('自动恢复或预期状态未在期限内出现')


def quotas(suite, direction):
    # 多次 HTTPS 连接累计；任务主动捕获错误也必须最终被判定为超限。
    code=f'''import ssl,urllib.request,time
context=ssl._create_unverified_context()
for i in range(20):
 try:
  request=urllib.request.Request('https://allowed.test/quota-{direction}?'+str(i), data={'b"x"*24576' if direction=='upload' else 'None'})
  with urllib.request.urlopen(request,context=context,timeout=5) as response:response.read()
 except Exception:pass
time.sleep(2)
print('caught network errors')
'''.encode()
    req=suite.request(code=code,network_domains=['allowed.test'],**{'network_'+direction+'_bytes':65536})
    suite.submit(req)
    result=suite.result(req,success=False)
    require(result.status.error_code=='NETWORK_'+direction.upper()+'_LIMIT','没有明确流量超限原因')
    suite.no_resources([req.request_id])
    # 超限任务不会关闭其他任务的额度。
    good=suite.run(code=b"import ssl,urllib.request\nwith urllib.request.urlopen('https://allowed.test/',context=ssl._create_unverified_context(),timeout=5) as r:print(r.status)",network_domains=['allowed.test'])
    require(good.stdout.strip()=='200','一个任务超限影响了后续任务')


def recovery(suite, component, sig):
    poll(lambda:suite.stubs['alice'].Ready(pb.Empty(),timeout=1).ready)
    req=suite.request(code=b'import time\ntime.sleep(110)',timeout_seconds=120)
    suite.submit(req)
    poll(lambda:suite.stubs['alice'].Status(pb.JobRef(request_id=req.request_id)).phase=='running')
    generation=(RUN/'service.pid').read_text()
    pid=int((RUN/(component+'.pid')).read_text())
    module={'service':b'sandbox_model.service','opensandbox':b'sandbox_model.opensandbox_process',
            'watchdog':b'sandbox_model.watchdog'}[component]
    require(module in Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0'),'故障目标进程不匹配')
    os.kill(pid,sig)
    def unavailable():
        try:return not suite.stubs['alice'].Ready(pb.Empty(),timeout=.5).ready
        except grpc.RpcError:return True
    poll(unavailable,20)
    rejected=suite.request()
    suite.denied(lambda:suite.stubs['bob'].Submit(rejected,timeout=1),
                 {grpc.StatusCode.UNAVAILABLE,grpc.StatusCode.DEADLINE_EXCEEDED})
    def recovered():
        return ((RUN/'service.pid').read_text()!=generation
                and suite.stubs['alice'].Ready(pb.Empty(),timeout=1).ready)
    poll(recovered)
    value=suite.wait(req)
    require(value.outcome in ('unknown','failed','cancelled') and value.cleanup_done,'故障任务结果或回收状态错误')
    repeated=suite.stubs['bob'].Submit(req,timeout=5)
    require(repeated.outcome==value.outcome and len(repeated.events)==len(value.events),'恢复后重新执行了旧任务')
    suite.no_resources([req.request_id,rejected.request_id])
    suite.run(code=b'print("recovered")')


def history(suite):
    old=suite.request();recent=suite.request()
    for req in (old,recent):suite.submit(req);suite.result(req)
    # 只改变本用例已完成的合成任务时间，触发真实启动清理，无需等待 24 小时。
    path=Path('/var/lib/sandbox_model/jobs.json')
    data=json.loads(path.read_text())
    data[old.request_id]['finished']=time.time()-8*86400
    atomic_json(path,data)
    subprocess.run(['bash',str(PROJECT/'scripts/restart_services.sh')],check=True,timeout=150)
    suite.denied(lambda:suite.stubs['alice'].Status(pb.JobRef(request_id=old.request_id)),{grpc.StatusCode.NOT_FOUND})
    before=suite.stubs['alice'].Status(pb.JobRef(request_id=recent.request_id))
    after=suite.stubs['bob'].Submit(recent)
    require(before.SerializeToString()==after.SerializeToString(),'未到期任务被重复执行')
    require(old.request_id not in json.loads(path.read_text()),'过期记录仍在磁盘中')


def overlapping_restart(suite):
    pid=int((RUN/'opensandbox.pid').read_text())
    os.kill(pid,signal.SIGKILL)
    subprocess.run(['bash',str(PROJECT/'scripts/restart_services.sh')],check=True,timeout=150)
    generation=(RUN/'service.pid').read_text()
    # 返回就绪后持续运行，不能被上一次恢复遗留的重启请求再次杀死。
    suite.run(code=b'import time\ntime.sleep(4)\nprint("stable")')
    require((RUN/'service.pid').read_text()==generation,'手动重启返回就绪后服务被再次重启')


def log_bounds():
    path=RUN/'operations-log.log'
    try:
        data=b'x'*(3*1024*1024)+b'last-operation-line'
        subprocess.run([str(PROJECT/'.venv/bin/python'),'-B','-m','sandbox_model.logs',str(path)],input=data,check=True)
        files=[path,path.with_suffix('.log.1')]
        require(all(p.stat().st_size<=1024*1024 for p in files),'单行日志突破大小上限')
        require(path.read_bytes().endswith(b'last-operation-line'),'轮转丢失最新日志')
    finally:
        path.unlink(missing_ok=True);path.with_suffix('.log.1').unlink(missing_ok=True)


def run_operations_checks(suite):
    suite.check('免认证任务执行与另一连接查询',lambda:suite.run())
    for direction in ('upload','download'):
        suite.check('普通脚本跨连接累计'+direction+'超限终止',lambda direction=direction:quotas(suite,direction))
    suite.check('管理日志超长单行和轮转总量有界',log_bounds)
    suite.check('过期任务记录清理且保留近期重复提交记录',lambda:history(suite))
    if suite.include_faults:
        suite.check('自动恢复期间请求手动重启，恢复后保持稳定',lambda:overlapping_restart(suite))
        for component in ('service','opensandbox','watchdog'):
            for sig in (signal.SIGKILL,signal.SIGSTOP):
                suite.check(component+' '+sig.name+' 后自动恢复且不重跑旧任务',
                            lambda component=component,sig=sig:recovery(suite,component,sig))


if __name__=='__main__':
    suite=Acceptance()
    try:
        run_operations_checks(suite)
        suite.completed=True
    finally:
        suite.save()
        for channel in suite.channels.values():channel.close()
    raise SystemExit(0 if all(item['passed'] for item in suite.checks) else 1)
