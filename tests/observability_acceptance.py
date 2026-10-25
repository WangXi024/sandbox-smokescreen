"""真实 gVisor 计量、聚合指标与就绪/容量验收，仅使用合成任务。"""
from pathlib import Path
import subprocess
import time

from acceptance import Acceptance, PROJECT, pb, require
from operations_acceptance import poll, recovery


def metrics(suite):
    return suite.stubs['alice'].Metrics(pb.Empty(),timeout=5)


def status(suite, req):
    return suite.stubs['alice'].Status(pb.JobRef(request_id=req.request_id),timeout=5)


def measured(value, final=True):
    require(value.cpu_usage_available and value.cpu_usage_usec>0,'缺少真实 CPU 累计计数')
    require(value.peak_memory_available and value.peak_memory_bytes>0,'缺少内核内存峰值')
    require(value.resource_sample_unix_ms>0,'缺少采样时间')
    require(value.resource_usage_final==final,'最终采集标记不符')


def short_task(suite):
    req=suite.request(code=b'print(5)')
    suite.submit(req);result=suite.result(req)
    measured(result.status)
    require(result.stdout.strip()=='5')
    suite.no_resources([req.request_id])
    after=status(suite,req)
    require(after.cpu_usage_usec==result.status.cpu_usage_usec,'容器删除后计量发生变化')
    suite.runtime_evidence['resource_sample']={
        'request_id':req.request_id,'cpu_usage_usec':after.cpu_usage_usec,
        'peak_memory_bytes':after.peak_memory_bytes,'resource_usage_final':after.resource_usage_final}
    print(f'[计量] {req.request_id}：CPU {after.cpu_usage_usec/1e6:.3f} 秒，内存峰值 {after.peak_memory_bytes/1024/1024:.2f} MiB',flush=True)


def load_and_kernel(suite):
    code=b'''import subprocess,sys,time
subprocess.run([sys.executable,'-c','x=bytearray(96*1024*1024);import time;time.sleep(.05)'],check=True)
end=time.process_time()+1.5
while time.process_time()<end:pass
time.sleep(5)
print('load completed')
'''
    req=suite.request(code=code);suite.submit(req)
    poll(lambda:status(suite,req).phase=='running')
    time.sleep(3)
    live=status(suite,req);measured(live,final=False)
    containers=suite.docker.containers.list(filters={'label':[f'lazyx.job={req.request_id}','opensandbox.io/id']})
    require(len(containers)==1,'缺少独立执行容器')
    pid=containers[0].attrs['State']['Pid']
    relative=Path(f'/proc/{pid}/cgroup').read_text().strip().split('::',1)[1]
    path=Path('/sys/fs/cgroup')/relative.lstrip('/')
    cpu=int(dict(line.split() for line in (path/'cpu.stat').read_text().splitlines())['usage_usec'])
    peak=int((path/'memory.peak').read_text())
    require(0<live.cpu_usage_usec<=cpu,'CPU 值与实际容器不符')
    require(96*1024*1024<=live.peak_memory_bytes<=peak,'子进程短时内存峰值未计入')
    final=suite.result(req).status;measured(final)
    require(final.cpu_usage_usec>=cpu and final.peak_memory_bytes>=peak,'最终快照丢失累计用量')
    require(final.cpu_usage_usec>=1500000,'CPU 密集负载未计入')
    suite.no_resources([req.request_id])


def concurrent(suite):
    busy=suite.request(code=b'import time\nend=time.process_time()+2\nwhile time.process_time()<end:pass\ntime.sleep(5)')
    idle=suite.request(code=b'import time\ntime.sleep(9)')
    for req in (busy,idle):suite.submit(req)
    poll(lambda:all(status(suite,r).phase=='running' for r in (busy,idle)))
    view=metrics(suite)
    require(view.inflight==2 and view.tasks_by_phase['running']==2,'并发状态数量不符')
    a=suite.result(busy).status;b=suite.result(idle).status
    measured(a);measured(b)
    require(a.cpu_usage_usec>b.cpu_usage_usec+1000000,'两个任务的 CPU 计数混合')
    suite.no_resources([busy.request_id,idle.request_id])


def cancelled(suite):
    req=suite.request(code=b'import time\nx=bytearray(24*1024*1024)\ntime.sleep(30)')
    suite.submit(req)
    poll(lambda:status(suite,req).phase=='running' and status(suite,req).cpu_usage_available)
    suite.stubs['alice'].Cancel(pb.JobRef(request_id=req.request_id),timeout=30)
    value=suite.wait(req);measured(value)
    require(value.outcome=='cancelled')
    suite.no_resources([req.request_id])


def lost_container(suite):
    req=suite.request(code=b'import time\ntime.sleep(30)')
    suite.submit(req)
    poll(lambda:status(suite,req).phase=='running' and status(suite,req).cpu_usage_available)
    before=status(suite,req)
    for c in suite.docker.containers.list(filters={'label':[f'lazyx.job={req.request_id}','opensandbox.io/id']}):
        c.remove(force=True,v=True)
    value=suite.wait(req);measured(value,final=False)
    require(value.cpu_usage_usec>=before.cpu_usage_usec,'丢失容器时抹掉已采集数据')
    require(value.outcome!='success')
    suite.no_resources([req.request_id])


def capacity(suite):
    requests=[suite.request(code=b'import time\ntime.sleep(25)') for _ in range(6)]
    try:
        for req in requests:suite.submit(req)
        view=metrics(suite)
        require(view.inflight==6 and view.tasks_by_phase['queued']>=1,'队列指标不符')
        require(view.readiness.ready and not view.readiness.accepting_tasks,'容量满被误判为服务故障')
        require(view.readiness.admission_reason=='QUEUE_FULL')
        suite.stubs['alice'].Submit(requests[0],timeout=5)
    finally:
        for req in requests:
            suite.stubs['alice'].Cancel(pb.JobRef(request_id=req.request_id),timeout=30)
    for req in requests:suite.wait(req)
    poll(lambda:metrics(suite).inflight==0)
    view=metrics(suite)
    require(view.readiness.accepting_tasks and view.cleanup_pending==0,'回收后没有恢复容量')
    suite.no_resources([r.request_id for r in requests])


def cache_counts(suite):
    before=dict(metrics(suite).environment_counters)
    req=suite.request(code=b'import six\nprint(six.__version__)',dependencies=['six==1.16.0'])
    suite.submit(req)
    building=False
    end=time.monotonic()+600
    while time.monotonic()<end:
        view=metrics(suite)
        building=building or view.builds_active>0
        value=status(suite,req)
        if value.phase=='finished' and value.cleanup_done:break
        time.sleep(.2)
    require(value.outcome=='success','依赖环境执行失败')
    measured(value)
    cold=not value.environment_cache_hit
    if cold:require(building,'未观察到真实构建中的指标')
    again=suite.request(code=req.code,dependencies=['six==1.16.0'])
    suite.submit(again);value=suite.result(again).status
    require(value.environment_cache_hit,'第二次未命中缓存')
    view=metrics(suite)
    require(view.environment_counters['cache_hits']>=before.get('cache_hits',0)+1)
    if cold:
        require(view.environment_counters['cache_misses']==before.get('cache_misses',0)+1)
        require(view.environment_counters['builds_succeeded']==before.get('builds_succeeded',0)+1)
        require(view.environment_counters['build_duration_ms']>before.get('build_duration_ms',0))
    require(view.builds_active==view.builds_pending==0)
    require(view.cache_images>0 and view.cache_bytes>0)
    suite.no_resources([req.request_id,again.request_id])


def failed_build(suite):
    before=metrics(suite).environment_counters['builds_failed']
    req=suite.request(dependencies=['lazyx-synthetic-missing-metrics-package==0.0.1'])
    suite.submit(req);value=suite.wait(req,seconds=600)
    require(value.outcome=='failed')
    require(not value.cpu_usage_available and not value.peak_memory_available,'构建开销误计入未创建的任务')
    view=metrics(suite)
    require(view.environment_counters['builds_failed']==before+1,'构建失败未统计')
    require(view.builds_active==view.builds_pending==view.cleanup_pending==0)
    suite.no_resources([req.request_id])


def restart_metadata(suite):
    req=suite.request();suite.submit(req)
    value=suite.result(req).status;measured(value)
    started=metrics(suite).service_started_unix_ms
    subprocess.run(['bash',str(PROJECT/'scripts/restart_services.sh')],check=True,timeout=150)
    after=status(suite,req);measured(after)
    require(after.cpu_usage_usec==value.cpu_usage_usec and after.peak_memory_bytes==value.peak_memory_bytes)
    view=metrics(suite)
    require(view.service_started_unix_ms>started,'计数周期未更新')
    require(all(v==0 for v in view.environment_counters.values()),'进程计数器重启未复位')
    require(view.readiness.ready and view.readiness.reason=='READY' and view.readiness.accepting_tasks)


def run_observability_checks(suite):
    for name,func in (
        ('短任务真实计量与销毁后查询',short_task),
        ('CPU负载和子进程瞬时内存峰值对照宿主内核',load_and_kernel),
        ('并发任务指标与资源计数互不混合',concurrent),
        ('取消任务保留最终计量',cancelled),
        ('执行容器异常消失保留部分计量',lost_container),
        ('队列满保持健康并正确显示准入状态',capacity),
        ('依赖构建和缓存命中指标',cache_counts),
        ('构建失败指标且不冒充任务用量',failed_build),
        ('重启保留任务用量并重置进程计数周期',restart_metadata),
    ):
        suite.check(name,lambda func=func:func(suite))
    if suite.include_faults:
        import signal
        suite.check('回收器失联时未就绪并自动恢复',lambda:recovery(suite,'watchdog',signal.SIGSTOP))


if __name__=='__main__':
    suite=Acceptance()
    try:
        run_observability_checks(suite)
        suite.completed=True
    finally:
        suite.save()
        for channel in suite.channels.values():channel.close()
    raise SystemExit(0 if all(item['passed'] for item in suite.checks) else 1)
