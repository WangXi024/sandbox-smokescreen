"""独立沙箱管理服务：检查请求、安排执行、回传内存结果并核对资源清理。

对外通过内网免认证 gRPC 提供接口；模型和工具转交通道只有测试处理器。
任务正文、日志与产物仅保存在运行内存中，持久记录只保留任务元数据。
"""
import argparse
import asyncio
import base64
from datetime import datetime, timedelta, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import signal
import stat
import subprocess
import sys
import threading
import time

import docker
import grpc
import httpx
from opensandbox import Sandbox
from opensandbox.config import ConnectionConfig
from opensandbox.models import PlatformSpec, WriteEntry
from opensandbox.models.execd import ExecutionHandlers, RunCommandOpts
from .environments import Environments, declaration
from .settings import Settings
from .logs import start as start_logged
from . import resources
from .network import NetworkManager, domains
from .proto import sandbox_pb2 as pb, sandbox_pb2_grpc as rpc
from .test_caller import CallerUnavailable, TestCaller
from .watchdog import read_private_json

ROOT = Path(__file__).resolve().parents[2]
RUN = Path('/run/sandbox_model')
STATE = Path('/var/lib/sandbox_model/jobs.json')
MAX_INPUT = 1024 * 1024
MAX_ARTIFACT = 2 * 1024 * 1024
MAX_OUTPUT = 4 * 1024 * 1024
RETENTION = 180
PHASES = {'queued':'排队', 'preparing':'准备环境', 'creating':'创建沙箱', 'running':'执行', 'returning':'回传', 'finished':'完成'}

# 可信 root 助手先冻结再终止任务 UID；不导入用户 Python 路径。
STOP_TASKS = """import os,signal,time
from pathlib import Path
def active():
 out=[]
 for p in Path('/proc').iterdir():
  if p.name.isdigit():
   try:
    s=(p/'status').read_text()
    uid=next(x for x in s.splitlines() if x.startswith('Uid:')).split()[1]
    state=next(x for x in s.splitlines() if x.startswith('State:')).split()[1]
    if uid=='1000' and state!='Z':out.append(int(p.name))
   except (OSError,StopIteration):pass
 return out
for _ in range(5):
 targets=active()
 for sig in (signal.SIGSTOP,signal.SIGKILL):
  for pid in targets:
   try:os.kill(pid,sig)
   except ProcessLookupError:pass
 time.sleep(.05)
 if not active():break
if active():raise RuntimeError('TASK_PROCESS_REMAINS')
"""


def now():
    return datetime.now(timezone.utc).isoformat()


def atomic(path, data):
    """以私有权限原子替换元数据文件，避免回收进程读到半份快照。"""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_suffix('.new')
    temporary.write_text(json.dumps(data, ensure_ascii=False))
    temporary.chmod(0o600)
    temporary.replace(path)


def path_name(value):
    """限定相对路径的字符和层级，拒绝绝对路径及目录穿越。"""
    if (not value or len(value) > 200 or not re.fullmatch(r'[A-Za-z0-9_./-]+', value)
            or value.startswith('/') or any(p in ('', '.', '..') for p in value.split('/'))):
        raise ValueError('INVALID_PATH')
    return value


class Manager(rpc.SandboxServiceServicer):
    """协调环境、任务和网络；执行完成与资源清理完成分别记录。"""
    def __init__(self, test_mode):
        self.test_mode = test_mode
        self.settings = Settings.load()
        self.jobs = {}
        self.client = docker.from_env()
        self.catalog = json.loads((ROOT / 'catalog.json').read_text())
        self.environments = Environments(self)
        self.network = NetworkManager(self.client, run_dir=str(RUN), proxy_image=self.settings.proxy_image,
            dns_over_https=self.settings.dns_over_https,
            dns_server='172.27.250.53' if test_mode else self.settings.dns_server,
            fixture_ip='172.27.250.10' if test_mode else None)
        self.slots = asyncio.Semaphore(self.settings.concurrency)
        self.loop = asyncio.get_running_loop()
        self.ready = False
        self.service_started_unix_ms = int(time.time()*1000)
        self.unready_reason = 'STARTING_OR_RECOVERING'
        self.last_progress = time.monotonic()
        self.server_process = None
        self.watchdog = None
        self.gateway = None
        self.last_networks = {}
        self.server_key = secrets.token_urlsafe(32)
        self.test_caller = TestCaller() if test_mode else None
        self.gateway_lock = threading.Lock()
        self.connection = ConnectionConfig(domain='127.0.0.1:18080', api_key=self.server_key,
            use_server_proxy=False, disable_metrics=True, request_timeout=timedelta(seconds=130))
        # 重启只恢复状态记录；旧任务正文和产物已丢失，不能继续执行或伪造结果。
        if STATE.exists():
            for ident, item in json.loads(STATE.read_text()).items():
                item.update(outcome=item.get('outcome') or 'unknown', phase='finished',
                            error_code=item.get('error_code') or 'RESTARTED_RESULT_UNAVAILABLE',
                            cleanup_done=bool(item.get('cleanup_done')), finished=item.get('finished') or time.time())
                self.jobs[ident] = item | {'spec':None, 'task':None, 'sandbox':None, 'artifacts':[], 'stdout':'', 'stderr':'', 'calls':0, 'requests':{}, 'gateway_closed':True, 'proposal_json':b'', 'restarted':True}

    def persist(self):
        """持久化状态与计量元数据，不写入代码、输入文件、日志或产物正文。"""
        fields = ('request_id','digest','phase','outcome','error_code','cleanup_done','delivery_done','events','started','finished','deadline','failure_site','failure_trace','input_bytes','output_bytes','log_bytes','model_calls','tool_calls','environment_id','environment_cache_hit')
        atomic(STATE, {key:{field:job[field] for field in fields + resources.FIELDS if field in job} for key,job in self.jobs.items()})

    def registry(self):
        """供独立 OpenSandbox 进程读取任务网络身份，不把 Docker 对象传过去。"""
        data = {ident:{'network_mode':ctx.name, 'guest_ip':ctx.guest_ip, 'trusted_peer':ctx.gateway}
                for ident,ctx in self.network.jobs.items() if ctx.active}
        atomic(RUN / 'network-registry.json', data)

    def recover_networks(self):
        """覆盖旧 RAM 快照前恢复清理身份；不会恢复执行或接收旧任务正文。"""
        try:
            snapshot=read_private_json(RUN/'leases.json')
        except FileNotFoundError:
            snapshot={'jobs':{}}
        if not isinstance(snapshot,dict) or not isinstance(snapshot.get('jobs'),dict):
            raise ValueError('INVALID_RECOVERY_LEASES')
        for ident,entry in snapshot['jobs'].items():
            if not isinstance(entry,dict) or not isinstance(entry.get('network'),dict):
                raise ValueError('INVALID_RECOVERY_LEASES')
            context=entry['network']
            if context.get('job_id')!=ident:
                raise ValueError('RECOVERY_NETWORK_MISMATCH')
            self.network.restore_context(context)
        candidates={ident for ident,job in self.jobs.items() if not job.get('cleanup_done')}|set(self.network.jobs)
        for network in self.client.networks.list(filters={'label':'lazyx.sb=true'}):
            labels=network.attrs.get('Labels') or {}
            if labels.get('lazyx.sb')!='true' or labels.get('lazyx.sb.fixture'):
                continue
            context=self.network.orphan_context(network)
            ident=context['job_id']
            old=self.network.jobs.get(ident)
            if old and old.name!=network.name:
                raise ValueError('RECOVERY_NETWORK_MISMATCH')
            if not old:
                self.network.restore_context(context)
            elif not old.proxy_out_ip and context['proxy_out_ip']:
                old.proxy_out_ip=context['proxy_out_ip']
            candidates.add(ident)
        for container in self.client.containers.list(all=True,filters={'label':'lazyx.sb=true'}):
            labels=container.labels or {}
            if labels.get('lazyx.sb')=='true' and not labels.get('lazyx.sb.fixture'):
                ident=labels.get('lazyx.job','')
                if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',ident):
                    raise ValueError('INVALID_RECOVERY_JOB')
                candidates.add(ident)
        return sorted(candidates)

    async def reconcile(self):
        """先清理旧租约及标签扫描发现的资源，成功后才允许启动接单。"""
        for ident in self.recover_networks():
            await self.cleanup(ident)
            if ident in self.jobs:self.jobs[ident]['cleanup_done']=True
        self.persist()

    def network_snapshot(self, ident, ctx=None):
        # 网络创建在工作线程中进行，心跳不能等待其全局锁。
        ctx = ctx or self.network.jobs[ident]
        data = {key: value for key, value in vars(ctx).items() if key != 'proxy'}
        data['policy_dir'] = str(ctx.policy_dir)
        data['allowed_domains'] = list(ctx.allowed_domains)
        data['proxy_name'] = ctx.proxy.name if ctx.proxy else 'sb-smokescreen-' + ctx.name.removeprefix('sb-job-')
        return data

    def leases(self):
        """写入管理心跳、截止时间和网络清理信息，供独立回收器失联时使用。"""
        owners = self.jobs | getattr(getattr(self, 'environments', None), 'active', {})
        contexts = {ident:{'deadline':owners[ident]['deadline'], 'network':self.network_snapshot(ident,ctx)}
                    for ident,ctx in list(self.network.jobs.items()) if ident in owners}
        atomic(RUN / 'leases.json', {'manager_pid':os.getpid(), 'opensandbox_pid':self.server_process.pid,
                'heartbeat':time.time(), 'jobs':contexts})

    def event(self, job, phase):
        job['phase'] = phase
        job['events'].append({'phase':phase, 'time':now()})
        self.persist()
        print(f"[{PHASES[phase]}] 任务 {job['request_id']}", flush=True)

    def response(self, job):
        return pb.JobStatus(request_id=job['request_id'], phase=job['phase'], outcome=job['outcome'],
            error_code=job['error_code'], cleanup_done=job['cleanup_done'], delivery_done=job['delivery_done'],
            elapsed_ms=int(1000 * ((job.get('finished') or time.time()) - job['started'])),
            input_bytes=job.get('input_bytes',0),output_bytes=job.get('output_bytes',0),
            log_bytes=job.get('log_bytes',0),
            model_calls=job.get('model_calls',0),tool_calls=job.get('tool_calls',0),
            **{field:job[field] for field in resources.FIELDS if field in job},
            environment_id=job.get('environment_id',''),environment_cache_hit=job.get('environment_cache_hit',False),
            events=[pb.Event(**e) for e in job['events']])

    def healthy(self):
        return self.readiness_reason() == 'READY'

    def readiness_reason(self):
        """同时检查控制进程和回收器心跳；任一失联都停止新任务接入。"""
        if not self.ready:return getattr(self,'unready_reason','STARTING_OR_RECOVERING')
        if (RUN/'restart-request').exists():return 'RESTART_PENDING'
        if time.monotonic()-self.last_progress >= 5:return 'MANAGER_STALLED'
        if self.server_process.poll() is not None:return 'OPENSANDBOX_EXITED'
        if self.watchdog.poll() is not None:return 'WATCHDOG_EXITED'
        try:
            heartbeat = read_private_json(RUN/'watchdog-heartbeat.json')
            if heartbeat['pid'] == self.watchdog.pid and 0 <= time.time()-heartbeat['time'] < 5:
                return 'READY'
        except (OSError, ValueError, KeyError):
            pass
        return 'WATCHDOG_STALE'

    def result_bytes(self, job):
        return (sum(len(a['data']) for a in job.get('artifacts',[])) + len(job.get('stdout','').encode())
                + len(job.get('stderr','').encode()) + len(job.get('proposal_json',b'')))

    def admission_reason(self):
        """接单前预留结果内存并限制在途任务，避免排队挤满节点内存。"""
        if len(self.jobs) >= self.settings.max_history:return 'HISTORY_FULL'
        reserved = sum(MAX_OUTPUT + 144*1024 if j['phase'] != 'finished' else self.result_bytes(j)
                       for j in self.jobs.values())
        if reserved + MAX_OUTPUT + 144*1024 > 32*1024*1024:return 'RESULT_CACHE_FULL'
        if sum(j['phase'] != 'finished' for j in self.jobs.values()) >= self.settings.max_inflight:
            return 'QUEUE_FULL'
        return ''

    async def lookup(self, request, context):
        job = self.jobs.get(request.request_id)
        if not job:
            await context.abort(grpc.StatusCode.NOT_FOUND, 'JOB_NOT_FOUND')
        return job

    @staticmethod
    def digest(request):
        return hashlib.sha256(request.SerializeToString(deterministic=True)).hexdigest()

    def prune_history(self):
        """只淘汰已清理且后台执行已结束的过期记录，保留未清理任务线索。"""
        expired = [ident for ident, job in self.jobs.items()
                   if job['phase'] == 'finished' and job.get('cleanup_done')
                   and (not job.get('task') or job['task'].done())
                   and time.time()-job.get('finished', time.time()) > self.settings.history_seconds]
        for ident in expired:
            del self.jobs[ident]
        if expired:
            self.persist()

    def validate(self, request):
        """检查支持的任务、环境、路径、摘要和额度；调用方只能缩小节点上限。"""
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', request.request_id) or request.request_id.startswith('build_'):
            raise ValueError('INVALID_ID')
        if request.kind not in ('code','skill','web','parse','render','audit') or request.environment not in self.catalog:
            raise ValueError('UNSUPPORTED_ENVIRONMENT')
        if request.kind == 'web' and request.environment != 'browser' or request.kind == 'render' and request.environment != 'browser':
            raise ValueError('UNSUPPORTED_ENVIRONMENT')
        if request.kind in ('parse','audit') and request.network_domains:
            raise ValueError('OFFLINE_REQUIRED')
        if request.HasField('parse_options'):
            options = request.parse_options
            if (request.kind != 'parse' or options.max_pages > 7
                    or options.max_pages and not options.pdf_images
                    or options.max_long_edge and not 64 <= options.max_long_edge <= 2048):
                raise ValueError('INVALID_PARSE_OPTIONS')
        declaration(request.environment, list(request.dependencies))
        if request.dependencies and request.kind not in ('code','skill'):
            raise ValueError('UNSUPPORTED_DEPENDENCIES')
        domains(list(request.network_domains))
        if not 128 <= (request.memory_mb or 512) <= self.settings.max_memory_mb or not 1 <= (request.timeout_seconds or 60) <= self.settings.max_timeout_seconds:
            raise ValueError('INVALID_LIMIT')
        if (request.network_upload_bytes > self.settings.upload_bytes
                or request.network_download_bytes > self.settings.download_bytes):
            raise ValueError('INVALID_NETWORK_LIMIT')
        if len(request.inputs) > 32 or len(request.code) + sum(len(f.data) for f in request.inputs) > MAX_INPUT:
            raise ValueError('INPUT_TOO_LARGE')
        # 仅允许固定语言及时区值；此接口不能把真实 API Key 注入任务环境。
        if set(request.environment_variables) - {"LANG","TZ"}:
            raise ValueError("ENV_NOT_ALLOWED")
        if request.environment_variables.get("LANG","C.UTF-8") not in ("C.UTF-8","C") or request.environment_variables.get("TZ","UTC") not in ("UTC","Asia/Shanghai","Asia/Hong_Kong","America/New_York","Europe/London"):
            raise ValueError("ENV_NOT_ALLOWED")
        seen = set()
        for entry in request.inputs:
            path_name(entry.path)
            if entry.path in seen or entry.sha256 != hashlib.sha256(entry.data).hexdigest():
                raise ValueError('INPUT_HASH_MISMATCH')
            seen.add(entry.path)
        if request.entrypoint:
            path_name(request.entrypoint)
        if request.kind == 'code' and not request.code:
            raise ValueError('CODE_REQUIRED')
        if request.kind in ('skill','audit') and not request.entrypoint:
            raise ValueError('ENTRY_REQUIRED')
        if request.kind == 'web':
            from urllib.parse import urlsplit
            target = urlsplit(request.url)
            if target.scheme != 'https' or target.username or target.password or target.port not in (None,443) or target.hostname not in request.network_domains:
                raise ValueError('URL_NOT_AUTHORIZED')
        if request.kind == 'render' and (request.render_format not in ('png','pdf') or request.network_domains):
            raise ValueError('INVALID_RENDER')

    async def Submit(self, request, context):
        """接收后异步执行；同编号同内容返回原状态，同编号不同内容拒绝。"""
        if not self.healthy():
            await context.abort(grpc.StatusCode.UNAVAILABLE, 'NOT_READY')
        try:
            self.validate(request)
        except ValueError as error:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, str(error))
        old = self.jobs.get(request.request_id)
        if old:
            if old['digest'] != self.digest(request):
                await context.abort(grpc.StatusCode.ALREADY_EXISTS, 'ID_CONFLICT')
            return self.response(old)
        self.prune_history()
        reason = self.admission_reason()
        if reason:
            await context.abort(grpc.StatusCode.RESOURCE_EXHAUSTED, reason)
        copy = pb.TaskRequest(); copy.CopyFrom(request)
        job = {'request_id':request.request_id,'digest':self.digest(request),'spec':copy,
               'phase':'queued','outcome':'','error_code':'','cleanup_done':False,'delivery_done':False,
               'events':[],'started':time.time(),'deadline':time.time()+(600 if request.dependencies else 180),'sandbox':None,'artifacts':[],
               'stdout':'','stderr':'','calls':0,'requests':{},'gateway_closed':False,
               'input_bytes':len(request.code)+sum(len(f.data) for f in request.inputs),
               'output_bytes':0,'log_bytes':0,'model_calls':0,'tool_calls':0,'proposal_json':b'', 'task':None}
        self.jobs[request.request_id] = job
        self.event(job, 'queued')
        job['task'] = asyncio.create_task(self.execute(job))
        return self.response(job)

    async def Status(self, request, context):
        return self.response(await self.lookup(request, context))

    async def Cancel(self, request, context):
        """请求停止并等待有限时间；返回时仍须由调用方检查 cleanup_done。"""
        job = await self.lookup(request, context)
        if job['phase'] != 'finished':
            self.stop_job(job, 'cancelled', 'CANCELLED')
            try:
                await asyncio.wait_for(asyncio.shield(job['task']), 20)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                pass
        return self.response(job)

    async def Result(self, request, context):
        """回传完成任务的内存结果；保留期届满或服务重启后正文不可取回。"""
        job = await self.lookup(request, context)
        if job['phase'] != 'finished':
            await context.abort(grpc.StatusCode.FAILED_PRECONDITION, 'NOT_FINISHED')
        if time.time() - job.get('finished',0) > RETENTION or job.get('restarted',False):
            await context.abort(grpc.StatusCode.NOT_FOUND, 'RESULT_EXPIRED')
        return pb.JobResult(status=self.response(job), artifacts=[pb.Artifact(**x) for x in job['artifacts']],
                            stdout=job['stdout'], stderr=job['stderr'],proposal_json=job.get('proposal_json',b''))

    async def Acknowledge(self, request, context):
        """记录调用方已收妥结果；接收确认与执行资源清理是两个独立状态。"""
        job = await self.lookup(request, context)
        if job['phase'] != 'finished':
            await context.abort(grpc.StatusCode.FAILED_PRECONDITION, 'NOT_FINISHED')
        job['delivery_done'] = True
        self.persist()
        return self.response(job)

    async def Ready(self, request, context):
        """区分控制组件就绪与当前有容量接单，满载时服务仍可能处于就绪状态。"""
        reason = self.readiness_reason()
        ready = reason == 'READY'
        admission = self.admission_reason() if ready else reason
        return pb.ReadyReply(ready=ready,environments=sorted(self.catalog),mode='test' if self.test_mode else 'independent',
                             reason=reason,accepting_tasks=ready and not admission,admission_reason=admission)

    async def Metrics(self, request, context):
        """汇总当前保留记录与环境缓存；任务数不是无限保留的历史累计值。"""
        jobs = list(self.jobs.values())
        env = self.environments
        active = sum(item['deadline'] > 0 for item in env.active.values())
        cached = [item for item in env.entries.values() if item.get('image_id')]
        return pb.MetricsReply(readiness=await self.Ready(request,context),
            service_started_unix_ms=self.service_started_unix_ms,
            tasks_by_phase={phase:sum(j['phase']==phase for j in jobs) for phase in PHASES},
            finished_by_outcome={outcome:sum(j['phase']=='finished' and j['outcome']==outcome for j in jobs)
                                 for outcome in ('success','failed','cancelled','unknown','needs_approval')},
            inflight=sum(j['phase']!='finished' for j in jobs),
            cleanup_pending=sum(j['phase']=='finished' and not j.get('cleanup_done') for j in jobs)
                            + sum(item['deadline']==0 for item in env.active.values()),
            result_cache_bytes=sum(self.result_bytes(j) for j in jobs),history_records=len(jobs),
            builds_active=active,builds_pending=max(0,sum(not p['task'].done() for p in env.pending.values())-active),
            cache_images=len(cached),cache_bytes=sum(item['bytes'] for item in cached),
            environment_counters=env.counters)

    def stop_job(self, job, outcome, error_code):
        """先关闭转交通道，再取消执行；尚未启动的排队任务直接完成收尾。"""
        job['gateway_closed'] = True
        if job['phase'] != 'finished' and not job['outcome']:
            queued = job['phase'] == 'queued'
            job['outcome'] = outcome
            job['error_code'] = error_code
            if job['task'] and not job['task'].cancelling():
                job['task'].cancel()
            if queued:
                job['spec'] = None
                job['cleanup_done'] = True
                job['finished'] = time.time()
                self.event(job, 'finished')

    async def command(self, sandbox, command, uid=1000, timeout=30, cap=7*1024*1024):
        """通过可信执行接口运行命令，流式限制输出，默认使用非特权任务 UID。"""
        chunks = []; size = 0
        async def capture(message):
            nonlocal size
            size += len(message.text.encode())
            if size > cap:
                raise ValueError('OUTPUT_TOO_LARGE')
            chunks.append(message.text)
        handlers = ExecutionHandlers(on_stdout=capture,on_stderr=capture,skip_accumulation=True)
        result = await sandbox.commands.run(command, opts=RunCommandOpts(uid=uid,gid=uid,
             timeout=timedelta(seconds=timeout),working_directory='/workspace',
             envs={'TMPDIR':'/tmp'} if uid==1000 else None),handlers=handlers)
        return result, ''.join(chunks)

    def ensure_image(self, environment):
        """按目录中固定镜像 ID 恢复或拉取基础镜像，核对可信运行组件标记。"""
        entry = self.catalog[environment]
        try:
            image = self.client.images.get(entry['image_id'])
        except docker.errors.ImageNotFound:
            if entry.get('image_archive'):
                loaded = subprocess.run(['docker','load','-i',entry['image_archive']],
                                           stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=90)
                if loaded.returncode:raise ValueError('IMAGE_RESTORE_FAILED')
            else:
                self.client.images.pull(entry['image_ref'])
            image = self.client.images.get(entry['image_id'])
        if image.id != entry['image_id'] or image.labels.get('lazyx.runtime') != 'sb0-v1':
            raise ValueError('IMAGE_MISMATCH')
        return image.id

    def test_gate_action(self, ident, point):
        """仅 root 在 /run 放置的验收屏障，生产模式完全不读取。"""
        if not self.test_mode:
            return None
        path=RUN/'test-gates'/f'{ident}.{point}'
        try:
            info=path.lstat()
        except FileNotFoundError:
            return None
        directory=path.parent.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode & 0o077
                or info.st_size>16 or not stat.S_ISDIR(directory.st_mode)
                or directory.st_uid!=0 or directory.st_mode & 0o077):
            raise ValueError('INVALID_TEST_GATE')
        action=path.read_text().strip()
        if action not in ('hold','lose'):
            raise ValueError('INVALID_TEST_GATE')
        marker=path.with_name(path.name+'.entered')
        if not marker.exists():
            descriptor=os.open(marker,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            with os.fdopen(descriptor,'w') as stream:stream.write(point)
        return action

    async def wait_test_gate(self, ident, point):
        while True:
            action=self.test_gate_action(ident,point)
            if action!='hold':break
            await asyncio.sleep(.05)
        if action=='lose':
            raise ValueError('TEST_GATE_FAILURE')

    def prepare_network(self, ident, allowed):
        while True:
            action=self.test_gate_action(ident,'preparing')
            if action!='hold':break
            time.sleep(.05)
        if action=='lose':raise ValueError('TEST_GATE_FAILURE')
        job=self.jobs[ident]
        if job['outcome'] or time.time() >= job['deadline']:
            raise ValueError('TASK_STOPPED')
        request = job['spec']
        return self.network.prepare(ident,allowed,self.test_mode,
            upload_bytes=request.network_upload_bytes or self.settings.upload_bytes,
            download_bytes=request.network_download_bytes or self.settings.download_bytes)

    async def execute(self, job):
        """依次准备环境、创建新沙箱、写入输入、执行与导出，任何退出路径都清理。"""
        ident = job['request_id']; request = job['spec']; acquired = False
        preparation=None; creation=None
        try:
            if request.dependencies:
                self.event(job,'preparing')
                base = await asyncio.to_thread(self.ensure_image, request.environment)
                image = await asyncio.wait_for(self.environments.ensure(job,base),
                    max(.01,job['deadline']-time.time()))
                await asyncio.wait_for(self.slots.acquire(),30)
                acquired = True
            else:
                await asyncio.wait_for(self.slots.acquire(), 30)
                acquired = True
                self.event(job,'preparing')
                image = await asyncio.to_thread(self.ensure_image, request.environment)
            # shield 让已发出的装配和创建继续可被对账；取消请求不等于资源未创建。
            preparation=asyncio.create_task(asyncio.to_thread(self.prepare_network,ident,list(request.network_domains)))
            ctx = await asyncio.shield(preparation)
            self.registry(); self.leases()
            self.event(job,'creating')
            env = ctx.env | {'HOME':'/home/sandbox','TMPDIR':'/tmp','LANG':'C.UTF-8','TZ':'UTC'} | dict(request.environment_variables)
            if self.test_mode and (RUN/'test-spki.txt').exists():
                env['LAZYX_TEST_TLS_SPKI'] = (RUN/'test-spki.txt').read_text().strip()
            creation=asyncio.create_task(Sandbox.create(image,entrypoint=['sleep','infinity'],
                 platform=PlatformSpec(os='linux',arch='arm64'),env=env,metadata={'lazyx.job':ident},
                 resource={'cpu':'1','memory':f'{request.memory_mb or 512}Mi'},timeout=timedelta(seconds=180),
                 ready_timeout=timedelta(seconds=90),connection_config=self.connection))
            sandbox=await asyncio.shield(creation)
            job['sandbox'] = sandbox
            owned = self.client.containers.list(filters={'label':f'lazyx.job={ident}'})
            owned = [c for c in owned if c.labels.get('opensandbox.io/id') == sandbox.id]
            if len(owned)!=1:
                raise ValueError('INSTANCE_MISMATCH')
            attrs=owned[0].attrs['HostConfig']
            if attrs['Runtime']!='runsc' or not attrs['ReadonlyRootfs'] or attrs['LogConfig']['Type']!='none':
                raise ValueError('PROTECTION_NOT_READY')
            resources.bind(job,owned[0]);resources.sample(job)
            print(f'[成功] 沙箱已创建，任务：{ident}',flush=True)
            # 工作区由运行适配器固定为 tmpfs，输入上传使用任务身份而非可信 root。
            files = sandbox.files.with_identity(1000,1000)
            import shlex
            parents = sorted({'/workspace/inputs/'+str(PurePosixPath(x.path).parent) for x in request.inputs})
            await self.command(sandbox, 'mkdir -p /workspace/out /workspace/inputs '+ ' '.join(shlex.quote(x) for x in parents))
            entries = [WriteEntry(path='/workspace/inputs/'+x.path,data=x.data,mode=600) for x in request.inputs]
            if request.kind=='code':
                entrypoint='main.js' if request.environment=='node' else 'main.py'
                entries.append(WriteEntry(path='/workspace/'+entrypoint,data=request.code,mode=600))
            else:
                entrypoint=request.entrypoint
            task={'kind':request.kind,'environment':request.environment,'entrypoint':entrypoint,
                  'url':request.url,'render_format':request.render_format,'options':{}}
            if request.kind == 'parse':
                task['options'] = {'pdf_images':request.parse_options.pdf_images,
                    'max_pages':request.parse_options.max_pages or 7,
                    'max_long_edge':request.parse_options.max_long_edge or 2048}
            entries.append(WriteEntry(path='/workspace/task.json',data=json.dumps(task).encode(),mode=600))
            await files.write_files(entries)
            job['deadline']=min(time.time()+(request.timeout_seconds or 60)+5,job['deadline'])
            self.leases()
            self.event(job,'running')
            result, _ = await asyncio.wait_for(self.command(sandbox,'python /opt/platform/guest.py',
                  timeout=request.timeout_seconds or 60,cap=256*1024),request.timeout_seconds or 60)
            # 任务进程停止后再导出，避免不可信子进程在检查和读取之间替换文件。
            stopped, _ = await self.command(sandbox,'python -I -c ' + shlex.quote(STOP_TASKS),uid=0,cap=1024)
            if stopped.exit_code != 0: raise ValueError('TASK_PROCESS_REMAINS')
            self.event(job,'returning')
            await self.wait_test_gate(ident,'returning')
            exported, text=await self.command(sandbox,'python -I /opt/platform/export.py',uid=0,timeout=15)
            if exported.exit_code!=0:
                raise ValueError('UNSAFE_OUTPUT')
            data=json.loads(text)
            manifest=data['manifest']
            total=0
            for item in data['artifacts']:
                path_name(item['path'])
                content=base64.b64decode(item['data_base64'],validate=True)
                total+=len(content)
                if len(content)>MAX_ARTIFACT or total>MAX_OUTPUT or hashlib.sha256(content).hexdigest()!=item['sha256']:
                    raise ValueError('OUTPUT_INVALID')
                job['artifacts'].append({'path':item['path'],'data':content,'sha256':item['sha256']})
            job['stdout']=str(manifest.get('stdout','')).encode('utf-8')[:65536].decode('utf-8',errors='ignore')
            job['stderr']=(str(manifest.get('stderr',''))+'\n'+str(manifest.get('error',''))).encode('utf-8')[:65536].decode('utf-8',errors='ignore')
            job['outcome']='success' if result.exit_code==0 and manifest.get('status')=='success' else 'failed'
            if job['outcome']=='failed': job['error_code']='EXECUTION_FAILED'
        except asyncio.CancelledError:
            job['outcome']=job['outcome'] or 'cancelled'; job['error_code']=job['error_code'] or 'CANCELLED'
        except asyncio.TimeoutError:
            job['outcome']='failed'; job['error_code']='TIMEOUT'
        except Exception as error:
            import traceback
            locations=[x for x in traceback.extract_tb(error.__traceback__) if str(x.filename).startswith(str(ROOT))]
            if locations:
                job['failure_site']={'file':Path(locations[-1].filename).name,'line':locations[-1].lineno}
                job['failure_trace']=[{'file':Path(x.filename).name,'line':x.lineno} for x in locations]
            job['error_code']=str(error) if isinstance(error,ValueError) and re.fullmatch(r'[A-Z_]+',str(error)) else type(error).__name__.upper()
            job['outcome']='failed'
        finally:
            try:
                # asyncio 取消不会停止线程或已送达创建；完成对账后才能记录清理成功。
                for pending in (preparation,creation):
                    if pending:
                        try:await asyncio.shield(pending)
                        except Exception:pass
                try:
                    await self.cleanup(ident)
                    job['cleanup_done']=True
                except Exception:
                    job['error_code']=job['error_code'] or 'CLEANUP_PENDING'
                job['spec']=None
                job['requests']={}
                job['output_bytes']=sum(len(item['data']) for item in job['artifacts'])+len(job['proposal_json'])
                job['log_bytes']=len(job['stdout'].encode())+len(job['stderr'].encode())
                job['finished']=time.time()
                self.event(job,'finished')
            finally:
                if acquired:self.slots.release()
                if job.get("environment_key"):self.environments.release(job)

    async def cleanup(self, ident):
        """先撤销网络，再采集最终用量并销毁容器，核对全部资源消失才算清理成功。"""
        job=self.jobs.get(ident)
        if job:job['gateway_closed'] = True
        if job and job.get('spec') and job['spec'].network_domains:
            error = await asyncio.to_thread(self.network.quota_error, ident)
            if error:
                job.update(outcome='failed', error_code=error)
        await asyncio.to_thread(self.network.revoke,ident)
        # 销毁前再读一次内核累计值；快速任务也不依赖维护循环刚好采到。
        if job and (not job.get('resource_usage_final') or
                    job.get('_usage_path') and job['_usage_path'].exists()):
            if not job.get('_usage_path'):
                containers = await asyncio.to_thread(self.client.containers.list,all=True,
                    filters={'label':['lazyx.sb=true','opensandbox.io/id',f'lazyx.job={ident}']})
                if len(containers)==1:resources.bind(job,containers[0])
            resources.sample(job,final=True)
        sandbox=job.get('sandbox') if job else None
        if sandbox:
            try: await asyncio.wait_for(sandbox.destroy(),5)
            except Exception: pass
        # 控制接口异常时使用可信 Docker 侧清理，包含响应丢失但已创建的实例。
        for container in await asyncio.to_thread(self.client.containers.list,all=True,filters={'label':f'lazyx.job={ident}'}):
            if container.labels.get('lazyx.sb')=='true' or container.labels.get('opensandbox.io/id'):
                await asyncio.to_thread(container.remove,force=True,v=True)
        if ident in self.network.jobs:
            await asyncio.to_thread(self.network.release,ident)
        left = await asyncio.to_thread(self.client.containers.list,all=True,filters={'label':f'lazyx.job={ident}'})
        if left: raise RuntimeError('CLEANUP_PENDING')
        remaining=await asyncio.to_thread(self.network.remaining_resources,ident)
        if any(remaining.values()):raise RuntimeError('NETWORK_RESOURCES_REMAIN')
        if self.test_mode:
            for point in ('preparing','returning'):
                for suffix in ('','.entered'):
                    (RUN/'test-gates'/f'{ident}.{point}{suffix}').unlink(missing_ok=True)
        self.registry()
        if self.server_process: self.leases()
        print(f'[清理] 沙箱已销毁，任务：{ident}',flush=True)

    def gateway_request(self, source_ip, data):
        """仅测试处理器支持的来源绑定转交；同编号不重做，结果未知时停止任务。"""
        with self.gateway_lock:
            ident=self.network.source_job(source_ip)
            job=self.jobs.get(ident)
            if (not job or not job.get('spec') or job['spec'].kind not in ('code','skill')
                    or job['phase']!='running' or job['outcome'] or job.get('gateway_closed')
                    or job.get('deadline',0)<=time.time()):
                return 403,{'status':'denied','reason':'INVALID_TASK'}
            if (not isinstance(data,dict) or set(data) not in
                    ({'type','operation','arguments'},{'type','operation','arguments','request_id'})
                    or data['type'] not in ('model','tool') or not isinstance(data['operation'],str)
                    or not isinstance(data['arguments'],dict)
                    or data['type']=='model' and job['spec'].kind!='skill' or not self.test_caller):
                return 403,{'status':'denied','reason':'INVALID_REQUEST'}
            request_id=data.get('request_id', 'legacy_'+secrets.token_hex(12))
            if not isinstance(request_id,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}',request_id):
                return 403,{'status':'denied','reason':'INVALID_REQUEST_ID'}
            message={key:data[key] for key in ('type','operation','arguments')}
            digest=hashlib.sha256(json.dumps(message,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()
            previous=job['requests'].get(request_id)
            if previous:
                if previous['digest']!=digest:
                    return 409,{'status':'denied','reason':'REQUEST_ID_CONFLICT','request_id':request_id}
                return previous['response']
            if job['calls']>=8:
                job['gateway_closed']=True
                self.loop.call_soon_threadsafe(self.stop_job,job,'failed','CALL_LIMIT')
                return 403,{'status':'denied','reason':'CALL_LIMIT','request_id':request_id}
            job['calls']+=1
            job[data['type']+'_calls']+=1
            try:
                result=self.test_caller.request('internal',ident,request_id,
                    data['type'],data['operation'],data['arguments'])
                if (result.get('owner'),result.get('job_id'),result.get('request_id'))!=('internal',ident,request_id):
                    raise CallerUnavailable('CALLER_CONTEXT_MISMATCH')
                response=(200,result)
            except Exception:
                # 不知道调用方是否已执行；保存拒绝并停止，绝不重发。
                response=(503,{'status':'denied','reason':'CALLER_UNAVAILABLE','request_id':request_id})
                job['gateway_closed']=True
                self.loop.call_soon_threadsafe(self.stop_job,job,'unknown','CALLER_LOST')
            job['requests'][request_id]={'digest':digest,'response':response}
            result=response[1]
            if result.get('status')=='needs_approval':
                job['proposal_json']=json.dumps(data | {'request_id':request_id},ensure_ascii=False).encode()
                job['gateway_closed']=True
                self.loop.call_soon_threadsafe(self.stop_job,job,'needs_approval','APPROVAL_REQUIRED')
            elif result.get('reason')=='BUDGET_EXHAUSTED':
                job['gateway_closed']=True
                self.loop.call_soon_threadsafe(self.stop_job,job,'failed','BUDGET_EXHAUSTED')
            self.loop.call_soon_threadsafe(self.persist)
            return response

    def start_gateway(self):
        """启动有大小、超时和并发限制的 HTTP 入口；独立模式不提供真实代调用。"""
        manager=self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args): pass
            def do_POST(self):
                status=403; result={'status':'denied','reason':'INVALID_TASK'}
                try:
                    if self.path!='/request': raise ValueError()
                    length=int(self.headers.get('Content-Length','0'))
                    if not 0<length<=16384: raise ValueError()
                    self.connection.settimeout(2)
                    data=json.loads(self.rfile.read(length))
                    status,result=manager.gateway_request(self.client_address[0],data)
                except (ValueError,TypeError,KeyError,TimeoutError,json.JSONDecodeError):
                    status=403; result={'status':'denied','reason':'INVALID_REQUEST'}
                wire=json.dumps(result,ensure_ascii=False).encode()
                self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(wire)));self.end_headers()
                try:self.wfile.write(wire)
                except (BrokenPipeError,ConnectionResetError):pass
        class GatewayServer(ThreadingHTTPServer):
            pending = threading.BoundedSemaphore(8)
            def process_request(self, request, address):
                request.settimeout(2)
                if not self.pending.acquire(blocking=False):
                    request.close()
                    return
                try:
                    super().process_request(request,address)
                except BaseException:
                    self.pending.release()
                    raise
            def process_request_thread(self, request, address):
                try:
                    super().process_request_thread(request,address)
                finally:
                    self.pending.release()
        self.gateway=GatewayServer(('0.0.0.0',18600),Handler)
        threading.Thread(target=self.gateway.serve_forever,daemon=True).start()

    async def maintenance(self):
        """持续检查控制组件、任务超时和额度，并清空过期正文、重试未完成清理。"""
        async with httpx.AsyncClient(trust_env=False) as http:
            while True:
                if not self.healthy():
                    self.unready_reason = self.readiness_reason()
                    self.ready = False
                    raise RuntimeError('CONTROL_LOST')
                try:
                    response = await http.get('http://127.0.0.1:18080/health', timeout=2)
                    response.raise_for_status()
                except httpx.HTTPError:
                    self.unready_reason = 'OPENSANDBOX_UNAVAILABLE'
                    self.ready = False
                    raise RuntimeError('CONTROL_LOST')
                try:
                    await asyncio.wait_for(asyncio.to_thread(self.client.ping),2)
                except Exception:
                    self.unready_reason = 'DOCKER_UNAVAILABLE'
                    self.ready = False
                    raise RuntimeError('CONTROL_LOST')
                self.leases()
                for job in list(self.jobs.values()):
                    if job['phase'] != 'finished':resources.sample(job)
                    if job['phase'] != 'finished' and time.time() >= job.get('deadline',0):
                        self.stop_job(job,'failed','TIMEOUT')
                    elif job['phase'] in ('running','returning') and job.get('spec') and job['spec'].network_domains:
                        error = await asyncio.to_thread(self.network.quota_error, job['request_id'])
                        if error:
                            self.stop_job(job,'failed',error)
                await self.check_oom()
                for job in list(self.jobs.values()):
                    if job['phase']=='finished' and time.time()-job.get('finished',0)>RETENTION:
                        job['artifacts']=[];job['stdout']='';job['stderr']='';job['proposal_json']=b''
                    if job['phase']=='finished' and not job['cleanup_done']:
                        try: await self.cleanup(job['request_id']);job['cleanup_done']=True;self.persist()
                        except Exception:pass
                self.prune_history()
                self.last_progress = time.monotonic()
                await asyncio.sleep(.5)

    async def check_oom(self):
        """仅依据 Docker 的 OOMKilled 状态判断内存超限，不把普通脚本失败当作 OOM。"""
        active_jobs={ident for ident,job in self.jobs.items()
                     if job['phase'] in ('running','returning') and not job['outcome']}
        if not active_jobs:return
        try:
            containers=await asyncio.to_thread(self.client.containers.list,all=True,
                filters={'label':['lazyx.sb=true','opensandbox.io/id']})
        except Exception:
            return  # 暂时读不到状态时不推断 OOM；下个周期和独立回收器继续检查。
        for container in containers:
            ident=(container.labels or {}).get('lazyx.job')
            if ident in active_jobs and container.attrs.get('State',{}).get('OOMKilled'):
                self.stop_job(self.jobs[ident],'failed','MEMORY_LIMIT')

    async def launch(self):
        """完成旧资源对账后启动 OpenSandbox 和回收器，两者健康才标记就绪。"""
        # 旧代理仍在时恢复地址身份；完整清理失败不能覆盖快照或重新接单。
        await self.reconcile()
        await asyncio.to_thread(self.environments.recover)
        config=f'''[server]\nhost = "127.0.0.1"\nport = 18080\napi_key = "{self.server_key}"\n[runtime]\ntype = "docker"\nexecd_image = "opensandbox/execd:release-1.1.1@sha256:cda2bc35409bbf57561599b316cafb899598f7dce671332e7ceda14eb1cfeded"\n[secure_runtime]\ntype = "gvisor"\ndocker_runtime = "runsc"\n[docker]\nnetwork_mode = "bridge"\npublish_host = "127.0.0.1"\n[proxy]\nresolve_internal = true\n[store]\ntype = "sqlite"\npath = "/run/sandbox_model/opensandbox.db"\n'''
        (RUN/'opensandbox.toml').write_text(config)
        self.registry()
        arguments=[sys.executable,'-m','sandbox_model.opensandbox_process','--config',str(RUN/'opensandbox.toml')]
        if self.test_mode:arguments.append('--test-mode')
        self.server_process=start_logged(arguments,RUN/'opensandbox.log',cwd=ROOT)
        (RUN/'opensandbox.pid').write_text(str(self.server_process.pid))
        self.leases()
        self.watchdog=start_logged([sys.executable,'-m','sandbox_model.watchdog'],RUN/'watchdog.log',cwd=ROOT)
        (RUN/'watchdog.pid').write_text(str(self.watchdog.pid))
        async with httpx.AsyncClient(trust_env=False) as http:
            for _ in range(90):
                try:
                    reply=await http.get('http://127.0.0.1:18080/health',timeout=1)
                    if reply.is_success:break
                except httpx.HTTPError:pass
                if self.server_process.poll() is not None:raise RuntimeError('OpenSandbox 启动失败，日志仅保留于 /run')
                self.leases();await asyncio.sleep(.5)
            else:raise RuntimeError('OpenSandbox 启动超时')
        for _ in range(50):
            try:
                heartbeat=read_private_json(RUN/'watchdog-heartbeat.json')
                if heartbeat['pid']==self.watchdog.pid and time.time()-heartbeat['time']<5:break
            except (OSError,ValueError,KeyError):pass
            await asyncio.sleep(.1)
        else:raise RuntimeError('WATCHDOG_NOT_READY')
        self.prune_history()
        self.start_gateway();self.last_progress=time.monotonic();self.ready=True


async def main(test_mode):
    """专用节点内的服务入口；收到退出或失联信号时停止接单并等待任务收尾。"""
    compose = os.environ.get('SANDBOX_DEPLOYMENT') == 'compose' and (RUN/'compose-node').exists()
    if os.geteuid()!=0 or not compose:
        raise SystemExit('必须在本项目专用 Linux 运行节点中启动')
    RUN.mkdir(mode=0o700,parents=True,exist_ok=True);os.umask(0o077)
    (RUN/'service.pid').write_text(str(os.getpid()))
    manager=Manager(test_mode)
    server=grpc.aio.server(options=[('grpc.max_receive_message_length',2*1024*1024),('grpc.max_send_message_length',8*1024*1024)])
    rpc.add_SandboxServiceServicer_to_server(manager,server)
    server.add_insecure_port('0.0.0.0:18443')
    stop=asyncio.Event()
    for sig in (signal.SIGINT,signal.SIGTERM):asyncio.get_running_loop().add_signal_handler(sig,stop.set)
    maintenance=None
    try:
        await manager.launch();await server.start();maintenance=asyncio.create_task(manager.maintenance())
        print('[就绪] 独立沙箱服务已启动：内网免认证 gRPC 18443',flush=True)
        stopping=asyncio.create_task(stop.wait())
        done,_=await asyncio.wait((stopping,maintenance),return_when=asyncio.FIRST_COMPLETED)
        if maintenance in done:
            manager.ready=False
            print('[恢复] 控制组件失联，停止接单并清理任务',flush=True)
        stopping.cancel()
    finally:
        manager.unready_reason='SHUTTING_DOWN'
        manager.ready=False
        for job in list(manager.jobs.values()):manager.stop_job(job,'unknown' if maintenance and maintenance.done() else 'cancelled',
                                                                  'CONTROL_LOST' if maintenance and maintenance.done() else 'SERVICE_STOP')
        tasks=[job['task'] for job in manager.jobs.values() if job.get('task')]
        if tasks:await asyncio.gather(*tasks,return_exceptions=True)
        if maintenance:
            maintenance.cancel()
            await asyncio.gather(maintenance,return_exceptions=True)
        await server.stop(2)
        if manager.gateway:manager.gateway.shutdown()
        for process in (manager.server_process,manager.watchdog):
            if process and process.poll() is None:
                process.terminate()
                try:process.wait(timeout=5)
                except subprocess.TimeoutExpired:process.kill();process.wait()


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--test-mode',action='store_true')
    asyncio.run(main(parser.parse_args().test_mode or os.environ.get('SANDBOX_TEST_MODE')=='1'))
