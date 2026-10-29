"""Bounded per-operation gVisor workspaces; payloads and file state stay in RAM."""
import asyncio
import base64
from datetime import timedelta
import hashlib
import json
from pathlib import Path
import re
import time

import grpc
from opensandbox import Sandbox
from opensandbox.models import PlatformSpec
from opensandbox.models.execd import ExecutionHandlers, RunCommandOpts

from .architecture import runtime_architecture
from .workspace_output import decode_output, workspace_connection
from .proto import workspace_pb2 as pb, workspace_pb2_grpc as rpc
from .watchdog import atomic_json, read_private_json

STATE=Path('/var/lib/sandbox_model/workspaces.json')
MAX_FILE=8*1024*1024
MAX_OUTPUT=1024*1024
MAX_COMMANDS=64
CLOSE_GRACE_SECONDS=5
MAX_CACHED_OUTPUT=8*1024*1024
MUTATIONS={'write','mkdir','remove','rename','chmod','symlink'}
OPERATIONS=MUTATIONS|{'read','stat','lstat','list','readlink','realpath'}
PERSISTED=('workspace_id','request_id','digest','job_id','state','deadline','cleanup_done','error_code')
SAFE_ERRORS={'MISSING','NOT_DIRECTORY','IS_DIRECTORY','PERMISSION_DENIED','INVALID_PATH',
             'UNAVAILABLE','LIMIT_EXCEEDED','UNSUPPORTED_FILE_TYPE','ALREADY_EXISTS','SYMLINK_LOOP'}

# Fixed isolated stdlib trampoline. Native execd records this process' real
# exit status; argv remains literal and never becomes a shell string.
ARGV_TRAMPOLINE = """import os,sys
args=sys.argv[2:]
try:
    os.execvpe(args[0],args,os.environ)
except FileNotFoundError:
    sys.stderr.write('command not found\\n')
    sys.exit(127)
except PermissionError:
    sys.stderr.write('command not executable\\n')
    sys.exit(126)
except OSError:
    sys.stderr.write('command could not be executed\\n')
    sys.exit(126)
"""


def identity(value):
    return isinstance(value,str) and re.fullmatch(r'[A-Za-z0-9_-]{1,128}',value) is not None


def digest(request):
    return hashlib.sha256(request.SerializeToString(deterministic=True)).hexdigest()


class WorkspaceService(rpc.WorkspaceServiceServicer):
    def __init__(self,manager,state_path=STATE):
        self.manager=manager
        self.state_path=state_path
        self.guard=asyncio.Lock()
        self.entries=read_private_json(state_path) if state_path.exists() else {}
        if not isinstance(self.entries,dict):raise ValueError('INVALID_WORKSPACE_STATE')
        for entry in self.entries.values():
            if entry['state']!='closed' or not entry['cleanup_done']:
                entry.update(state='closing',cleanup_done=False,error_code='SERVICE_RESTART')
            self._runtime(entry)

    @staticmethod
    def _runtime(entry):
        entry.update(sandbox=None,open_task=None,cleanup_task=None,slot=False,close_requested=entry['state']!='opening',
                     commands={},ledger={},fs_guard=asyncio.Lock(),fs_slots=asyncio.Semaphore(4),
                     command_slots=asyncio.Semaphore(4),io_tasks=set())

    @property
    def active_count(self):
        return sum(not entry['cleanup_done'] for entry in self.entries.values())

    def leases(self):
        return {entry['job_id']:{'deadline':entry['deadline']} for entry in self.entries.values()
                if not entry['cleanup_done']}

    def persist(self):
        self.state_path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        atomic_json(self.state_path,{key:{field:entry[field] for field in PERSISTED}
                                    for key,entry in self.entries.items()})

    @staticmethod
    def status(entry):
        return pb.WorkspaceStatus(workspace_id=entry['workspace_id'],state=entry['state'],
                                  working_dir='/workspace',expires_unix_ms=int(entry['deadline']*1000),
                                  cleanup_done=entry['cleanup_done'],error_code=entry['error_code'])

    async def _find(self,value,context,*,require_open=False):
        if not identity(value):await context.abort(grpc.StatusCode.INVALID_ARGUMENT,'INVALID_ID')
        entry=self.entries.get(value)
        if not entry:await context.abort(grpc.StatusCode.NOT_FOUND,'WORKSPACE_NOT_FOUND')
        if require_open:
            if entry['state'] in {'opening','open'} and time.time()>=entry['deadline'] and not entry['cleanup_done']:
                self._request_close(entry,'EXPIRED')
            if entry['state']!='open':await context.abort(grpc.StatusCode.FAILED_PRECONDITION,'WORKSPACE_CLOSED')
        return entry

    async def Open(self,request,context):
        if (not identity(request.request_id) or not 1<=(request.ttl_seconds or 600)<=1800
                or not 128<=(request.memory_mb or 512)<=self.manager.settings.max_memory_mb):
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT,'INVALID_WORKSPACE_LIMIT')
        async with self.guard:
            entry=self.entries.get(request.request_id)
            if entry:
                if entry['state'] not in {'opening','open'}:
                    await context.abort(grpc.StatusCode.FAILED_PRECONDITION,'WORKSPACE_CLOSED')
                if entry['digest']!=digest(request):
                    await context.abort(grpc.StatusCode.ALREADY_EXISTS,'ID_CONFLICT')
            else:
                if not self.manager.healthy():await context.abort(grpc.StatusCode.UNAVAILABLE,'NOT_READY')
                if len(self.entries)>=self.manager.settings.max_history:
                    await context.abort(grpc.StatusCode.RESOURCE_EXHAUSTED,'WORKSPACE_HISTORY_FULL')
                reason=self.manager.admission_reason()
                if reason:await context.abort(grpc.StatusCode.RESOURCE_EXHAUSTED,reason)
                entry={'workspace_id':request.request_id,'request_id':request.request_id,'digest':digest(request),
                       'job_id':'ws_'+hashlib.sha256(request.request_id.encode()).hexdigest()[:56],
                       'state':'opening','deadline':time.time()+(request.ttl_seconds or 600),
                       'cleanup_done':False,'error_code':''}
                self._runtime(entry)
                self.entries[request.request_id]=entry
                self.persist()
                entry['open_task']=asyncio.create_task(self._open(entry,request.memory_mb or 512))
        if entry['open_task']:await asyncio.shield(entry['open_task'])
        if entry['state']!='open':
            await context.abort(grpc.StatusCode.FAILED_PRECONDITION,entry['error_code'] or 'WORKSPACE_CLOSED')
        return self.status(entry)

    async def _open(self,entry,memory):
        try:
            await asyncio.wait_for(self.manager.slots.acquire(),min(30,max(.01,entry['deadline']-time.time())))
            entry['slot']=True
            if entry['close_requested']:return
            entry['phase']='preparing'
            image=await asyncio.to_thread(self.manager.ensure_image,'python')
            preparing=asyncio.create_task(asyncio.to_thread(self.manager.network.prepare,entry['job_id'],[],
                                                         self.manager.test_mode))
            entry['preparing']=preparing
            await asyncio.shield(preparing)
            self.manager.registry();self.manager.leases()
            if entry['close_requested']:return
            entry['phase']='creating'
            creation=asyncio.create_task(Sandbox.create(image,entrypoint=['sleep','infinity'],
                platform=PlatformSpec(os='linux',arch=runtime_architecture()),
                env={'HOME':'/home/sandbox','TMPDIR':'/tmp','LANG':'C.UTF-8','TZ':'UTC'},
                metadata={'lazyx.job':entry['job_id']},resource={'cpu':'1','memory':f'{memory}Mi'},
                timeout=timedelta(seconds=max(1,entry['deadline']-time.time())),
                ready_timeout=timedelta(seconds=90),connection_config=workspace_connection(self.manager.connection)))
            entry['creation']=creation
            entry['sandbox']=await asyncio.shield(creation)
            owned=await asyncio.to_thread(self.manager.client.containers.list,
                                         filters={'label':f"lazyx.job={entry['job_id']}"})
            owned=[container for container in owned if container.labels.get('opensandbox.io/id')==entry['sandbox'].id]
            if len(owned)!=1:raise RuntimeError('INSTANCE_MISMATCH')
            config=owned[0].attrs['HostConfig']
            if (config['Runtime']!='runsc' or not config['ReadonlyRootfs'] or config['Privileged']
                    or config['LogConfig']['Type']!='none' or 'ALL' not in config['CapDrop']):
                raise RuntimeError('PROTECTION_NOT_READY')
            if entry['close_requested'] or time.time()>=entry['deadline']:return
            entry.update(state='open',phase='ready')
            self.persist();self.manager.leases()
        except asyncio.CancelledError:
            entry['error_code']=entry['error_code'] or 'CANCELLED'
        except Exception:
            entry['error_code']='OPEN_FAILED'
        finally:
            if entry['state']!='open' or entry['close_requested']:
                self._request_close(entry,entry['error_code'] or 'CLOSED_DURING_OPEN')

    def _request_close(self,entry,error=''):
        entry['close_requested']=True
        if entry['cleanup_done']:return
        if entry['state']!='closing':
            # Preserve the original hard TTL; give the normal cleaner only a
            # short bounded head start over the independent watchdog.
            entry['deadline']=min(entry['deadline'],time.time()+CLOSE_GRACE_SECONDS)
        entry['state']='closing'
        entry['error_code']=entry['error_code'] or error
        if not entry['cleanup_task'] or entry['cleanup_task'].done():
            entry['cleanup_task']=asyncio.create_task(self._cleanup(entry))
        self.persist()

    async def _cleanup(self,entry):
        opening=entry.get('open_task')
        if opening and opening is not asyncio.current_task() and not opening.done():
            if entry.get('phase') not in {'preparing','creating'}:opening.cancel()
            await asyncio.gather(asyncio.shield(opening),return_exceptions=True)
        for task in list(entry['io_tasks']):
            if task is not asyncio.current_task():task.cancel()
        if entry['io_tasks']:await asyncio.gather(*list(entry['io_tasks']),return_exceptions=True)
        for command in entry['commands'].values():
            if command['state']!='finished':
                command['cancelled']=True
                await self._interrupt(entry,command)
        running=[command['task'] for command in entry['commands'].values() if command.get('task')]
        if running:
            try:await asyncio.wait_for(asyncio.gather(*running,return_exceptions=True),8)
            except TimeoutError:pass
        sandbox=entry.get('sandbox')
        if sandbox:
            try:await asyncio.wait_for(sandbox.destroy(),5)
            except Exception:pass
        try:
            await self.manager.cleanup(entry['job_id'])
        except Exception as error:
            entry['error_code']=entry['error_code'] or 'CLEANUP_PENDING'
            entry['cleanup_failure']=type(error).__name__
            print('[workspace cleanup pending] '+type(error).__name__,flush=True)
            self.persist()
            return
        finally:
            if sandbox:
                try:await sandbox.close()
                except Exception:pass
        entry.update(state='closed',cleanup_done=True,sandbox=None)
        if entry['error_code']=='CLEANUP_PENDING':entry['error_code']=''
        entry['cleanup_failure']=''
        for command in entry['commands'].values():command['stdout'].clear();command['stderr'].clear()
        entry['ledger'].clear()
        if entry['slot']:
            entry['slot']=False;self.manager.slots.release()
        self.persist();self.manager.leases()

    async def Status(self,request,context):
        entry=await self._find(request.workspace_id,context)
        if entry['state'] in {'opening','open'} and not entry['cleanup_done'] and time.time()>=entry['deadline']:
            self._request_close(entry,'EXPIRED')
        return self.status(entry)

    async def Close(self,request,context):
        if not identity(request.workspace_id):await context.abort(grpc.StatusCode.INVALID_ARGUMENT,'INVALID_ID')
        async with self.guard:
            entry=self.entries.get(request.workspace_id)
            if entry is None:
                if len(self.entries)>=self.manager.settings.max_history:
                    # The bounded permanent ledger is full: Open rejects every
                    # unknown ID, so this unknown ID cannot own or create resources.
                    return pb.WorkspaceStatus(workspace_id=request.workspace_id,state='closed',
                                              working_dir='/workspace',cleanup_done=True)
                entry={'workspace_id':request.workspace_id,'request_id':request.workspace_id,'digest':'',
                       'job_id':'ws_'+hashlib.sha256(request.workspace_id.encode()).hexdigest()[:56],
                       'state':'closed','deadline':0,'cleanup_done':True,'error_code':''}
                self._runtime(entry);self.entries[request.workspace_id]=entry;self.persist()
            else:self._request_close(entry)
        if entry['cleanup_task']:await asyncio.shield(entry['cleanup_task'])
        return self.status(entry)

    async def recover(self):
        for entry in self.entries.values():
            if not entry['cleanup_done']:
                self._request_close(entry,'SERVICE_RESTART')
                await asyncio.shield(entry['cleanup_task'])

    async def maintain(self):
        for entry in list(self.entries.values()):
            if not entry['cleanup_done']:
                if entry['state']=='closing':self._request_close(entry)
                elif time.time()>=entry['deadline']:self._request_close(entry,'EXPIRED')

    async def shutdown(self):
        for entry in self.entries.values():self._request_close(entry,'SERVICE_STOP')
        tasks=[entry['cleanup_task'] for entry in self.entries.values() if entry['cleanup_task']]
        if tasks:await asyncio.gather(*tasks,return_exceptions=True)

    async def _filesystem(self,entry,request):
        payload={'op':request.op,'path':request.path,'target':request.target,
                 'data':base64.b64encode(request.data).decode(),'mode':request.mode,
                 'parents':request.parents,'recursive':request.recursive}
        client=entry['sandbox'].files._httpx_client
        response=await client.post('/lazyx/workspace/fs',json=payload,timeout=20)
        response.raise_for_status()
        result=response.json()
        code=result.get('error_code','')
        if code:return pb.FileReply(error_code=code if code in SAFE_ERRORS else 'UNAVAILABLE')
        data=base64.b64decode(result.get('data',''),validate=True)
        entries=result.get('entries',[])
        if len(data)>MAX_FILE or len(entries)>4096:raise ValueError('LIMIT_EXCEEDED')
        return pb.FileReply(data=data,path=result.get('path',''),link_target=result.get('link_target',''),
                            entries=[pb.FileEntry(**item) for item in entries])

    async def Filesystem(self,request,context):
        entry=await self._find(request.workspace_id,context,require_open=True)
        if (request.op not in OPERATIONS or not request.path or len(request.path)>4096
                or '\x00' in request.path or len(request.target)>4096 or '\x00' in request.target):
            return pb.FileReply(error_code='INVALID_PATH')
        if len(request.data)>MAX_FILE:return pb.FileReply(error_code='LIMIT_EXCEEDED')
        mutation=request.op in MUTATIONS
        if mutation and not identity(request.request_id):
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT,'INVALID_REQUEST_ID')
        if mutation:
            async with entry['fs_guard']:
                previous=entry['ledger'].get(request.request_id)
                if previous:
                    if previous[0]!=digest(request):
                        await context.abort(grpc.StatusCode.ALREADY_EXISTS,'ID_CONFLICT')
                    pending=previous[1]
                else:
                    if len(entry['ledger'])>=256:
                        await context.abort(grpc.StatusCode.RESOURCE_EXHAUSTED,'FILESYSTEM_HISTORY_FULL')
                    copy=pb.FileRequest();copy.CopyFrom(request)
                    pending=asyncio.create_task(self._file_operation(entry,copy))
                    entry['io_tasks'].add(pending)
                    pending.add_done_callback(entry['io_tasks'].discard)
                    entry['ledger'][request.request_id]=(digest(request),pending)
            # RPC disconnect does not revoke a mutation or lose its receipt.
            return await asyncio.shield(pending)
        task=asyncio.current_task();entry['io_tasks'].add(task)
        try:return await self._file_operation(entry,request)
        finally:entry['io_tasks'].discard(task)

    async def _file_operation(self,entry,request):
        try:
            async with entry['fs_slots']:
                if entry['state']!='open':return pb.FileReply(error_code='UNAVAILABLE')
                return await self._filesystem(entry,request)
        except asyncio.CancelledError:raise
        except Exception:return pb.FileReply(error_code='UNAVAILABLE')

    @staticmethod
    def command_status(command):
        return pb.CommandReply(command_id=command['command_id'],state=command['state'],
            stdout=bytes(command['stdout']),stderr=bytes(command['stderr']),
            exit_code_available=command['exit_code'] is not None,exit_code=command['exit_code'] or 0,
            timed_out=command['timed_out'],cancelled=command['cancelled'],
            output_truncated=command['output_truncated'],error_code=command['error_code'],
            output_complete=command['output_complete'])

    async def StartCommand(self,request,context):
        entry=await self._find(request.workspace_id,context,require_open=True)
        invalid=(not identity(request.request_id) or not 1<=(request.timeout_seconds or 120)<=120
                 or request.output_limit_bytes>MAX_OUTPUT or len(request.argv)>128
                 or sum(len(value) for value in request.argv)+len(request.shell_command)>65536
                 or bool(request.argv)==bool(request.shell_command)
                 or request.shell and bool(request.argv) or not request.shell and bool(request.shell_command)
                 or len(request.cwd)>4096 or '\x00' in request.cwd)
        for name,value in request.env.items():
            if (not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,63}',name) or len(value)>4096 or '\x00' in value
                    or re.search(r'(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|EXECD|PROXY|LD_PRELOAD|LD_LIBRARY_PATH|PYTHONPATH)',name,re.I)):
                invalid=True
        if len(request.env)>32 or any('\x00' in value for value in request.argv) or '\x00' in request.shell_command:invalid=True
        if invalid:await context.abort(grpc.StatusCode.INVALID_ARGUMENT,'INVALID_COMMAND')
        command=entry['commands'].get(request.request_id)
        if command:
            if command['digest']!=digest(request):await context.abort(grpc.StatusCode.ALREADY_EXISTS,'ID_CONFLICT')
        else:
            if len(entry['commands'])>=MAX_COMMANDS or sum(len(c['stdout'])+len(c['stderr']) for c in entry['commands'].values())>=MAX_CACHED_OUTPUT:
                await context.abort(grpc.StatusCode.RESOURCE_EXHAUSTED,'COMMAND_HISTORY_FULL')
            command={'command_id':request.request_id,'digest':digest(request),'state':'starting','stdout':bytearray(),
                     'stderr':bytearray(),'exit_code':None,'timed_out':False,'cancelled':False,'output_truncated':False,
                     'error_code':'','output_complete':False,'execution_id':None,'task':None,'started':asyncio.Event()}
            entry['commands'][request.request_id]=command
            copy=pb.CommandRequest();copy.CopyFrom(request)
            command['task']=asyncio.create_task(self._run(entry,command,copy))
        try:await asyncio.wait_for(command['started'].wait(),5)
        except TimeoutError:pass
        return self.command_status(command)

    async def _interrupt(self,entry,command):
        if command.get('execution_id') and entry.get('sandbox'):
            try:await asyncio.wait_for(entry['sandbox'].commands.interrupt(command['execution_id']),3)
            except Exception:command['error_code']='INTERRUPT_UNCONFIRMED'

    async def _run(self,entry,command,request):
        timeout=request.timeout_seconds or 120
        limit=request.output_limit_bytes or MAX_OUTPUT
        async def capture(message,channel):
            raw=decode_output(message.text)
            cached=sum(len(c['stdout'])+len(c['stderr']) for c in entry['commands'].values())
            remaining=max(0,min(limit-len(command[channel]),MAX_CACHED_OUTPUT-cached))
            command[channel].extend(raw[:remaining])
            if len(raw)>remaining:
                command['output_truncated']=True
                command['error_code']='OUTPUT_LIMIT'
                await self._interrupt(entry,command)
        async def stdout(message):await capture(message,'stdout')
        async def stderr(message):await capture(message,'stderr')
        async def initialized(value):
            command['execution_id']=value.id
            command['state']='running';command['started'].set()
            if command['cancelled'] or entry['close_requested']:await self._interrupt(entry,command)
        stream=None
        try:
            async with entry['command_slots']:
                if command['cancelled'] or entry['close_requested']:return
                argv=(['/bin/sh','-lc',request.shell_command] if request.shell else
                      ['/usr/local/bin/python','-I','-c',ARGV_TRAMPOLINE,'--',*request.argv])
                stream=asyncio.create_task(entry['sandbox'].commands.run(argv,
                    opts=RunCommandOpts(uid=1000,gid=1000,working_directory=request.cwd or '/workspace',
                        timeout=timedelta(seconds=120),envs=dict(request.env)|{'TMPDIR':'/tmp'}),
                    handlers=ExecutionHandlers(on_stdout=stdout,on_stderr=stderr,on_init=initialized,skip_accumulation=True)))
                done,_=await asyncio.wait({stream},timeout=timeout)
                if not done:
                    command['timed_out']=True;await self._interrupt(entry,command)
                try:
                    await asyncio.wait_for(asyncio.shield(stream),5)
                    command['output_complete']=not command['output_truncated']
                except TimeoutError:
                    command['error_code']='COMMAND_STOP_UNCONFIRMED';stream.cancel()
                if command['execution_id']:
                    status=await entry['sandbox'].commands.get_command_status(command['execution_id'])
                    if status.running is False and status.exit_code is not None:
                        command['exit_code']=status.exit_code
                    else:command['error_code']=command['error_code'] or 'EXIT_CODE_UNAVAILABLE'
        except asyncio.CancelledError:
            command['cancelled']=True;await self._interrupt(entry,command)
            if stream:stream.cancel()
        except TimeoutError:
            command['timed_out']=True;await self._interrupt(entry,command)
            command['error_code']=command['error_code'] or 'COMMAND_TIMEOUT'
        except Exception:
            command['error_code']=command['error_code'] or 'EXECUTION_UNAVAILABLE'
        finally:
            command['state']='finished';command['started'].set()

    async def PollCommand(self,request,context):
        entry=await self._find(request.workspace_id,context)
        command=entry['commands'].get(request.command_id)
        if not command:await context.abort(grpc.StatusCode.NOT_FOUND,'COMMAND_NOT_FOUND')
        return self.command_status(command)

    async def CancelCommand(self,request,context):
        entry=await self._find(request.workspace_id,context)
        if not identity(request.command_id):await context.abort(grpc.StatusCode.INVALID_ARGUMENT,'INVALID_ID')
        command=entry['commands'].get(request.command_id)
        if command is None:
            if len(entry['commands'])>=MAX_COMMANDS:
                await context.abort(grpc.StatusCode.RESOURCE_EXHAUSTED,'COMMAND_HISTORY_FULL')
            command={'command_id':request.command_id,'digest':'','state':'finished','stdout':bytearray(),'stderr':bytearray(),
                     'exit_code':None,'timed_out':False,'cancelled':True,'output_truncated':False,
                     'error_code':'NOT_STARTED','output_complete':True,'execution_id':None,'task':None,
                     'started':asyncio.Event()}
            command['started'].set();entry['commands'][request.command_id]=command
        elif command['state']!='finished':
            command['cancelled']=True
            await self._interrupt(entry,command)
        return self.command_status(command)
