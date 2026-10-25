"""SB3 公共依赖环境：单构建并发、不可变镜像、有限本地缓存。"""
import asyncio
import base64
from collections import Counter
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile
import threading
import time
import uuid

import docker
from .runtime_adapter import harden_host_config
from .watchdog import atomic_json, read_private_json

STATE = Path('/var/lib/sandbox_model/environments.json')
LOCKS = Path('/var/lib/sandbox_model/environment-locks')
REGISTRY = Path('/run/sandbox_model/environment-images.json')
LIMIT = 128 * 1024 * 1024
BUILD_SECONDS = 300
MAX_ENTRIES = 8
MAX_LOCKS = 128
MAX_CACHE_BYTES = 512 * 1024 * 1024
SOURCES = ('pypi.org', 'files.pythonhosted.org', 'registry.npmjs.org')


def declaration(environment, values):
    """规范化精确版本声明，并拒绝范围版本、任意 URL 和同名版本冲突。"""
    if not values:
        return []
    if environment not in ('python', 'node') or len(values) > 32:
        raise ValueError('UNSUPPORTED_DEPENDENCIES')
    result = {}
    for item in values:
        if not isinstance(item,str) or len(item) > 180:
            raise ValueError('INVALID_DEPENDENCY')
        if environment == 'python':
            match = re.fullmatch(r'([A-Za-z0-9][A-Za-z0-9_.-]*)==([0-9][A-Za-z0-9.!+-]{0,63})', item)
            if not match:
                raise ValueError('DEPENDENCY_EXACT_VERSION_REQUIRED')
            name, version = re.sub(r'[-_.]+', '-', match[1]).lower(), match[2]
            value = name + '==' + version
        else:
            match = re.fullmatch(r'((?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*)@([0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?(?:\+[A-Za-z0-9.-]+)?)', item)
            if not match:
                raise ValueError('DEPENDENCY_EXACT_VERSION_REQUIRED')
            name, version = match[1], match[2]
            value = name + '@' + version
        if name in result and result[name] != value:
            raise ValueError('DEPENDENCY_CONFLICT')
        result[name] = value
    return sorted(result.values())


def fingerprint(value):
    # 字段顺序不影响摘要，相同声明能复用同一个环境标识。
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',',':')).encode()).hexdigest()


def checked_context(raw, base, key):
    """只重新打包受限依赖目录，永不将不可信 tar 解压到宿主文件系统。"""
    total, seen, lock = 0, set(), None
    output = io.BytesIO()
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as source, tarfile.open(fileobj=output, mode='w') as target:
        members = source.getmembers()
        if len(members) > 20000:
            raise ValueError('BUILD_EXPORT_LIMIT')
        for member in members:
            path = PurePosixPath(member.name)
            if (not member.name.startswith('env/') or path.is_absolute() or '..' in path.parts
                    or str(path) != member.name or member.name in seen or len(member.name) > 1024
                    or any(ord(c)<32 for c in member.name) or '\\' in member.name
                    or member.mode & 0o6000 or member.size < 0):
                raise ValueError('BUILD_EXPORT_UNSAFE_PATH')
            seen.add(member.name)
            if not (member.isfile() or member.isdir() or member.issym()):
                raise ValueError('BUILD_EXPORT_SPECIAL_FILE')
            if member.issym():
                # 相对链接必须始终位于 env 内；后续也拒绝通过链接父目录放置文件。
                parts = list(path.parent.parts)
                if not member.linkname or member.linkname.startswith('/') or '\\' in member.linkname:
                    raise ValueError('BUILD_EXPORT_UNSAFE_LINK')
                for part in PurePosixPath(member.linkname).parts:
                    if part == '..':
                        if len(parts) <= 1:raise ValueError('BUILD_EXPORT_UNSAFE_LINK')
                        parts.pop()
                    elif part != '.':parts.append(part)
            total += member.size
            if total > LIMIT:
                raise ValueError('BUILD_EXPORT_LIMIT')
            clean = tarfile.TarInfo(member.name)
            clean.type, clean.linkname = member.type, member.linkname
            clean.mode = 0o755 if member.isdir() or member.mode & 0o111 else 0o644
            clean.size = member.size if member.isfile() else 0
            content = source.extractfile(member) if member.isfile() else None
            if member.name == 'env/lock.json':
                if not member.isfile() or member.size > 1024*1024:raise ValueError('BUILD_LOCK_INVALID')
                payload = content.read()
                lock = json.loads(payload)
                content = io.BytesIO(payload)
            target.addfile(clean, content)
        symlinks = {m.name for m in members if m.issym()}
        if any(str(parent) in symlinks for m in members for parent in PurePosixPath(m.name).parents):
            raise ValueError('BUILD_EXPORT_UNSAFE_LINK')
        if not isinstance(lock,dict) or lock.get('language') not in ('python','node'):
            raise ValueError('BUILD_LOCK_INVALID')
        environment_id = fingerprint({'key':key,'lock':lock})
        dockerfile = (f'FROM {base}\nCOPY env/ /opt/env/\n'
                      f'LABEL lazyx.environment="{environment_id}" lazyx.environment.request="{key}"\n').encode()
        entry = tarfile.TarInfo('Dockerfile'); entry.size = len(dockerfile)
        target.addfile(entry,io.BytesIO(dockerfile))
    return output.getvalue(), environment_id, total, lock


def validate_lock(spec, lock):
    # 从构建容器返回的锁文件仍不可信，须核对显式依赖、包源和完整性字段。
    from .build_guest import public_url
    if lock.get('language') != spec['environment']:raise ValueError('BUILD_LOCK_INVALID')
    replay = {'environment':spec['environment'],'dependencies':spec['dependencies'],'lock':lock}
    if len(base64.b64encode(json.dumps(replay).encode()))>100000:raise ValueError('BUILD_LOCK_TOO_LARGE')
    if lock['language']=='python':
        packages = lock.get('packages',[])
        if not 0 < len(packages) <= 256:raise ValueError('BUILD_LOCK_INVALID')
        versions = {}
        for package in packages:
            normalized = declaration('python',[package['name']+'=='+package['version']])[0]
            name,version = normalized.split('==')
            if name in versions or not re.fullmatch(r'[0-9a-f]{64}',package['sha256']):raise ValueError('BUILD_LOCK_INVALID')
            versions[name] = version
            public_url(package['url'])
        for item in spec['dependencies']:
            name,version = item.split('==')
            if versions.get(name)!=version:raise ValueError('BUILD_LOCK_MISMATCH')
    else:
        packages = lock.get('lockfile',{}).get('packages',{})
        expected = dict(item.rsplit('@',1) for item in spec['dependencies'])
        if not 1 < len(packages) <= 256 or packages.get('',{}).get('dependencies')!=expected:
            raise ValueError('BUILD_LOCK_MISMATCH')
        for name,package in packages.items():
            if not name:continue
            if not name.startswith('node_modules/') or '..' in PurePosixPath(name).parts or package.get('link'):
                raise ValueError('BUILD_LOCK_INVALID')
            if not package.get('integrity','').startswith('sha512-'):raise ValueError('BUILD_LOCK_INVALID')
            public_url(package.get('resolved',''))


class Environments:
    """管理公共依赖镜像；缓存只包含依赖，不包含任务输入和业务产物。"""
    def __init__(self, manager):
        self.manager = manager
        self.client = manager.client
        self.entries = read_private_json(STATE) if STATE.exists() else {}
        self.pending = {}
        # 在途任务固定住环境条目，缓存淘汰时跳过仍被使用的镜像。
        self.pins = Counter()
        self.guard = asyncio.Lock()
        self.slot = asyncio.Semaphore(1)
        self.active = {}  # 构建租约与普通任务一起交给独立回收器。
        self.counters = Counter(cache_hits=0, cache_misses=0, builds_succeeded=0,
                                builds_failed=0, builds_cancelled=0, build_duration_ms=0)
        self.register()

    def recover(self):
        # 服务启动先清理旧任务，再回收没有正式登记的本项目镜像。
        for directory in Path('/run/sandbox_model').glob('build-*'):
            if directory.is_dir() and not directory.is_symlink():shutil.rmtree(directory)
        retained = {x['image_id'] for x in self.entries.values()}
        for image in self.client.images.list(filters={'label':'lazyx.environment'}):
            if image.id not in retained and any(t.startswith('sandbox-public-env:') for t in image.tags):
                self.client.images.remove(image.id,force=False,noprune=False)

    def register(self):
        atomic_json(REGISTRY, sorted({x['image_id'] for x in self.entries.values() if x['image_id']}))

    def persist(self):
        atomic_json(STATE, self.entries)
        self.register()

    def valid(self, entry):
        # 用不可变镜像 ID 和标签核对缓存，不能只凭可被重新指向的镜像名称。
        if not entry.get('image_id'):return False
        try:
            image = self.client.images.get(entry['image_id'])
            return (image.id == entry['image_id'] and image.labels.get('lazyx.runtime') == 'sb0-v1'
                    and image.labels.get('lazyx.environment') == entry['environment_id'])
        except docker.errors.ImageNotFound:
            return False

    async def ensure(self, job, base):
        # 构建模板、基础镜像和架构都参与键计算，避免复用不兼容的依赖环境。
        request = job['spec']
        deps = declaration(request.environment,list(request.dependencies))
        builder = await asyncio.to_thread(self.client.images.get, 'sandbox-model-builder:sb3')
        spec = {'environment':request.environment,'dependencies':deps,'base':base,'builder':builder.id,
                'platform':'linux/arm64','template':'sb3-v1','sources':SOURCES}
        key = fingerprint(spec)
        job['environment_key'] = key
        self.pins[key] += 1
        async with self.guard:
            entry = self.entries.get(key)
            if not entry and len(self.entries)>=MAX_LOCKS:raise ValueError('ENVIRONMENT_CATALOG_FULL')
            if entry:
                try:
                    lock = read_private_json(LOCKS / (entry['environment_id']+'.json'))
                    if (fingerprint(lock) != entry['lock_sha256'] or
                            fingerprint({'key':key,'lock':lock}) != entry['environment_id']):
                        raise ValueError('BUILD_LOCK_INVALID')
                    validate_lock(spec,lock)
                except (ValueError,KeyError,TypeError,OSError):
                    raise ValueError('BUILD_LOCK_INVALID') from None
            if entry and await asyncio.to_thread(self.valid, entry):
                self.counters['cache_hits'] += 1
                entry['used'] = time.time(); self.persist()
                job['environment_id'] = entry['environment_id']; job['environment_cache_hit'] = True
                print(f"[环境缓存] 已命中，任务：{job['request_id']}", flush=True)
                return entry['image_id']
            if entry:spec['lock'] = lock
            self.counters['cache_misses'] += 1
            pending = self.pending.get(key)
            # 同一组合共享一次构建；取消某个等待任务不会影响其他等待者。
            if pending is None:
                cancel = threading.Event()
                task = asyncio.create_task(self.build(key,spec,cancel))
                pending = self.pending[key] = {'task':task,'cancel':cancel,'waiters':0}
            pending['waiters'] += 1
        try:
            # shield 让调用方取消只退出等待，最后一个等待者负责通知构建取消。
            entry = await asyncio.shield(pending['task'])
            job['environment_id'] = entry['environment_id']
            return entry['image_id']
        finally:
            async with self.guard:
                pending['waiters'] -= 1
                if pending['waiters'] == 0:
                    if not pending['task'].done():pending['cancel'].set()
            if pending['waiters'] == 0:
                # 取消 asyncio 调用不会终止 Docker exec，等待受限构建完成清理。
                try:await asyncio.shield(pending['task'])
                except Exception:pass
                async with self.guard:
                    if self.pending.get(key) is pending:self.pending.pop(key,None)

    def release(self, job):
        # 任务清理结束后释放引用，镜像才可以被缓存淘汰逻辑选中。
        key = job.pop('environment_key',None)
        if key:
            self.pins[key] -= 1
            if self.pins[key] <= 0:del self.pins[key]

    def prune(self, incoming=0, replacing=None):
        def occupied():return [x for k,x in self.entries.items() if k!=replacing and x.get('image_id')]
        for key, entry in sorted(list(self.entries.items()),key=lambda pair:pair[1]['used']):
            if len(occupied()) < MAX_ENTRIES and sum(x['bytes'] for x in occupied())+incoming <= MAX_CACHE_BYTES:
                break
            if self.pins[key] or not entry.get('image_id'):continue
            if self.valid(entry):self.client.images.remove(entry['image_id'],force=False,noprune=False)
            # 清理镜像保留原锁：以后请求该组合仍按原间接依赖重建。
            entry.update(image_id='',bytes=0)
        if len(occupied()) >= MAX_ENTRIES or sum(x['bytes'] for x in occupied())+incoming > MAX_CACHE_BYTES:
            raise ValueError('ENVIRONMENT_CACHE_FULL')

    async def build(self, key, spec, cancel):
        # 安装与镜像封装共享单个构建槽，限制构建对节点内存的峰值占用。
        # 排队构建也能及时取消，不能等前一个安装结束后才处理。
        while True:
            if cancel.is_set():raise ValueError('ENVIRONMENT_BUILD_CANCELLED')
            try:
                await asyncio.wait_for(self.slot.acquire(),.2)
                break
            except asyncio.TimeoutError:pass
        ident = 'build_' + uuid.uuid4().hex
        entry = None
        started = time.monotonic()
        outcome = 'builds_failed'
        try:
            if cancel.is_set():raise ValueError('ENVIRONMENT_BUILD_CANCELLED')
            self.active[ident] = {'deadline':time.time()+BUILD_SECONDS+30}
            self.manager.leases()
            entry = await asyncio.to_thread(self.build_sync,ident,key,spec,cancel)
            await self.manager.cleanup(ident)
            self.active.pop(ident,None)
            async with self.guard:
                if cancel.is_set():raise ValueError('ENVIRONMENT_BUILD_CANCELLED')
                await asyncio.to_thread(self.prune,entry['bytes'],key)
                lock = entry.pop('lock')
                # 只有镜像验证和构建资源清理都完成，才登记锁文件与缓存条目。
                LOCKS.mkdir(mode=0o700,parents=True,exist_ok=True)
                atomic_json(LOCKS / (entry['environment_id']+'.json'),lock)
                self.entries[key] = entry
                self.persist()
            outcome = 'builds_succeeded'
            return entry
        finally:
            try:
                if entry and self.entries.get(key) is not entry:
                    try:await asyncio.to_thread(self.client.images.remove,entry['image_id'],force=False)
                    except docker.errors.ImageNotFound:pass
                if ident in self.active:
                    try:
                        await self.manager.cleanup(ident)
                    except Exception:
                        self.active[ident]['deadline'] = 0
                        raise
                    else:self.active.pop(ident,None)
            finally:
                self.counters['builds_cancelled' if cancel.is_set() else outcome] += 1
                self.counters['build_duration_ms'] += int((time.monotonic()-started)*1000)
                self.slot.release()

    def command(self, args, cancel, deadline, directory, *, cap=LIMIT+8*1024*1024, env=None):
        # 命令输出有界保留在节点 RAM；轮询同时响应取消、超时和输出超限。
        path = directory/'command.out'
        with path.open('wb') as stream:
            process = subprocess.Popen(args,stdout=stream,stderr=subprocess.DEVNULL,env=env)
        try:
            while process.poll() is None:
                if cancel.is_set():raise ValueError('ENVIRONMENT_BUILD_CANCELLED')
                if time.monotonic() >= deadline:raise ValueError('ENVIRONMENT_BUILD_TIMEOUT')
                if path.stat().st_size > cap:raise ValueError('BUILD_EXPORT_LIMIT')
                time.sleep(.1)
            if path.stat().st_size > cap:raise ValueError('BUILD_EXPORT_LIMIT')
            if process.returncode:
                code = path.read_bytes()[-256:].decode(errors='ignore').strip()
                if not re.fullmatch(r'(DEPENDENCY|BUILD)_[A-Z_]+',code):code = 'ENVIRONMENT_BUILD_FAILED'
                raise ValueError(code)
            return path.read_bytes()
        finally:
            if process.poll() is None:
                process.terminate()
                try:process.wait(timeout=3)
                except subprocess.TimeoutExpired:process.kill();process.wait()
            path.unlink(missing_ok=True)

    def container(self, image, ident, ctx, *, builder=False):
        # 构建容器与验证容器都沿用任务隔离约束，不开放宿主挂载和网关调用。
        options = {'mem_limit':1024*1024*1024,'nano_cpus':1000000000,'network_mode':ctx.name}
        harden_host_config(options)
        options.pop('port_bindings',None)
        if builder:
            options['tmpfs']['/opt/env'] = 'rw,nosuid,nodev,exec,size=256m,mode=0700,uid=1000,gid=1000'
            options['tmpfs']['/tmp'] = 'rw,nosuid,nodev,exec,size=128m,mode=1777'
        info = self.client.api.create_container(image, command=['infinity'],entrypoint=['sleep'],user='0:0',
            name=ident,labels={'lazyx.sb':'true','lazyx.job':ident,'lazyx.build':'true'},
            environment={k:v for k,v in ctx.env.items() if k!='LAZYX_GATEWAY'} | {'HOME':'/home/sandbox','TMPDIR':'/tmp','PYTHONDONTWRITEBYTECODE':'1'},
            host_config=self.client.api.create_host_config(**options),
            networking_config=self.client.api.create_networking_config({ctx.name:self.client.api.create_endpoint_config(ipv4_address=ctx.guest_ip)}))
        container = self.client.containers.get(info['Id']); container.start(); container.reload()
        host = container.attrs['HostConfig']
        if host['Runtime']!='runsc' or not host['ReadonlyRootfs'] or host.get('Binds') or host['Privileged']:
            raise ValueError('BUILD_PROTECTION_NOT_READY')
        return container

    def build_sync(self, ident, key, spec, cancel):
        """隔离安装、停止安装进程、撤网、校验导出，再封装和试运行环境镜像。"""
        from .service import STOP_TASKS
        deadline = time.monotonic()+BUILD_SECONDS
        print(f'[环境构建] 开始隔离安装，构建：{ident}',flush=True)
        container = None; image_id = None; published = False
        with tempfile.TemporaryDirectory(prefix='build-',dir='/run/sandbox_model') as temporary:
            directory = Path(temporary)
            try:
                ctx = self.manager.network.prepare(ident,SOURCES,True,public_build=True)
                container = self.container(spec['builder'],ident,ctx,builder=True)
                encoded = base64.b64encode(json.dumps({k:v for k,v in spec.items() if k in ('environment','dependencies','lock')}).encode()).decode()
                if len(encoded)>100000:raise ValueError('BUILD_LOCK_TOO_LARGE')
                try:
                    self.command(['docker','exec','--user','1000:1000',ident,'python','-I','/opt/platform/build_guest.py',encoded],cancel,deadline,directory,cap=65536)
                except ValueError:
                    self.command(['docker','exec',ident,'python','-I','-c',STOP_TASKS],
                        threading.Event(),time.monotonic()+5,directory,cap=1024)
                    # 最近一次公共依赖安装诊断，仅有界保留在节点 RAM，不进入普通日志。
                    diagnostic = self.command(['docker','exec',ident,'python','-I','-c',
                        "from pathlib import Path; import sys; p=Path('/tmp/install.log'); sys.stdout.buffer.write(p.read_bytes()[-32768:] if p.is_file() and not p.is_symlink() else b'')"],
                        threading.Event(),time.monotonic()+5,directory,cap=32768)
                    path = Path('/run/sandbox_model/build-last.log');path.write_bytes(diagnostic);path.chmod(0o600)
                    raise
                self.command(['docker','exec',ident,'python','-I','-c',STOP_TASKS],cancel,deadline,directory,cap=1024)
                # 先停止包安装脚本并撤销出网，避免导出期间依赖目录继续变化。
                self.manager.network.revoke(ident)
                raw = self.command(['docker','exec',ident,'python','-I','/opt/platform/build_guest.py','export'],cancel,deadline,directory)
                context, environment_id, size, lock = checked_context(raw,spec['base'],key)
                del raw
                validate_lock(spec,lock)
                if spec.get('lock') and lock != spec['lock']:raise ValueError('BUILD_LOCK_CHANGED')
                archive = directory/'context.tar'; archive.write_bytes(context); del context
                container.remove(force=True); container=None
                base_config = self.client.images.get(spec['base']).attrs.get('Config',{})
                if base_config.get('OnBuild') or base_config.get('Volumes'):
                    raise ValueError('BUILD_BASE_UNSAFE')
                tag = 'sandbox-public-env:' + environment_id
                print(f'[环境构建] 校验通过，正在封装镜像，构建：{ident}',flush=True)
                # 固定版本 Docker 的经典构建器只执行 FROM/COPY/LABEL，不产生 BuildKit 长期缓存。
                with archive.open('rb') as source, (directory/'build.out').open('wb') as output:
                    process = subprocess.Popen(['docker','build','--no-cache','--force-rm','-q','-t',tag,'-'],
                        stdin=source,stdout=output,stderr=subprocess.DEVNULL,env=os.environ|{'DOCKER_BUILDKIT':'0'})
                try:
                    while process.poll() is None:
                        if cancel.is_set() or time.monotonic()>deadline:raise ValueError('ENVIRONMENT_BUILD_CANCELLED')
                        time.sleep(.1)
                    if process.returncode:raise ValueError('IMAGE_ASSEMBLY_FAILED')
                finally:
                    if process.poll() is None:
                        process.terminate()
                        try:process.wait(timeout=3)
                        except subprocess.TimeoutExpired:process.kill();process.wait()
                image = self.client.images.get(tag); image_id=image.id
                if image.labels.get('lazyx.environment')!=environment_id:raise ValueError('IMAGE_MISMATCH')
                container = self.container(image_id,ident,ctx)
                # 在同等隔离条件下检查解释器能够启动，通过后才允许发布环境。
                check = "import sys; assert sys.version_info[:2]==(3,12)" if spec['environment']=='python' else "console.log(process.version)"
                command = ['/opt/env/python/bin/python','-c',check] if spec['environment']=='python' else ['node','-e',check]
                self.command(['docker','exec','--user','1000:1000',ident,*command],cancel,deadline,directory,cap=65536)
                published=True
                print(f'[环境构建] 新镜像验证完成，构建：{ident}',flush=True)
                return {'image_id':image_id,'environment_id':environment_id,'used':time.time(),'bytes':size,
                        'spec':{k:v for k,v in spec.items() if k!='lock'},'lock_sha256':fingerprint(lock),'lock':lock}
            finally:
                if container:
                    container.remove(force=True)
                if image_id and not published:
                    self.client.images.remove(image_id,force=False)
