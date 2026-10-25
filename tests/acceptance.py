"""专用 Linux 节点的真实 gRPC → OpenSandbox → gVisor 集成验收。

仅使用合成数据。报告保存检查结果与计量，不保存任务正文或密钥。
每个未执行/失败用例都不能标记通过；默认全部验收，末尾故障测试会停止服务。
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import errno
import hashlib
import io
import json
import logging
logging.disable(logging.CRITICAL)
import mmap
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
import uuid
import zipfile

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / 'src'))
import docker
import grpc
from sandbox_model import client
from sandbox_model.network import NetworkManager
from sandbox_model.proto import sandbox_pb2 as pb
from sandbox_model.watchdog import read_private_json

RUN = Path('/run/sandbox_model')
FIXTURES = PROJECT / 'tests' / 'fixtures'
SUCCEEDED = {'success', 'succeeded'}
FINISHED = SUCCEEDED | {'failed', 'cancelled', 'canceled', 'unknown', 'timeout', 'revoked', 'needs_approval'}


def require(value, message='检查条件不满足'):
    if not value:
        raise AssertionError(message)


def input_file(path, data):
    return pb.InputFile(path=path, data=data, sha256=hashlib.sha256(data).hexdigest())


def fixture_inputs(name):
    root = FIXTURES / name
    return [input_file(str(path.relative_to(FIXTURES)), path.read_bytes()) for path in sorted(root.rglob('*')) if path.is_file() and '__pycache__' not in path.parts]


class Acceptance:
    def __init__(self, include_faults=True):
        self.started = datetime.now(timezone.utc).isoformat()
        self.completed = False
        self.checks = []
        self.include_faults = include_faults
        self.channels = {}
        self.stubs = {}
        for owner in ('alice', 'bob'):
            self.channels[owner], self.stubs[owner] = client.connect()
            grpc.channel_ready_future(self.channels[owner]).result(timeout=30)
        self.docker = docker.from_env()
        self.network_audit = NetworkManager(self.docker, run_dir=str(RUN))
        self.ids = []
        self.scan_evidence = {}
        self.runtime_evidence = {}

    def check(self, name, callback):
        start = time.monotonic()
        result = None
        entry = {'name': name, 'passed': False}
        try:
            result = callback()
            if result is False:
                raise AssertionError('检查返回失败')
            entry['passed'] = True
        except Exception as error:
            # 不将gRPC错误正文、脚本输出、任务路径或凭据复制到节点报告。
            entry['error'] = type(error).__name__
            if isinstance(error, grpc.RpcError):
                entry['rpc_code'] = error.code().name
            elif isinstance(error, AssertionError):
                entry['reason'] = str(error)[:160]
        entry['elapsed_ms'] = int((time.monotonic() - start) * 1000)
        self.checks.append(entry)
        print(f"[{'通过' if entry['passed'] else '失败'}] {name}", flush=True)
        self.save()
        return result

    def save(self):
        RUN.mkdir(parents=True, exist_ok=True)
        report = {'schema_version': 1, 'started_at': self.started,
                  'updated_at': datetime.now(timezone.utc).isoformat(),
                  'passed': self.completed and bool(self.checks) and all(item['passed'] for item in self.checks),
                  'completed': self.completed,
                  'checks': self.checks, 'runtime': self.runtime_evidence,
                  'disk_scan': self.scan_evidence,
                  'scope': '合成输入、真实OpenSandbox/gVisor与免认证接口；不等同生产产品接入',
                  'destructive_faults_requested': self.include_faults}
        (RUN / 'report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')

    def request(self, kind='code', owner='alice', **fields):
        req = pb.TaskRequest(request_id='check_' + uuid.uuid4().hex[:20], kind=kind,
                             environment='python', memory_mb=512, timeout_seconds=60)
        if kind == 'code':
            req.code = b"print('synthetic result')\n"
        for key, value in fields.items():
            if key in ('inputs', 'network_domains', 'dependencies'):
                getattr(req, key).extend(value)
            elif key == 'environment_variables':
                req.environment_variables.update(value)
            else:
                setattr(req, key, value)
        return req

    def submit(self, req, owner='alice'):
        self.ids.append(req.request_id)
        return self.stubs[owner].Submit(req, timeout=15)

    def wait(self, req, owner='alice', seconds=150):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            try:
                status = self.stubs[owner].Status(pb.JobRef(request_id=req.request_id), timeout=5)
            except grpc.RpcError as error:
                if error.code()!=grpc.StatusCode.UNAVAILABLE:raise
                time.sleep(.2);continue
            if status.outcome in FINISHED and status.cleanup_done:
                return status
            time.sleep(.2)
        raise AssertionError('任务或清理未在验收期限内结束')

    def result(self, req, owner='alice', success=True):
        status = self.wait(req, owner)
        require(status.cleanup_done, '资源清理未完成')
        result = self.stubs[owner].Result(pb.JobRef(request_id=req.request_id), timeout=15)
        if success:
            require(result.status.outcome in SUCCEEDED, '任务没有成功')
        else:
            require(result.status.outcome not in SUCCEEDED, '应拒绝/失败的任务却成功')
        require(result.status.cleanup_done, '结果中的清理状态不成立')
        for artifact in result.artifacts:
            require(hashlib.sha256(artifact.data).hexdigest() == artifact.sha256, '产物摘要不匹配')
        if hasattr(self.stubs[owner], 'Acknowledge'):
            self.stubs[owner].Acknowledge(pb.JobRef(request_id=req.request_id), timeout=10)
        return result

    def run(self, kind='code', owner='alice', success=True, **fields):
        req = self.request(kind, owner, **fields)
        self.submit(req, owner)
        return self.result(req, owner, success)

    @staticmethod
    def artifact(result, name):
        matches = [item.data for item in result.artifacts if item.path == name]
        require(len(matches) == 1, '没有找到唯一的预期产物')
        return matches[0]

    def guest(self, req, seconds=40):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            candidates = self.docker.containers.list(all=True, filters={'label': f'lazyx.job={req.request_id}'})
            guests = [item for item in candidates if item.name.startswith('sandbox-')]
            if len(guests) == 1 and guests[0].status == 'running':
                guests[0].reload()
                return guests[0]
            time.sleep(.1)
        raise AssertionError('找不到实际执行沙箱')

    def denied(self, call, accepted_codes=None):
        try:
            call()
        except grpc.RpcError as error:
            if accepted_codes:
                require(error.code() in accepted_codes, '返回的拒绝类别不符合约定')
            return True
        raise AssertionError('应拒绝的接口调用却被接受')

    def no_resources(self, job_ids):
        for job_id in job_ids:
            remaining = self.network_audit.remaining_resources(job_id)
            remaining['containers'] = len(self.docker.containers.list(all=True, filters={'label': f'lazyx.job={job_id}'}))
            proof = self.runtime_evidence.setdefault('cleanup', {})
            proof[job_id] = proof.get(job_id, {}) | remaining
            require(remaining == {'networks':0, 'rules':0, 'containers':0}, '任务容器、网络或iptables规则残留')
        return True

    def initial_security(self):
        self.check('gRPC服务就绪且为测试模式', lambda: self.ready())
        self.check('无证书无执行许可可以提交任务', lambda:self.run())
        for label, mutator in (
            ('输入摘要不匹配', lambda request: self.bad_input(request)),
            ('输入路径越界', lambda request: self.path_input(request)),
            ('未登记执行环境', lambda request: self.unknown_environment(request)),
            ('输入超过1MiB', lambda request: self.change_and_sign(request, code=b'#' * (1024 * 1024 + 1))),
            ('内存限制越界', lambda request: self.change_and_sign(request, memory_mb=2048)),
            ('执行时限越界', lambda request: self.change_and_sign(request, timeout_seconds=121)),
            ('域名通配符', lambda request: self.change_and_sign(request, network_domains=['*.allowed.test'])),
            ('静态审核请求联网', lambda request: self.change_and_sign(request, kind='audit', entrypoint='inputs/skill_ok', network_domains=['allowed.test'])),
            ('真实密钥字段环境变量', lambda request: self.change_and_sign(request, environment_variables={'API_KEY':'<REDACTED>'})),
            ('改写代理环境变量', lambda request: self.change_and_sign(request, environment_variables={'HTTPS_PROXY':'http://unapproved.test:3128'})),
            ('非预设普通环境变量值', lambda request: self.change_and_sign(request, environment_variables={'TZ':'arbitrary'})),
        ):
            def reject(mutator=mutator):
                req = self.request()
                mutator(req)
                self.denied(lambda: self.stubs['alice'].Submit(req, timeout=10))
                self.no_resources([req.request_id])
            self.check(label + '被拒绝且未创建资源', reject)

    def ready(self):
        value = self.stubs['alice'].Ready(pb.Empty(), timeout=10)
        require(value.ready and value.mode in ('test', 'test-mode'), '服务不是就绪测试模式')
        require({'python', 'node', 'browser', 'files'} <= set(value.environments), '固定环境缺失')

    def change_and_sign(self, req, **changes):
        for key, value in changes.items():
            if key == 'network_domains':
                del req.network_domains[:]
                req.network_domains.extend(value)
            elif key == 'environment_variables':
                req.environment_variables.clear()
                req.environment_variables.update(value)
            else:
                setattr(req, key, value)

    def bad_input(self, req):
        req.inputs.append(pb.InputFile(path='value.txt', data=b'synthetic', sha256='0' * 64))

    def path_input(self, req):
        req.inputs.append(input_file('../outside.txt', b'synthetic'))

    def unknown_environment(self, req):
        req.environment = 'unregistered'

    def image_pull(self):
        # 动态镜像以固定镜像为父层；冷拉取故障测试先清理专属公共缓存。
        from sb3_acceptance import clear_environment_cache
        clear_environment_cache(self)
        catalog = json.loads((PROJECT / 'catalog.json').read_text())
        entry = catalog['python']
        require(entry['image_ref'].startswith('localhost:5000/sandbox-model/features@sha256:'), '不允许删除非专属验收镜像')
        require(not self.docker.containers.list(filters={'ancestor': entry['image_id']}), '镜像仍被运行任务使用')
        self.docker.images.remove(entry['image_id'], force=True, noprune=True)
        try:
            self.docker.images.get(entry['image_id'])
        except docker.errors.ImageNotFound:
            pass
        else:
            raise AssertionError('登记镜像没有从本地索引移除')
        self.run()
        image = self.docker.images.get(entry['image_id'])
        require(image.id == entry['image_id'] and entry['image_ref'] in image.attrs.get('RepoDigests', []), '缺少镜像没有按固定摘要拉取')
        self.runtime_evidence['automatic_pull_verified'] = True

    def queue_limits(self):
        requests = [self.request(code=b'import time\ntime.sleep(60)\n') for _ in range(6)]
        try:
            for req in requests:
                self.submit(req)
            for req in requests[:2]:
                self.guest(req)
            extra = self.request()
            self.denied(lambda: self.stubs['alice'].Submit(extra, timeout=10), {grpc.StatusCode.RESOURCE_EXHAUSTED})
            statuses = [self.stubs['alice'].Status(pb.JobRef(request_id=req.request_id), timeout=5) for req in requests]
            require(sum(value.phase != 'queued' for value in statuses) <= 2, '并发任务超过2个')
            require(statuses[-1].phase == 'queued', '排队用例没有真正进入队列')
            self.stubs['alice'].Cancel(pb.JobRef(request_id=requests[-1].request_id), timeout=15)
            self.result(requests[-1], success=False)
            self.no_resources([requests[-1].request_id, extra.request_id])
        finally:
            for req in requests:
                try:
                    self.stubs['alice'].Cancel(pb.JobRef(request_id=req.request_id), timeout=15)
                    self.wait(req, seconds=30)
                except grpc.RpcError:
                    pass
        self.no_resources([req.request_id for req in requests])

    def runtime_and_memory(self):
        marker = 'SB_DATA_' + uuid.uuid4().hex
        attack = (PROJECT / 'tests/guest_attacks.py').read_bytes()
        code = ("import runpy,json,time,sys\nfrom pathlib import Path\n"
                "attack=runpy.run_path('/workspace/inputs/guest_attacks.py')\n"
                "Path('/workspace/out/attestation.json').write_text(json.dumps(attack['run']()))\n"
                f"marker={marker!r}\nPath('/workspace/out/data.txt').write_text(marker)\n"
                "print(marker);print(marker,file=sys.stderr);time.sleep(15)\n").encode()
        req = self.request(code=code, inputs=[input_file('guest_attacks.py', attack), input_file('data.txt', marker.encode())], timeout_seconds=120)
        self.submit(req)
        guest = self.guest(req)
        config = guest.attrs['HostConfig']
        self.runtime_evidence |= {'docker_runtime': config.get('Runtime'), 'readonly_rootfs': config.get('ReadonlyRootfs'),
                                 'log_driver': config.get('LogConfig', {}).get('Type'),
                                 'memory': config.get('Memory'), 'memory_swap': config.get('MemorySwap'),
                                 'pids_limit': config.get('PidsLimit'),
                                 'tmpfs_paths': sorted(config.get('Tmpfs', {})),
                                 'execution_endpoint': 'internal_bridge',
                                 'host_publish_bindings_present': any(guest.attrs.get('NetworkSettings', {}).get('Ports', {}).values())}
        self.check('实际Docker运行时为runsc', lambda: require(config.get('Runtime') == 'runsc'))
        self.check('只读根目录与任务内存挂载', lambda: require(config.get('ReadonlyRootfs') is True and {'/workspace', '/tmp', '/run', '/home/sandbox', '/var/tmp'} <= set(config.get('Tmpfs', {}))))
        self.check('日志驱动none、无swap、禁core、进程上限', lambda: require(config.get('LogConfig', {}).get('Type') == 'none' and config.get('MemorySwap') == config.get('Memory') and config.get('PidsLimit', 0) > 0 and any(item.get('Name') == 'core' and item.get('Hard') == 0 for item in config.get('Ulimits', []))))
        self.check('控制端口配置限制为宿主loopback', lambda: require(all(binding['HostIp'] == '127.0.0.1' for bindings in config.get('PortBindings', {}).values() for binding in bindings)))
        result = self.result(req)
        attestation = json.loads(self.artifact(result, 'attestation.json'))
        for name, passed in sorted(attestation.items()):
            self.check('任务攻击检查：' + name, lambda passed=passed: require(passed))
        require(self.artifact(result, 'data.txt').decode() == marker, '内存文件结果错误')
        require(marker in result.stdout and marker in result.stderr, 'stdout/stderr中转丢失')
        self.check('代码、输入、stdout/stderr、输出未留节点磁盘', lambda: self.scan_disk(marker))
        self.check('临时文件超限明确失败且不回退磁盘', self.tmpfs_overflow)

    def scan_disk(self, marker):
        needle = marker.encode()
        checked = total = 0
        hits = 0
        for directory in ('/var/lib/docker', '/var/lib/containerd', '/var/lib/sandbox_model', '/var/log', '/tmp', '/var/tmp', '/opt/sandbox_model', '/root'):
            base = Path(directory)
            if not base.exists():
                continue
            for current, folders, names in os.walk(base, followlinks=False):
                folders[:] = [name for name in folders if not (Path(current) / name).is_symlink()]
                for name in names:
                    path = Path(current) / name
                    if path.is_symlink() or not path.is_file():
                        continue
                    try:
                        with path.open('rb') as stream:
                            size = os.fstat(stream.fileno()).st_size
                            if size:
                                with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as mapped:
                                    if mapped.find(needle) != -1:
                                        hits += 1
                            checked += 1
                            total += size
                    except FileNotFoundError:
                        continue  # 并发清理删除文件，不存在残留内容。
        self.scan_evidence = {'files_scanned': checked, 'bytes_scanned': total, 'marker_hits': hits,
                              'directories': ['/var/lib/docker', '/var/lib/containerd', '/var/lib/sandbox_model', '/var/log', '/tmp', '/var/tmp', '/opt/sandbox_model', '/root']}
        require(checked > 0 and hits == 0, '节点磁盘发现任务标记或未扫描')
        if os.environ.get('SANDBOX_DEPLOYMENT') == 'compose':
            # Docker Desktop 的其他容器可使用 swap；本节点及子 cgroup 必须被硬性禁止。
            swap_max = Path('/sys/fs/cgroup/memory.swap.max').read_text().strip()
            swap_current = Path('/sys/fs/cgroup/memory.swap.current').read_text().strip()
            require(swap_max == '0' and swap_current == '0', '节点允许或已使用swap')
            self.scan_evidence['swap'] = {'scope': 'node-and-descendant-cgroups',
                                          'max': swap_max, 'current': swap_current}
        else:
            require(not Path('/proc/swaps').read_text().splitlines()[1:], '宿主启用了swap')

    def tmpfs_overflow(self):
        code = b"import errno,json\nfrom pathlib import Path\nblocked=False\ntry:\n with open('/tmp/fill','wb') as f:\n  for _ in range(40): f.write(b'x'*1048576)\nexcept OSError as e: blocked=e.errno==errno.ENOSPC\nPath('/workspace/out/check.json').write_text(json.dumps({'blocked':blocked}))\n"
        result = self.run(code=code)
        require(json.loads(self.artifact(result, 'check.json'))['blocked'], 'tmpfs满后未拒绝写入')

    def owner_and_duplicate(self):
        req = self.request(code=b"import time\ntime.sleep(8)\nprint('synthetic')\n")
        self.submit(req)
        self.check('另一内网连接可查询任务', lambda:require(self.stubs['bob'].Status(pb.JobRef(request_id=req.request_id)).request_id==req.request_id))
        self.check('相同任务重复提交返回同一任务', lambda: require(self.stubs['alice'].Submit(req, timeout=10).request_id == req.request_id))
        other = pb.TaskRequest(); other.CopyFrom(req); other.code += b'# conflict'
        self.check('相同编号不同摘要拒绝', lambda: self.denied(lambda: self.stubs['alice'].Submit(other, timeout=10)))
        self.result(req)
        self.check('结果送达状态与清理状态分别记录', lambda: require(self.stubs['alice'].Status(pb.JobRef(request_id=req.request_id), timeout=5).delivery_done))

    def task_functions(self):
        def python_code():
            result = self.run(code="from pathlib import Path\nPath('/workspace/out/result.txt').write_text('合成中文结果')\nprint('计算完成')\n".encode())
            require(self.artifact(result, 'result.txt').decode() == '合成中文结果')
            require('计算完成' in result.stdout)
        self.check('Agent生成Python代码返回中文输出和产物', python_code)
        self.check('允许的普通环境变量进入任务', lambda: require(json.loads(self.artifact(self.run(environment_variables={'LANG':'C','TZ':'Asia/Shanghai'},code=b"import os,json\nfrom pathlib import Path\nPath('out/env.json').write_text(json.dumps({'LANG':os.getenv('LANG'),'TZ':os.getenv('TZ')}))\n"),'env.json')) == {'LANG':'C','TZ':'Asia/Shanghai'}))
        self.check('Node代码在登记Node环境执行', lambda: require(self.artifact(self.run(environment='node', code="require('fs').writeFileSync('/workspace/out/result.txt','Node结果');console.log('Node完成');".encode()), 'result.txt').decode() == 'Node结果'))
        def skill():
            result = self.run('skill', entrypoint='inputs/skill_ok/scripts/summarize.py', inputs=fixture_inputs('skill_ok') + [input_file('input.csv', (FIXTURES / 'input.csv').read_bytes())])
            value = json.loads(self.artifact(result, 'summary.json'))
            require(value == {'items': 2, 'quantity': 5, 'amount': 13.0}, '技能汇总结果错误')
        self.check('上传技能包并执行指定脚本', skill)
        self.check('CSV解析', lambda: require(len(json.loads(self.artifact(self.run('parse', environment='files', inputs=[input_file('input.csv', (FIXTURES / 'input.csv').read_bytes())]), 'parsed.json'))['content']) == 2))
        from file_acceptance import run_file_checks
        run_file_checks(self)
        self.check('JSON解析', lambda: require(json.loads(self.artifact(self.run('parse', environment='files', inputs=[input_file('value.json', b'{"value": 7}')]), 'parsed.json'))['content']['value'] == 7))
        self.check('损坏JSON受控失败', lambda: self.run('parse', success=False, environment='files', inputs=[input_file('bad.json', b'broken')]))
        for kind in ('docx', 'xlsx'):
            self.check(kind.upper() + '合成文件解析', lambda kind=kind: self.office_parse(kind))
        for name, expected in (('skill_ok', True), ('skill_bad', False)):
            def audit(name=name, expected=expected):
                result = self.run('audit', entrypoint='inputs/' + name, inputs=fixture_inputs(name))
                report = json.loads(self.artifact(result, 'audit.json'))
                require(report['passed'] is expected)
                require(all(item.path != 'summary.json' for item in result.artifacts), '审核执行了技能脚本')
            self.check('断网静态审核：' + name, audit)
        self.check('ZIP正常解包和索引', lambda: self.zip_parse(False))
        self.check('ZIP路径穿越受控失败', lambda: self.zip_parse(True))
        self.check('ZIP膨胀压缩比受控失败', self.zip_bomb)
        self.check('公开网页读取与内容解析', self.web_read)
        from web_acceptance import run_web_checks
        run_web_checks(self)
        self.check('中文长图尺寸与内容', lambda: self.render('png'))
        self.check('中文PDF分页、字体与内容', lambda: self.render('pdf'))
        self.check('断网多页PDF与中文分页', lambda: self.render('pdf', multi_page=True))

    def office_parse(self, kind):
        data = io.BytesIO()
        if kind == 'docx':
            from docx import Document
            doc = Document(); doc.add_paragraph('合成中文文件'); doc.save(data)
        else:
            from openpyxl import Workbook
            book = Workbook(); book.active.append(['商品', '数量']); book.active.append(['苹果', 2]); book.save(data)
        result = self.run('parse', environment='files', inputs=[input_file('source.' + kind, data.getvalue())])
        parsed = json.loads(self.artifact(result, 'parsed.json'))
        require('合成中文文件' in json.dumps(parsed, ensure_ascii=False) if kind == 'docx' else '苹果' in json.dumps(parsed, ensure_ascii=False))

    def zip_parse(self, malicious):
        data = io.BytesIO()
        with zipfile.ZipFile(data, 'w', zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('../outside.txt' if malicious else 'folder/value.txt', 'synthetic')
        result = self.run('parse', success=not malicious, environment='files', inputs=[input_file('source.zip', data.getvalue())])
        if not malicious:
            require(self.artifact(result, 'extracted-00-value.txt') == b'synthetic')

    def zip_bomb(self):
        data = io.BytesIO()
        with zipfile.ZipFile(data, 'w', zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('big.txt', b'x' * 1048576)
        self.run('parse', success=False, environment='files', inputs=[input_file('source.zip', data.getvalue())])

    def web_read(self):
        result = self.run('web', environment='browser', url='https://allowed.test/', network_domains=['allowed.test'], memory_mb=1024)
        page = json.loads(self.artifact(result, 'webpage.json'))
        require(bool(page['title']) and '合成公开网页' in page['text'] and 'fixture:public-fixture' in page['text'], '合成网页内容不符')

    def render(self, format_name, multi_page=False):
        content = (FIXTURES / 'render.html').read_bytes()
        if multi_page:
            content += b'<style>@media print{section{min-height:600px;break-inside:avoid}}</style>'
        result = self.run('render', environment='browser', render_format=format_name, memory_mb=1024, inputs=[input_file('render.html', content)])
        data = self.artifact(result, 'render.' + format_name)
        if format_name == 'png':
            import struct
            require(data.startswith(b'\x89PNG\r\n\x1a\n'))
            width, height = struct.unpack('!II', data[16:24])
            require(320 <= width <= 1600 and 900 < height <= 12000, '长图尺寸不符')
        else:
            from pypdf import PdfReader
            pdf = PdfReader(io.BytesIO(data))
            require(len(pdf.pages) >= (2 if multi_page else 1), 'PDF分页数量不符')
            text = '\n'.join(page.extract_text() or '' for page in pdf.pages)
            require('沙箱渲染验证' in text and '第四部分' in text, 'PDF中文文本丢失')
            parsed = self.run('parse', environment='files', inputs=[input_file('rendered.pdf', data)])
            require('沙箱渲染验证' in json.loads(self.artifact(parsed, 'parsed.json'))['content'])
        return data

    def limits(self):
        self.check('执行超时与资源清理', lambda: self.run(success=False, timeout_seconds=2, code=b'import time\ntime.sleep(60)\n'))
        def cancel():
            req = self.request(code=b'import time\ntime.sleep(60)\n')
            self.submit(req)
            self.guest(req)
            self.stubs['alice'].Cancel(pb.JobRef(request_id=req.request_id), timeout=10)
            result = self.result(req, success=False)
            require(result.status.outcome in ('cancelled', 'canceled', 'revoked'), '取消没有独立结果状态')
            self.no_resources([req.request_id])
        self.check('人工取消正在执行任务并清理', cancel)
        self.check('脚本错误为失败而非成功', lambda: self.run(success=False, code=b'raise RuntimeError("synthetic failure")\n'))
        self.check('stdout超量受控失败', lambda: self.run(success=False, code=b'print("x" * 70000)\n'))
        def chinese_stderr():
            result = self.run(success=False, code="import sys\nprint('测'*30000,file=sys.stderr)\n".encode())
            require(len(result.stdout.encode()) <= 65536 and len(result.stderr.encode()) <= 65536,
                    '中文日志和错误说明合并后超过64KiB字节上限')
            self.no_resources([result.status.request_id])
        self.check('中文stderr超量失败且返回UTF8字节受限', chinese_stderr)
        self.check('超大产物受控失败', lambda: self.run(success=False, code=b'from pathlib import Path\nPath("out/big.bin").write_bytes(b"x" * (2*1024*1024+1))\n'))
        self.check('产物符号链接拒绝导出', lambda: self.run(success=False, code=b'from pathlib import Path\nPath("out/link.txt").symlink_to("/etc/passwd")\n'))
        self.check('产物硬链接拒绝导出', lambda: self.run(success=False, code=b'import os\nfrom pathlib import Path\nPath("/workspace/source.txt").write_text("synthetic")\nos.link("/workspace/source.txt", "out/link.txt")\n'))
        self.check('内存超限受控失败和回收', lambda: self.run(success=False, memory_mb=128, code=b'values=[]\nwhile True: values.append(bytearray(16*1024*1024))\n'))
        self.check('512MiB Python fork饱和明确内存限制并回收', self.fork_memory_limit)
        self.check('进程数超限被拒绝', self.process_limit)
        self.check('可信root导出不加载用户sitecustomize或pth', self.root_python_isolation)
        self.check('可信助手停止setsid逃离进程组的UID1000子进程并读取产物', self.escaped_child)

    def escaped_child(self):
        code = b"""import os,time,signal
from pathlib import Path
pid=os.fork()
if pid==0:
 os.setsid()
 signal.signal(signal.SIGTERM,signal.SIG_IGN)
 for descriptor in (0,1,2):
  try:os.close(descriptor)
  except OSError:pass
 time.sleep(90)
 os._exit(0)
Path('out/daemon.pid').write_text(str(pid))
Path('out/result.txt').write_text('protected private workspace artifact')
"""
        # service 的可信停止程序必须确认活跃UID1000全部消失，才进入root导出。
        # 因此该成功结果同时验证跨UID终止与0700工作区内0600产物的读取。
        result = self.run(code=code)
        require(int(self.artifact(result, 'daemon.pid')) > 0)
        require(self.artifact(result, 'result.txt') == b'protected private workspace artifact')

    def root_python_isolation(self):
        code = b"""from pathlib import Path
home=Path('/home/sandbox/.local/lib/python3.12/site-packages')
home.mkdir(parents=True,exist_ok=True)
(home/'sitecustomize.py').write_text("import os\\nfrom pathlib import Path\\nif os.geteuid()==0: Path('/workspace/out/root-site-executed.txt').write_text('unsafe')\\n")
(home/'attack.pth').write_text("import os; os.geteuid()==0 and __import__('pathlib').Path('/workspace/out/root-pth-executed.txt').write_text('unsafe')\\n")
Path('out/result.txt').write_text('normal synthetic result')
"""
        result = self.run(code=code)
        require(self.artifact(result, 'result.txt') == b'normal synthetic result')
        require(not any(item.path in ('root-site-executed.txt', 'root-pth-executed.txt') for item in result.artifacts), '可信root Python加载了任务用户site代码')

    def process_limit(self):
        # 子进程保留最小可信 sleep 映射，避免在 PID 上限前耗尽 Python fork 内存。
        code = b"import os,signal,json,resource\nfrom pathlib import Path\nchildren=[]\nfailure=None\ntry:\n for _ in range(200):\n  try: pid=os.fork()\n  except OSError as error: failure=error.errno;break\n  if pid==0: os.execl('/usr/bin/sleep','sleep','60')\n  children.append(pid)\nfinally:\n for pid in children:\n  try: os.kill(pid,signal.SIGKILL);os.waitpid(pid,0)\n  except ProcessLookupError: pass\nPath('out/pids.json').write_text(json.dumps({'errno':failure,'count':len(children),'nproc':resource.getrlimit(resource.RLIMIT_NPROC)}))\n"
        result = self.run(code=code, memory_mb=512)
        report = json.loads(self.artifact(result, 'pids.json'))
        require(report['errno'] == errno.EAGAIN and report['count'] < 200
                and report['nproc'] == [128, 128], '进程上限未以实际128限制和EAGAIN生效')
        self.runtime_evidence['process_limit'] = {'memory_mb':512, **report,
                                                  'cleanup_done':result.status.cleanup_done}

    def fork_memory_limit(self):
        code = b"import os,time,signal,json\nfrom pathlib import Path\nchildren=[]\nblocked=False\ntry:\n for _ in range(200):\n  try: pid=os.fork()\n  except OSError: blocked=True;break\n  if pid==0: time.sleep(20);os._exit(0)\n  children.append(pid)\nfinally:\n for pid in children:\n  try: os.kill(pid,signal.SIGKILL);os.waitpid(pid,0)\n  except ProcessLookupError: pass\nPath('out/pids.json').write_text(json.dumps({'blocked':blocked,'count':len(children)}))\n"
        result = self.run(code=code, memory_mb=512, success=False)
        require(result.status.error_code == 'MEMORY_LIMIT' and result.status.cleanup_done,
                '已证实的Python fork内存饱和仍被误记为超时或未清理')

    def two_task_isolation(self):
        req = self.request(code=b"import socket,time\ns=socket.socket();s.bind(('0.0.0.0',9000));s.listen();time.sleep(45)\n", timeout_seconds=60)
        self.submit(req)
        guest = self.guest(req)
        target = next(iter(guest.attrs['NetworkSettings']['Networks'].values()))['IPAddress']
        attack = (PROJECT / 'tests/guest_attacks.py').read_bytes()
        code = f"import runpy,json\nfrom pathlib import Path\na=runpy.run_path('/workspace/inputs/guest_attacks.py')\nr=a['run']({target!r})\nPath('out/attestation.json').write_text(json.dumps(r))\n".encode()
        try:
            result = self.run(owner='bob', code=code, inputs=[input_file('guest_attacks.py', attack)])
            report = json.loads(self.artifact(result, 'attestation.json'))
            require(report.get('other_task_control_denied') and report.get('other_task_port_denied'), '两个任务能够互访')
        finally:
            self.stubs['alice'].Cancel(pb.JobRef(request_id=req.request_id), timeout=10)
            self.wait(req)
        self.no_resources([req.request_id])

    def gateway_request(self, message, kind='skill', headers=None, success=True):
        code = ("import json,os,urllib.request,urllib.error\nfrom pathlib import Path\n"
                f"message={message!r}\nheaders={headers or {}!r}\n"
                "headers['Content-Type']='application/json'\n"
                "opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))\n"
                "request=urllib.request.Request(os.environ['LAZYX_GATEWAY']+'/request',data=json.dumps(message).encode(),headers=headers)\n"
                "try:\n response=opener.open(request,timeout=8)\nexcept urllib.error.HTTPError as error: response=error\n"
                "value=json.load(response)\nPath('out/gateway.json').write_text(json.dumps(value))\n").encode()
        fields = {'entrypoint': 'inputs/gateway.py', 'inputs': [input_file('gateway.py', code)]}
        if kind == 'code':
            fields = {'code': code}
        return self.run(kind, success=success, **fields)

    def gateway_flow(self):
        def model():
            result = self.gateway_request({'type': 'model', 'operation': 'complete', 'arguments': {}})
            value = json.loads(self.artifact(result, 'gateway.json'))
            require(value.get('status') == 'ok' and value.get('module') == '06' and value.get('result', {}).get('text') == '模拟模型响应', '模型请求没有按06返回')
        self.check('模拟Skill模型请求转交06并返回原任务', model)
        def tool():
            result = self.gateway_request({'type': 'tool', 'operation': 'echo', 'arguments': {'value': 'synthetic'}})
            value = json.loads(self.artifact(result, 'gateway.json'))
            require(value.get('status') in ('ok', 'allowed') and value.get('module') == '02', '工具请求没有按02返回')
        self.check('模拟Skill工具提议转交02并返回原任务', tool)
        def key_demo():
            result = self.gateway_request({'type': 'tool', 'operation': 'key_demo', 'arguments': {}})
            value = json.loads(self.artifact(result, 'gateway.json'))
            serialized = json.dumps(value).lower()
            require(value.get('module') == '02' and value.get('result', {}).get('credential_used') is True and set(value.get('result', {})) == {'value', 'credential_used'} and 'synthetic-api-key' not in serialized and 'authorization' not in serialized, '连接器凭据出现在返回中')
        self.check('模拟连接器调用返回不包含凭据或认证字段', key_demo)
        for name, message, kind in (
            ('拒绝工具', {'type': 'tool', 'operation': 'deny', 'arguments': {}}, 'skill'),
            ('普通代码不能请求模型', {'type': 'model', 'operation': 'complete', 'arguments': {}}, 'code'),
            ('未知工具', {'type': 'tool', 'operation': 'unregistered', 'arguments': {}}, 'skill'),
            ('任务自报身份', {'type': 'model', 'operation': 'complete', 'arguments': {}, 'owner': 'bob'}, 'skill'),
        ):
            def denied(message=message, kind=kind):
                result = self.gateway_request(message, kind=kind, headers={'X-Owner': 'bob', 'X-Job-Id': 'other-task'})
                value = json.loads(self.artifact(result, 'gateway.json'))
                require(value.get('status') in ('denied', 'error'), '网关拒绝变成放行')
            self.check('网关受限通道：' + name, denied)
        for name, message, outcome in (
            ('模型预算超额结束任务', {'type': 'model', 'operation': 'budget_exhausted', 'arguments': {}}, None),
            ('模拟需用户批准时回传提议并销毁沙箱', {'type': 'tool', 'operation': 'approval', 'arguments': {'value':'synthetic-proposal'}}, 'needs_approval'),
        ):
            def stopped(message=message, outcome=outcome):
                result = self.gateway_request(message, success=False)
                if outcome:
                    require(result.status.outcome == outcome, '需批准没有独立结果状态')
                    require(hasattr(result, 'proposal_json') and bool(result.proposal_json), '调用方没有收到待批准提议')
                    proposal = json.loads(result.proposal_json)
                    require(proposal.get('operation') == 'approval' and proposal.get('arguments') == {'value':'synthetic-proposal'}, '待批准提议内容不符')
            self.check(name, stopped)

    def stop_process(self, file, job_id):
        path = RUN / file
        require(path.is_file(), '缺少独立进程PID记录，不能执行失联验收')
        pid = int(path.read_text().strip())
        modules = {'service.pid':b'sandbox_model.service', 'opensandbox.pid':b'sandbox_model.opensandbox_process'}
        command = Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
        require(file in modules and any(command[index] == b'-m' and command[index + 1] == modules[file]
                    for index in range(len(command) - 1)), 'PID记录与指定服务模块argv不匹配')
        os.kill(pid, signal.SIGKILL)
        end = time.monotonic() + 45
        while time.monotonic() < end:
            try:
                self.no_resources([job_id])
                return
            except (AssertionError, FileNotFoundError, docker.errors.NotFound):
                time.sleep(.3)
        raise AssertionError('独立回收未在45秒内清理失联任务')

    def shutdown_faults(self):
        # OpenSandbox故障先做；Python管理器故障最后做。重启由setup/manual入口处理。
        for label, file in [('OpenSandbox失联独立回收', 'opensandbox.pid'), ('管理服务失联独立回收', 'service.pid')]:
            def fault(file=file):
                req = self.request(code=b'import time\ntime.sleep(110)\n', timeout_seconds=120)
                self.submit(req)
                self.guest(req)
                self.stop_process(file, req.request_id)
            self.check(label, fault)
            if file == 'opensandbox.pid':
                # 后一个case需要真实OpenSandbox重新可用，不能用模拟资源冒充。
                helper = PROJECT / 'scripts/restart_services.sh'
                if not helper.is_file():
                    self.check('OpenSandbox故障后恢复供后续验收', lambda: require(False, '缺少可信重启入口'))
                    return
                self.check('OpenSandbox故障后恢复供后续验收', lambda: subprocess.run(['bash', str(helper)], check=True, timeout=30))

    def execute(self):
        try:
            self.initial_security()
            self.check('节点缺少登记镜像时按固定摘要自动拉取', self.image_pull)
            self.check('运行隔离和内存全路径', self.runtime_and_memory)
            self.owner_and_duplicate()
            self.task_functions()
            self.limits()
            self.check('并发2、总队列6、队列满拒绝及排队取消', self.queue_limits)
            self.gateway_flow()
            from gateway_acceptance import run_gateway_checks
            run_gateway_checks(self)
            from lifecycle_acceptance import run_lifecycle_checks
            run_lifecycle_checks(self)
            try:
                from network_acceptance import run_network_checks
            except ImportError:
                self.check('网络故障与DNS验收模块存在', lambda: require(False, '缺少网络集成验收模块'))
            else:
                run_network_checks(self)
            self.check('两个并行任务不能互访', self.two_task_isolation)
            self.check('正常和失败任务全部完成回收', lambda: self.no_resources(self.ids))
            from sb3_acceptance import run_sb3_checks
            run_sb3_checks(self)
            if self.include_faults:
                self.shutdown_faults()
                subprocess.run(["bash",str(PROJECT/"scripts/restart_services.sh")],check=True,timeout=150)
            from operations_acceptance import run_operations_checks
            run_operations_checks(self)
            from observability_acceptance import run_observability_checks
            run_observability_checks(self)
            self.completed = True
        finally:
            for channel in self.channels.values():
                channel.close()
            self.save()
        return all(item['passed'] for item in self.checks)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--without-shutdown-faults', action='store_true', help='人工逐项复验时保留服务；报告明确不包含失联故障验收')
    args = parser.parse_args()
    suite = Acceptance(not args.without_shutdown_faults)
    try:
        passed = suite.execute()
    except Exception as error:
        suite.check('验收流程完整执行', lambda: (_ for _ in ()).throw(error))
        passed = False
    print(f"[完成] {'验收通过' if passed else '验收未通过'}；报告：{RUN / 'report.json'}", flush=True)
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
