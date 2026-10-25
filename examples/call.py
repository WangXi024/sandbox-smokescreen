#!/usr/bin/env python3
"""独立调用方示例：仅依赖 gRPC，直接连接服务端口，不调用 Docker。"""
import argparse
import hashlib
import importlib
import json
from pathlib import Path, PurePosixPath
import sys
import tempfile
import time
import uuid

sys.dont_write_bytecode = True
import grpc
from grpc_tools import protoc

PROJECT = Path(__file__).resolve().parents[1]
OUTPUTS = PROJECT.parent / 'sandbox_smokescreen_outputs' / 'external'


def protocol():
    # 生成文件只放临时目录；调用方不导入管理服务或 OpenSandbox。
    source = PROJECT / 'src/sandbox_model/proto'
    with tempfile.TemporaryDirectory(prefix='sandbox-client-proto-') as directory:
        if protoc.main(['protoc', '-I' + str(source), '--python_out=' + directory,
                        '--grpc_python_out=' + directory, str(source / 'sandbox.proto')]):
            raise RuntimeError('协议生成失败')
        sys.path.insert(0, directory)
        try:
            return importlib.import_module('sandbox_pb2'), importlib.import_module('sandbox_pb2_grpc')
        finally:
            sys.path.remove(directory)


pb, rpc = protocol()


def input_file(name, data):
    # 摘要由调用方根据原始字节生成，服务端收到后会再次核对。
    return pb.InputFile(path=name, data=data, sha256=hashlib.sha256(data).hexdigest())


def execute(stub, request, directory, *, cancel=False):
    """提交、等待、验证并保存结果后 ACK；本地超时/中断也发取消。"""
    reference = pb.JobRef(request_id=request.request_id)
    submitted = False
    finished = False
    try:
        # 响应丢失时任务可能已创建；先交出编号，并尝试按原编号取消。
        print('[提交]', request.request_id, flush=True)
        submitted = True
        try:
            stub.Submit(request, timeout=10)
        except grpc.RpcError as error:
            # 明确拒绝无需取消；失联或响应不确定时，任务可能已被服务端接收。
            submitted = error.code() in (grpc.StatusCode.DEADLINE_EXCEEDED, grpc.StatusCode.UNAVAILABLE,
                                        grpc.StatusCode.CANCELLED, grpc.StatusCode.UNKNOWN, grpc.StatusCode.INTERNAL)
            raise
        deadline = time.monotonic() + (660 if request.dependencies else 180)
        # 包含环境构建、排队和清理的等待时间，区别于单次 RPC 的网络超时。
        cancelled = False
        while time.monotonic() < deadline:
            status = stub.Status(reference, timeout=5)
            if cancel and not cancelled and status.phase == 'running':
                stub.Cancel(reference, timeout=5)
                cancelled = True
            if status.phase == 'finished' and status.cleanup_done:
                finished = True
                break
            time.sleep(.2)
        if not finished:
            raise TimeoutError('任务或清理超时，已请求取消')
        result = stub.Result(reference, timeout=10)
        data = {}
        total = 0
        for artifact in result.artifacts:
            # 校验所有返回路径、额度和摘要，防止越界写文件或接受不完整产物。
            path = PurePosixPath(artifact.path)
            total += len(artifact.data)
            if (not artifact.path or path.is_absolute() or '..' in path.parts or '\\' in artifact.path
                    or artifact.path in data or len(artifact.path) > 1024
                    or any(ord(c) < 32 for c in artifact.path)
                    or len(artifact.data) > 2 * 1024 * 1024 or total > 4 * 1024 * 1024
                    or len(result.artifacts) > 8
                    or hashlib.sha256(artifact.data).hexdigest() != artifact.sha256):
                raise ValueError('产物路径、大小或摘要校验失败')
            data[artifact.path] = artifact.data
        # 每次调用使用新目录，不能覆盖上次的产物；先全部校验再写入。
        directory.mkdir(parents=True, exist_ok=False)
        for name, content in data.items():
            target = directory / 'artifacts' / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
        report = {'request_id':request.request_id, 'outcome':status.outcome,
                  'error_code':status.error_code, 'cleanup_done':status.cleanup_done,
                  'stdout':result.stdout, 'stderr':result.stderr,
                  'artifacts':[{ 'path':a.path, 'sha256':a.sha256, 'bytes':len(a.data)} for a in result.artifacts]}
        (directory / 'report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
        # 先保存结果再确认接收；确认后服务端就可以释放结果正文。
        delivery = stub.Acknowledge(reference, timeout=5)
        if not delivery.delivery_done:
            raise RuntimeError('服务未确认送达')
        print(f'[结果] {status.outcome}；清理完成：{status.cleanup_done}；已确认接收', flush=True)
        print('[产物]', directory, flush=True)
        if status.outcome != ('cancelled' if cancel else 'success'):
            raise RuntimeError('任务失败：' + status.error_code + '；原因见 report.json')
        return data
    finally:
        if submitted and not finished:
            # 调用方退出不等于任务停止；按原编号尝试取消，失败时保留查询线索。
            try:
                stub.Cancel(reference, timeout=5)
            except grpc.RpcError:
                print('[提示] 取消未获确认，请通过 request_id 查询任务状态', file=sys.stderr)


def request(**fields):
    # 新任务用新编号；重试已有任务时应保留原请求，不能调用此函数换编号重投。
    return pb.TaskRequest(request_id='external_' + uuid.uuid4().hex,
                          kind='code', environment='python', memory_mb=512,
                          timeout_seconds=60, **fields)


def staged(stub, directory):
    # 第一段主动返回调用需求和检查点；不申请 API Key，也不假装进程暂停恢复。
    first = request(code=b'''import json
from pathlib import Path
items=[{'price':20,'quantity':3},{'price':40,'quantity':1}]
state={'subtotal':sum(x['price']*x['quantity'] for x in items)}
Path('out/next.json').write_text(json.dumps({'operation':'demo.tax_rate','arguments':{'region':'demo'},'state':state}))
''')
    data = execute(stub, first, directory / 'step-1')
    proposal = json.loads(data['next.json'])
    # 沙箱给出的调用需求属于待检查输入，调用方确认操作和参数后再提供数据。
    if (set(proposal) != {'operation','arguments','state'} or proposal['operation'] != 'demo.tax_rate'
            or proposal['arguments'] != {'region':'demo'} or proposal['state'] != {'subtotal':100}):
        raise ValueError('第一段提出了未获准的操作或参数')
    print('[调用方] 已检查请求，使用合成税率 0.06；没有调用真实收费 API', flush=True)
    # 产品在这里通过自己的连接器调用 API；本例仅模拟返回业务数据，没有密钥。
    second = request(code=b'''import json
from pathlib import Path
data=json.loads(Path('inputs/resume.json').read_text())
assert not Path('out/next.json').exists()
result={'total':round(data['subtotal']*(1+data['tax_rate']),2)}
Path('out/total.json').write_text(json.dumps(result))
''', inputs=[input_file('resume.json', json.dumps({**proposal['state'], 'tax_rate':.06}).encode())])
    result = execute(stub, second, directory / 'step-2')
    if json.loads(result['total.json']) != {'total':106.0}:
        raise ValueError('分段结果不符')
    print('[通过] 两个不同任务通过显式输入衔接，合计 106.0', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--address', default='localhost:18443')
    parser.add_argument('case', choices=['python', 'parse', 'staged', 'cancel'])
    parser.add_argument('file', nargs='?', type=Path)
    parser.add_argument('--pdf-images', action='store_true')
    parser.add_argument('--max-pages', type=int, default=7)
    parser.add_argument('--max-long-edge', type=int, default=2048)
    args = parser.parse_args()
    if args.case == 'parse' and not args.file:
        parser.error('parse 需要输入文件路径')
    with grpc.insecure_channel(args.address, options=[('grpc.max_send_message_length', 8*1024*1024),
                                ('grpc.max_receive_message_length', 8*1024*1024)]) as channel:
        stub = rpc.SandboxServiceStub(channel)
        ready = stub.Ready(pb.Empty(), timeout=5)
        # 就绪和可接单分别检查；健康服务也可能因队列或历史额度暂时拒绝新任务。
        if not ready.ready or not ready.accepting_tasks:
            raise RuntimeError('服务暂不可接单：' + (ready.admission_reason or ready.reason))
        directory = OUTPUTS / (args.case + '-' + uuid.uuid4().hex[:12])
        if args.case == 'staged':
            staged(stub, directory)
            return
        req = request(code=b"print(2+3)\n")
        if args.case == 'parse':
            # 本机先按输入总额读取有限字节，避免示例客户端一次加载任意大文件。
            with args.file.open('rb') as source:
                content = source.read(1024*1024 + 1)
            if len(content) > 1024*1024:
                raise ValueError('输入超过当前 1 MiB 上限')
            req.kind, req.environment, req.code = 'parse', 'files', b''
            req.inputs.append(input_file(args.file.name, content))
            req.parse_options.CopyFrom(pb.ParseOptions(pdf_images=args.pdf_images,
                max_pages=args.max_pages if args.pdf_images else 0, max_long_edge=args.max_long_edge))
        elif args.case == 'cancel':
            req.code = b'import time\ntime.sleep(45)\n'
        execute(stub, req, directory, cancel=args.case == 'cancel')


if __name__ == '__main__':
    try:
        main()
    except grpc.RpcError as error:
        print('[失败]', error.code().name, error.details(), file=sys.stderr)
        raise SystemExit(1)
    except (OSError, RuntimeError, ValueError) as error:
        print('[失败]', str(error), file=sys.stderr)
        raise SystemExit(1)
