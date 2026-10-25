"""专用测试 VM 的真实生命周期验收；屏障与诊断仅保留在 root 私有 RAM。"""
from contextlib import ExitStack, contextmanager
import hashlib
import os
from pathlib import Path
import subprocess
import time

import grpc
from sandbox_model.proto import sandbox_pb2 as pb, sandbox_pb2_grpc as rpc

RUN = Path('/run/sandbox_model')
PROJECT = Path(__file__).resolve().parents[1]


def require(value, reason):
    if not value:
        raise AssertionError(reason)


def poll(callback, reason, seconds=55):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = callback()
        if value:
            return value
        time.sleep(.05)
    raise AssertionError(reason)


def status(suite, req):
    return suite.stubs['alice'].Status(pb.JobRef(request_id=req.request_id), timeout=5)


@contextmanager
def gate(req, point):
    directory = RUN / 'test-gates'
    directory.mkdir(mode=0o700, exist_ok=True)
    info = directory.lstat()
    require(os.geteuid() == 0 and directory.is_dir() and not directory.is_symlink()
            and info.st_uid == 0 and not info.st_mode & 0o077, '测试屏障目录不是 root 私有 RAM 路径')
    path = directory / f'{req.request_id}.{point}'
    entered = path.with_name(path.name + '.entered')
    path.write_text('hold')
    path.chmod(0o600)
    try:
        yield path, entered
    finally:
        path.unlink(missing_ok=True)
        entered.unlink(missing_ok=True)


def reached(suite, req, entered, phase):
    poll(lambda: entered.is_file(), '真实执行路径未命中可信测试屏障')
    value = status(suite, req)
    require(value.phase == phase, '屏障未停在预期生命周期阶段')
    return value


def evidence(suite, case, value, **fields):
    suite.runtime_evidence.setdefault('lifecycle', []).append({
        'case': case, 'outcome': value.outcome, 'cleanup_done': value.cleanup_done,
        'phases': [event.phase for event in value.events], **fields})


def reuse_both_slots(suite):
    requests = [suite.request() for _ in range(2)]
    with ExitStack() as stack:
        held = [stack.enter_context(gate(req, 'preparing')) for req in requests]
        for req in requests:
            suite.submit(req)
        for req, (_, entered) in zip(requests, held):
            reached(suite, req, entered, 'preparing')
        for path, _ in held:
            path.unlink(missing_ok=True)
        for req in requests:
            require(suite.result(req).status.outcome == 'success', '取消后两个执行槽不能复用')
    suite.no_resources([req.request_id for req in requests])


def cancel_phase(suite, point, phase):
    req = suite.request(code=b'from pathlib import Path\nPath("out/executed.txt").write_text("synthetic")\n')
    with gate(req, point) as (path, entered):
        suite.submit(req)
        reached(suite, req, entered, phase)
        guest_present = bool(suite.docker.containers.list(filters={'label': f'lazyx.job={req.request_id}'}))
        if phase != 'preparing':
            require(suite.guest(req).status == 'running', '取消用例没有创建真实执行实例')
        cancellation = suite.stubs['alice'].Cancel.future(pb.JobRef(request_id=req.request_id), timeout=25)
        poll(lambda: status(suite, req).outcome == 'cancelled', '取消意图未进入真实任务状态', seconds=10)
        repeated = suite.stubs['alice'].Cancel.future(pb.JobRef(request_id=req.request_id), timeout=25)
        path.unlink(missing_ok=True)
        cancellation.result(timeout=30)
        repeated.result(timeout=30)
        result = suite.result(req, success=False)
    phases = [event.phase for event in result.status.events]
    require(result.status.outcome == 'cancelled', '取消结果被后续成功覆盖')
    require(phase == 'returning' or 'running' not in phases, '准备/创建取消后仍执行任务')
    require(not result.artifacts, '取消任务仍交付产物')
    again = suite.stubs['alice'].Cancel(pb.JobRef(request_id=req.request_id), timeout=10)
    require(again.outcome == 'cancelled' and len(again.events) == len(result.status.events), '重复取消改写终态或重复完成事件')
    suite.no_resources([req.request_id])
    reuse_both_slots(suite)
    evidence(suite, 'cancel_' + phase, result.status, guest_observed=guest_present,
             repeated_cancel_stable=True, slots_reused=2)


def result_reception_and_ack(suite):
    req = suite.request(code=b'from pathlib import Path\nPath("out/result.bin").write_bytes(b"x"*65536)\n')
    with gate(req, 'returning') as (path, entered):
        suite.submit(req)
        reached(suite, req, entered, 'returning')
        suite.denied(lambda: suite.stubs['alice'].Acknowledge(pb.JobRef(request_id=req.request_id), timeout=10),
                     {grpc.StatusCode.FAILED_PRECONDITION})
        path.unlink(missing_ok=True)
        value = suite.wait(req)
    require(value.outcome == 'success' and not value.delivery_done, '结果在接收前已被确认送达')
    channel = grpc.insecure_channel('localhost:18443',
        options=[('grpc.max_receive_message_length', 1024)])
    try:
        suite.denied(lambda: rpc.SandboxServiceStub(channel).Result(pb.JobRef(request_id=req.request_id), timeout=10),
                     {grpc.StatusCode.RESOURCE_EXHAUSTED})
    finally:
        channel.close()
    require(not status(suite, req).delivery_done, '真实接收失败被误记为送达')
    first = suite.stubs['alice'].Result(pb.JobRef(request_id=req.request_id), timeout=10)
    second = suite.stubs['alice'].Result(pb.JobRef(request_id=req.request_id), timeout=10)
    require(first.SerializeToString(deterministic=True) == second.SerializeToString(deterministic=True), '结果重传内容不稳定')
    require(not status(suite, req).delivery_done, '读取结果未经显式ACK却记为送达')
    content = suite.artifact(first, 'result.bin')
    expected = next(item.sha256 for item in first.artifacts if item.path == 'result.bin')
    require(len(content) == 65536 and hashlib.sha256(content).hexdigest() == expected, '重传产物摘要不符')
    for _ in range(2):
        acknowledged = suite.stubs['alice'].Acknowledge(pb.JobRef(request_id=req.request_id), timeout=10)
        require(acknowledged.delivery_done and acknowledged.cleanup_done, 'ACK 未稳定记录独立送达状态')
    suite.no_resources([req.request_id])
    evidence(suite, 'result_receive_failure_retry_ack', acknowledged,
             failed_receive_code='RESOURCE_EXHAUSTED', retransmission_same=True)


def restart(suite):
    subprocess.run(['bash', str(PROJECT / 'scripts/restart_services.sh')], check=True,
                   timeout=60, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    poll(lambda: ready(suite), '专属服务重启后未就绪')


def ready(suite):
    try:
        return suite.stubs['alice'].Ready(pb.Empty(), timeout=1).ready
    except grpc.RpcError:
        return False


def create_response_lost(suite):
    req = suite.request(code=b'from pathlib import Path\nPath("out/executed.txt").write_text("synthetic")\n')
    try:
        with gate(req, 'create_response') as (_, entered):
            suite.submit(req)
            reached(suite, req, entered, 'creating')
            suite.guest(req)
            suite.stop_process('opensandbox.pid', req.request_id)
            value = suite.wait(req)
            require(value.outcome in ('unknown', 'failed'), '实际创建响应中断仍报告成功')
            require(not any(event.phase == 'running' for event in value.events), '创建响应丢失后仍执行任务')
            suite.no_resources([req.request_id])
            evidence(suite, 'create_http_response_lost', value, real_guest_observed=True,
                     opensandbox_process_killed=True)
    finally:
        restart(suite)


def manager_restart_unknown(suite):
    req = suite.request(code=b'import time\ntime.sleep(110)\n', timeout_seconds=120)
    suite.submit(req)
    suite.guest(req)
    poll(lambda: status(suite, req).phase == 'running', '重启用例未实际开始执行')
    suite.stop_process('service.pid', req.request_id)
    restart(suite)
    value = status(suite, req)
    require(value.outcome == 'unknown' and value.cleanup_done, '重启后未完成任务没有保留 unknown 状态')
    suite.denied(lambda: suite.stubs['alice'].Result(pb.JobRef(request_id=req.request_id), timeout=10),
                 {grpc.StatusCode.NOT_FOUND})
    repeated = suite.stubs['alice'].Submit(req, timeout=10)
    require(repeated.outcome == 'unknown' and len(repeated.events) == len(value.events), '重启后同一任务被重新执行')
    time.sleep(.5)
    suite.no_resources([req.request_id])
    require(status(suite, req).outcome == 'unknown', '旧任务 unknown 状态被改写')
    evidence(suite, 'manager_restart_no_replay', repeated, duplicate_submit_same=True)


def run_lifecycle_checks(suite):
    for point, phase in (('preparing', 'preparing'), ('create_response', 'creating'), ('returning', 'returning')):
        suite.check(phase + ' 阶段取消且迟到资源完成回收',
                    lambda point=point, phase=phase: cancel_phase(suite, point, phase))
    suite.check('真实结果接收失败、稳定重传与显式ACK', lambda: result_reception_and_ack(suite))
    if suite.include_faults:
        suite.check('真实创建HTTP响应丢失后回收未执行实例', lambda: create_response_lost(suite))
        suite.check('管理器重启保留unknown且原任务不重做', lambda: manager_restart_unknown(suite))
