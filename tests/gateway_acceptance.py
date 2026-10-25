"""经真实任务网络的请求绑定、幂等转交与调用方失联验收。"""
import hashlib
import json

from sandbox_model.proto import sandbox_pb2 as pb


def require(value, reason):
    if not value:
        raise AssertionError(reason)


def request(suite, messages, owner='alice'):
    req = suite.request('skill', owner=owner, entrypoint='inputs/gateway.py')
    source = ("import json,os,urllib.request,urllib.error\nfrom pathlib import Path\n"
              f"messages={messages!r}\n"
              "opener=urllib.request.build_opener(urllib.request.ProxyHandler({}));results=[]\n"
              "for message in messages:\n"
              " request=urllib.request.Request(os.environ['LAZYX_GATEWAY']+'/request',data=json.dumps(message).encode(),headers={'Content-Type':'application/json'})\n"
              " try:response=opener.open(request,timeout=8)\n"
              " except urllib.error.HTTPError as error:response=error\n"
              " results.append({'code':response.code,'reply':json.load(response)})\n"
              "Path('out/gateway.json').write_text(json.dumps(results))\n").encode()
    req.inputs.append(pb.InputFile(path='gateway.py', data=source, sha256=hashlib.sha256(source).hexdigest()))
    return req


def idempotent_forwarding(suite):
    model = {'request_id': 'model_once', 'type': 'model', 'operation': 'complete', 'arguments': {}}
    tool = {'request_id': 'connector_once', 'type': 'tool', 'operation': 'key_demo', 'arguments': {'value': 'synthetic'}}
    conflict = tool | {'arguments': {'value': 'changed'}}
    req = request(suite, [model] * 10 + [tool] * 10 + [conflict, tool], owner='bob')
    suite.submit(req, owner='bob')
    result = suite.result(req, owner='bob')
    values = json.loads(suite.artifact(result, 'gateway.json'))
    require(len(values) == 22 and all(item['code'] == 200 for item in values[:20]), '重复请求被错误地按转交次数耗尽')
    require(all(item['reply'] == values[0]['reply'] for item in values[:10]), '模型重复请求没有稳定返回同一结果')
    require(all(item['reply'] == values[10]['reply'] for item in values[10:20]), '连接器重复请求没有稳定返回同一结果')
    require(values[20]['code'] == 409 and values[20]['reply'].get('reason') == 'REQUEST_ID_CONFLICT', '同请求编号不同载荷没有拒绝')
    require(values[21] == values[10], '冲突请求污染了原请求缓存')
    for value in values[:20]:
        reply = value['reply']
        require(reply.get('owner') == 'internal' and reply.get('job_id') == req.request_id, '调用方返回没有绑定任务上下文')
    require(values[0]['reply'].get('request_id') == 'model_once' and values[10]['reply'].get('request_id') == 'connector_once', '调用方返回没有绑定请求编号')
    connector = values[10]['reply'].get('result', {})
    require(connector == {'value': 'synthetic', 'credential_used': True}, '连接器返回包含凭据或未执行认证代调用')
    require(result.status.model_calls == 1 and result.status.tool_calls == 1, '重复请求或冲突重复计入转交次数')
    suite.no_resources([req.request_id])
    suite.runtime_evidence.setdefault('gateway', []).append({
        'case': 'binding_cache_conflict', 'client_requests': 22,
        'model_calls': result.status.model_calls, 'tool_calls': result.status.tool_calls,
        'owner_task_request_bound': True, 'repeated_response_same': True})


def unique_call_limit(suite):
    messages = [{'request_id': 'call_' + str(index), 'type': 'tool', 'operation': 'echo', 'arguments': {}}
                for index in range(9)]
    req = request(suite, messages)
    suite.submit(req)
    result = suite.result(req, success=False)
    require(result.status.error_code == 'CALL_LIMIT' and result.status.tool_calls == 8
            and result.status.model_calls == 0, '8次唯一转交上限没有按实际调用生效')
    suite.no_resources([req.request_id])
    suite.runtime_evidence.setdefault('gateway', []).append({
        'case': 'unique_call_limit', 'tool_calls': result.status.tool_calls,
        'error_code': result.status.error_code, 'cleanup_done': result.status.cleanup_done})


def caller_lost(suite):
    message = {'request_id': 'lost_once', 'type': 'tool', 'operation': 'caller_lost', 'arguments': {}}
    req = request(suite, [message, message])
    suite.submit(req)
    result = suite.result(req, success=False)
    require(result.status.outcome == 'unknown' and result.status.error_code == 'CALLER_LOST', '调用方失联没有保留未知结果')
    require(result.status.tool_calls == 1, '失联请求被再次转交')
    repeated = suite.stubs['alice'].Submit(req, timeout=10)
    require(repeated.outcome == 'unknown' and repeated.tool_calls == 1
            and len(repeated.events) == len(result.status.events), '失联后重复提交重新执行了原任务')
    suite.no_resources([req.request_id])
    suite.runtime_evidence.setdefault('gateway', []).append({
        'case': 'caller_lost_no_replay', 'outcome': repeated.outcome,
        'tool_calls': repeated.tool_calls, 'duplicate_submit_same': True})


def run_gateway_checks(suite):
    suite.check('真实网关绑定身份任务请求、去重转交和载荷冲突', lambda: idempotent_forwarding(suite))
    suite.check('真实网关按8个唯一请求限制转交并回收', lambda: unique_call_limit(suite))
    suite.check('调用方失联结果unknown且同请求不重新转交', lambda: caller_lost(suite))
