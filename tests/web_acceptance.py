"""真实浏览器失败验收：源站证据在 RAM，不把超时或未开始当作阻断成功。"""
import json
import urllib.request
import uuid


def requests():
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open('http://172.27.250.10/_evidence', timeout=3) as reply:
        return json.load(reply)['requests']


def run_web_checks(suite):
    def require(value, reason):
        if not value:
            raise AssertionError(reason)
    def failure(path, expected, redirect=False):
        marker = uuid.uuid4().hex
        result = suite.run('web', success=False, environment='browser',
                           url='https://allowed.test/' + path + '?' + marker,
                           network_domains=['allowed.test'], memory_mb=1024, timeout_seconds=40)
        records = [record for record in requests() if marker in record['path']]
        suite.runtime_evidence.setdefault('web_failures', []).append({
            'case': path, 'reached_approved_origin': any(record['host'] == 'allowed.test' for record in records),
            'reached_forbidden_origin': any(record['host'] == 'blocked.test' for record in records),
            'cleanup_done': result.status.cleanup_done})
        require(any(record['host'] == 'allowed.test' for record in records), '网页未到达获准源站，不能当作功能验收')
        require(not any(record['host'] == 'blocked.test' for record in records), '越权重定向到达了源站')
        if not redirect:
            require(expected in result.stderr, '失败原因不符合网页限额/登录/超时条件')
        require(not result.artifacts, '失败网页生成了成功产物')
    suite.check('网页转向未授权域名失败且目标源站无请求', lambda: failure('redirect', '', True))
    suite.check('网页遇到密码登录表单明确停止', lambda: failure('login', '登录'))
    suite.check('网页与子资源下载超过4MiB受控失败', lambda: failure('oversize', '网页下载超过'))
    suite.check('网页慢响应超过浏览器期限受控失败', lambda: failure('slow', 'Timeout'))
