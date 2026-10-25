"""独立测试调用方：模拟 02/06 与连接器，不代表真实产品授权或计费。"""
from collections import deque
import hmac
import json
import secrets


class CallerUnavailable(RuntimeError):
    pass


def connector_payload(context, value):
    return json.dumps([context, value], sort_keys=True, separators=(",", ":")).encode()


class SyntheticUpstream:
    """合成第三方端点：校验连接器认证，认证数据不进入返回值。"""
    def __init__(self, key):
        self.key = key
        self.accepted_calls = 0

    def echo(self, context, value, signature):
        expected = hmac.digest(self.key, connector_payload(context, value), "sha256")
        if not hmac.compare_digest(signature, expected):
            raise ValueError("SYNTHETIC_CONNECTOR_AUTH_FAILED")
        self.accepted_calls += 1
        return {"value": value, "credential_used": True}


class SyntheticConnector:
    """只在测试调用方持有随机合成密钥，代调用独立的合成端点。"""
    def __init__(self, key=None, upstream=None):
        self.key = key if key is not None else secrets.token_bytes(32)
        self.upstream = upstream or SyntheticUpstream(self.key)

    def echo(self, context, value):
        signature = hmac.digest(self.key, connector_payload(context, value), "sha256")
        return self.upstream.echo(context, value, signature)


class TestCaller:
    """仅供合成测试模拟模型、工具、审批和调用方失联，不承担产品授权。"""
    def __init__(self, connector=None):
        self.connector = connector or SyntheticConnector()
        self.received = deque(maxlen=64)
        self.available = True

    def request(self, owner, job_id, request_id, request_type, operation, arguments):
        # 请求上下文随响应返回，便于测试管理侧是否正确绑定任务与调用。
        context = {"owner": owner, "job_id": job_id, "request_id": request_id}
        self.received.append(context | {"type": request_type, "operation": operation})
        if not self.available or operation == "caller_lost":
            raise CallerUnavailable("TEST_CALLER_UNAVAILABLE")
        module = "06" if request_type == "model" else "02"
        result = {"status": "denied", "module": module, "reason": "DENIED"}
        if request_type == "model":
            # 固定测试响应，不调用真实模型，也不产生真实 API 费用。
            if operation == "complete":
                result = {"status": "ok", "module": module,
                          "result": {"text": "模拟模型响应", "usage": 1}}
            elif operation == "budget_exhausted":
                result["reason"] = "BUDGET_EXHAUSTED"
        elif request_type == "tool":
            value = str(arguments.get("value", ""))[:1024]
            if operation == "echo":
                result = {"status": "ok", "module": module,
                          "result": {"value": value, "credential_used": False}}
            elif operation == "key_demo":
                result = {"status": "ok", "module": module,
                          "result": self.connector.echo(context, value)}
            elif operation == "approval":
                result = {"status": "needs_approval", "module": module}
        return result | context
