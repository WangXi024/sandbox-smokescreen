"""仅检查免认证 gRPC 接口就绪状态；不输出证书、许可或任务内容。"""
from sandbox_model.client import connect
from sandbox_model.proto.sandbox_pb2 import Empty

try:
    channel, stub = connect()
    try:
        # 健康检查只看控制组件是否就绪；队列满导致不能接单不应判为服务故障。
        ready = stub.Ready(Empty(), timeout=2).ready
    finally:
        channel.close()
except Exception:
    ready = False
raise SystemExit(0 if ready else 1)
