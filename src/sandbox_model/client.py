"""同步 gRPC 调用方；任务内容只在客户端内存中装配。"""
import os
import grpc
from .proto import sandbox_pb2 as pb, sandbox_pb2_grpc as rpc


def connect(address=None):
    # 当前接口按内网免认证部署；放宽 gRPC 消息上限以容纳受限产物和日志。
    channel = grpc.insecure_channel(address or os.environ.get("SANDBOX_ADDRESS", "localhost:18443"),
        options=[("grpc.max_send_message_length", 8 * 1024 * 1024), ("grpc.max_receive_message_length", 8 * 1024 * 1024)])
    return channel, rpc.SandboxServiceStub(channel)
