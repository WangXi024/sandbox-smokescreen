#!/usr/bin/env python3
"""只读查询就绪状态、基础指标；可附加一个任务的状态和资源用量。"""
import argparse
import sys

sys.dont_write_bytecode = True
from compose_host import node_command

# 查询程序在节点内使用已生成的协议模块；本机仅转交任务编号并打印 JSON。
QUERY = '''import json,sys
from google.protobuf.json_format import MessageToDict
from sandbox_model.client import connect
from sandbox_model.proto.sandbox_pb2 import Empty,JobRef
channel,stub=connect()
try:
 data={'metrics':MessageToDict(stub.Metrics(Empty(),timeout=5),preserving_proto_field_name=True,always_print_fields_with_no_presence=True)}
 if sys.argv[1]:data['job']=MessageToDict(stub.Status(JobRef(request_id=sys.argv[1]),timeout=5),preserving_proto_field_name=True,always_print_fields_with_no_presence=True)
 print(json.dumps(data,ensure_ascii=False,indent=2))
finally:channel.close()
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--job', default='', help='需要查看的 request_id')
    args = parser.parse_args()
    # 任务编号作为独立进程参数传递，不拼接进待执行的 Python 代码。
    result = node_command('/opt/sandbox_model/.venv/bin/python','-B','-c',QUERY,args.job,
                          capture=True,check=False,timeout=20)
    if result.returncode:
        print('[失败] 查询失败：请检查服务是否就绪，以及任务编号是否存在。',file=sys.stderr)
        return 1
    print(result.stdout,end='')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
