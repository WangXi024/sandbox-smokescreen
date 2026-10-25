"""人工复验调用方：只用合成输入、免认证 gRPC 接口。"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import time
import uuid


CASES = ("python", "node", "skill", "web", "parse", "png", "pdf", "audit", "gateway", "cancel", "deps-python", "deps-node", "deps-source")
ROOT = Path(__file__).resolve().parents[2]
RUN = Path("/run/sandbox_model")
FINISHED = {"success", "failed", "cancelled", "needs_approval"}


def input_file(pb, path, data):
    return pb.InputFile(path=path, data=data, sha256=hashlib.sha256(data).hexdigest())


def make_request(case, pb, *, audit_bad=False):
    """用合成文件和固定代码装配验收任务，不能替代真实 Agent 的任务规划。"""
    request = pb.TaskRequest(request_id="manual_" + uuid.uuid4().hex[:24], kind="code",
                             environment="python", memory_mb=512, timeout_seconds=60)
    fixture = ROOT / "tests" / "fixtures"
    if case == "python":
        request.code = b"import json\nfrom pathlib import Path\nPath('out/result.json').write_text(json.dumps({'language':'Python','value':2+3}))\nprint('Python demo OK')\n"
    elif case == "node":
        request.environment = "node"
        request.code = b"const fs=require('fs');fs.writeFileSync('out/result.json',JSON.stringify({language:'JavaScript',value:2+3}));console.log('Node demo OK');\n"
    elif case in ("skill", "audit"):
        name = "skill_bad" if audit_bad else "skill_ok"
        request.kind = "audit" if case == "audit" else "skill"
        request.environment = "files" if case == "audit" else "python"
        request.entrypoint = "inputs/" + name + ("" if case == "audit" else "/scripts/summarize.py")
        for path in sorted((fixture / name).rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
                relative = str(path.relative_to(fixture))
                request.inputs.append(input_file(pb, relative, path.read_bytes()))
        if case == "skill":
            request.inputs.append(input_file(pb, "input.csv", (fixture / "input.csv").read_bytes()))
    elif case == "web":
        request.kind = "web"
        request.environment = "browser"
        request.memory_mb = 1024
        request.url = "https://allowed.test/"
        request.network_domains.append("allowed.test")
    elif case == "parse":
        request.kind = "parse"
        request.environment = "files"
        request.inputs.append(input_file(pb, "input.csv", (fixture / "input.csv").read_bytes()))
    elif case in ("png", "pdf"):
        request.kind = "render"
        request.environment = "browser"
        request.memory_mb = 1024
        request.render_format = case
        request.inputs.append(input_file(pb, "render.html", (fixture / "render.html").read_bytes()))
    elif case == "gateway":
        # 此样例仅验证测试模式通道，连接器和认证材料均为合成数据。
        request.kind = "skill"
        request.entrypoint = "inputs/gateway.py"
        code = b"""import json,os,urllib.request
from pathlib import Path
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
messages=[{'type':'model','operation':'complete','arguments':{}},{'type':'tool','operation':'echo','arguments':{'value':'synthetic'}},{'type':'tool','operation':'key_demo','arguments':{}}]
results=[]
for message in messages:
 request=urllib.request.Request(os.environ['LAZYX_GATEWAY']+'/request',data=json.dumps(message).encode(),headers={'Content-Type':'application/json'})
 with opener.open(request,timeout=8) as response:results.append(json.load(response))
Path('out/gateway.json').write_text(json.dumps(results,ensure_ascii=False))
"""
        request.inputs.append(input_file(pb, "gateway.py", code))
    elif case == "deps-python":
        request.dependencies.extend(['requests==2.32.3'])
        request.code = b"import requests,json; from pathlib import Path; Path('out/dependencies.json').write_text(json.dumps({'package':'requests','version':requests.__version__}))"
    elif case == "deps-source":
        request.dependencies.extend(['netifaces==0.11.0'])
        request.code = b"import netifaces,json; from pathlib import Path; Path('out/dependencies.json').write_text(json.dumps({'package':'netifaces','interfaces':netifaces.interfaces()}))"
    elif case == "deps-node":
        request.environment = 'node'
        request.dependencies.extend(['esbuild@0.25.0','lodash-es@4.17.21'])
        request.code = b"const fs=require('fs');const esbuild=require('esbuild'); import('lodash-es').then(m=>{const transformed=esbuild.transformSync('const n: number = 1',{loader:'ts'}).code; fs.writeFileSync('out/dependencies.json',JSON.stringify({package:'esbuild',version:esbuild.version,value:m.sum([2,3]),compiled:transformed.includes('const n = 1')}));});"
    elif case == "cancel":
        request.code = b"import time\nprint('cancellation demo started',flush=True)\ntime.sleep(90)\n"
        request.timeout_seconds = 120
    else:
        raise ValueError("未知人工复验项目")
    return request


def wait_finished(stub, reference, *, deadline):
    # 执行终态和资源清理分别判断，得到结果不表示容器已回收。
    while time.monotonic() < deadline:
        status = stub.Status(reference, timeout=5)
        if status.outcome in FINISHED and status.cleanup_done:
            return status
        time.sleep(0.2)
    raise RuntimeError("任务或清理未在人工复验期限内结束")


def checked_artifacts(result):
    # 落盘前检查路径、额度与摘要，不能直接信任远端返回的产物名称。
    if len(result.artifacts) > 8:
        raise ValueError("返回产物过多")
    total = 0
    names = set()
    for artifact in result.artifacts:
        path = PurePosixPath(artifact.path)
        if (not artifact.path or path.is_absolute() or ".." in path.parts or "\\" in artifact.path
                or len(artifact.path) > 1024 or any(ord(char) < 32 for char in artifact.path)
                or artifact.path in names):
            raise ValueError("返回产物路径不合法")
        names.add(artifact.path)
        total += len(artifact.data)
        if len(artifact.data) > 2 * 1024 * 1024 or total > 4 * 1024 * 1024:
            raise ValueError("返回产物超过大小限制")
        if hashlib.sha256(artifact.data).hexdigest() != artifact.sha256:
            raise ValueError("返回产物摘要校验失败")
    return result.artifacts


def assert_result(case, result, *, audit_bad=False):
    data = {entry.path: entry.data for entry in checked_artifacts(result)}
    if case in ("python", "node"):
        if json.loads(data["result.json"])["value"] != 5:
            raise ValueError("计算结果错误")
    elif case == "skill":
        summary = json.loads(data["summary.json"])
        if summary != {"items": 2, "quantity": 5, "amount": 13.0}:
            raise ValueError("技能汇总结果错误")
    elif case == "web":
        page = json.loads(data["webpage.json"])
        if "fixture:" not in page["text"] or page["url"] != "https://allowed.test/":
            raise ValueError("合成网页解析结果错误")
    elif case == "parse":
        if len(json.loads(data["parsed.json"])["content"]) != 2:
            raise ValueError("CSV 解析结果错误")
    elif case == "png":
        if not data["render.png"].startswith(b"\x89PNG\r\n\x1a\n"):
            raise ValueError("长图不是 PNG 文件")
    elif case == "pdf":
        if not data["render.pdf"].startswith(b"%PDF-"):
            raise ValueError("输出不是 PDF 文件")
    elif case == "audit":
        if json.loads(data["audit.json"])["passed"] != (not audit_bad):
            raise ValueError("技能审核结果错误")
    elif case.startswith('deps-'):
        result_data = json.loads(data['dependencies.json'])
        if case=='deps-python' and result_data.get('version')!='2.32.3':raise ValueError('Python 依赖不匹配')
        if case=='deps-node' and (result_data.get('value')!=5 or result_data.get('compiled') is not True):raise ValueError('Node 依赖不匹配')
        if case=='deps-source' and not result_data.get('interfaces'):raise ValueError('原生扩展执行失败')
    elif case == "gateway":
        responses = json.loads(data["gateway.json"])
        if (len(responses) != 3 or responses[0].get("module") != "06"
                or responses[1].get("module") != "02" or responses[2].get("module") != "02"
                or any(response.get("status") != "ok" for response in responses)
                or responses[2].get("result", {}).get("credential_used") is not True
                or set(responses[2]["result"]) != {"value", "credential_used"}):
            raise ValueError("模型或工具转交流程错误")
        if "authorization" in json.dumps(responses).lower():
            raise ValueError("返回中包含认证字段")


def run_job(case, stub, pb, *, audit_bad=False):
    """提交、等待清理、核对结果并确认接收，失败时尝试取消未完成任务。"""
    request = make_request(case, pb, audit_bad=audit_bad)
    reference = pb.JobRef(request_id=request.request_id)
    finished = False
    stub.Submit(request, timeout=15)
    print(f"[提交] 已提交 {case} 合成任务", flush=True)
    try:
        if case == "cancel":
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                status = stub.Status(reference, timeout=5)
                if status.phase == "running":
                    break
                if status.outcome:
                    raise RuntimeError("任务在取消前已经结束")
                time.sleep(0.2)
            else:
                raise RuntimeError("未观察到运行中的任务")
            stub.Cancel(reference, timeout=25)
            print("[取消] 已发送取消请求", flush=True)
        status = wait_finished(stub, reference, deadline=time.monotonic() + (600 if case.startswith("deps-") else 150))
        if status.outcome != ("cancelled" if case == "cancel" else "success"):
            raise RuntimeError(f"任务结果不符合预期：{status.outcome}/{status.error_code}")
        result = stub.Result(reference, timeout=15)
        if not result.status.cleanup_done:
            raise RuntimeError("结果尚未确认资源清理")
        assert_result(case, result, audit_bad=audit_bad)
        acknowledged = stub.Acknowledge(reference, timeout=10)
        if not acknowledged.delivery_done or not acknowledged.cleanup_done:
            raise RuntimeError("结果送达确认或清理状态不成立")
        finished = True
        record = {"request_id": request.request_id, "outcome": status.outcome,
                  "cleanup_done": status.cleanup_done, "delivery_done": acknowledged.delivery_done,
                  "elapsed_ms": status.elapsed_ms,
                  "phases": [event.phase for event in status.events],
                  "environment_id":getattr(status,"environment_id",""),
                  "environment_cache_hit":getattr(status,"environment_cache_hit",False)}
        if case.startswith("deps-"):
            print(f"[环境] {status.environment_id}；缓存命中：{status.environment_cache_hit}",flush=True)
        print("[核验] 产物摘要、结果及清理状态通过", flush=True)
        return result, record
    finally:
        if not finished:
            try:
                stub.Cancel(reference, timeout=25)
            except Exception:
                pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case", nargs="?", choices=CASES)
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()
    if args.list:
        print("\n".join(CASES))
        return 0
    if not args.case:
        parser.error("请选择一个人工复验项目")
    from .client import connect
    from .proto import sandbox_pb2 as pb
    channel, stub = connect()
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:8]
    destination = RUN / "manual" / args.case / run_id
    destination.mkdir(parents=True, mode=0o700)
    report = {"case": args.case, "passed": False, "run_id": run_id, "jobs": [], "artifacts": [],
              "scope": "合成输入、内网免认证 gRPC；web 为合成自签源站"}
    try:
        readiness = stub.Ready(pb.Empty(), timeout=10)
        if args.case in ("web", "gateway") and readiness.mode != "test":
            raise RuntimeError("此样例使用合成网站/连接器，请用 SANDBOX_TEST_MODE=1 docker compose up -d 启用测试模式")
        if not readiness.ready:
            raise RuntimeError("独立服务尚未就绪")
        for audit_bad in ((False, True) if args.case == "audit" else (False,)):
            result, record = run_job(args.case, stub, pb, audit_bad=audit_bad)
            report["jobs"].append(record)
            for artifact in checked_artifacts(result):
                relative = ("bad/" if audit_bad else "good/") + artifact.path if args.case == "audit" else artifact.path
                path = destination / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(artifact.data)
                report["artifacts"].append({"path": relative, "size": len(artifact.data), "sha256": artifact.sha256,
                                            "remote_path": str(path)})
        report["passed"] = True
    except Exception as error:
        report["error"] = f"{type(error).__name__}: {error}"[:2000]
    finally:
        channel.close()
        report_path = destination / "report.json"
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
        print(json.dumps({"case": args.case, "report_path": str(report_path), "passed": report["passed"]}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
