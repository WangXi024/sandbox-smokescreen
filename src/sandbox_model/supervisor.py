"""单节点服务监督：失联后停止旧控制进程，重新启动时先清理、后接单。"""
import fcntl
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

from .logs import start
from .watchdog import pid_alive, read_private_json

RUN = Path('/run/sandbox_model')
COMPONENTS = {'service':'sandbox_model.service', 'opensandbox':'sandbox_model.opensandbox_process',
              'watchdog':'sandbox_model.watchdog'}


def recorded_pid(component):
    """同时核对 PID 文件和进程模块名，避免 PID 被复用后误杀其他程序。"""
    try:
        pid = int((RUN/(component+'.pid')).read_text())
        command = Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
        module = COMPONENTS[component].encode()
        if any(command[i:i+2] == [b'-m', module] for i in range(len(command)-1)):
            return pid
    except (OSError, ValueError):
        pass
    return None


def stop_components():
    """先恢复暂停进程并请求退出，超时再结束组件进程组及准备子进程。"""
    pids = [pid for component in COMPONENTS if (pid := recorded_pid(component))]
    for pid in pids:
        try:
            os.kill(pid, signal.SIGCONT)
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    end = time.monotonic()+8
    while any(pid_alive(pid) for pid in pids) and time.monotonic()<end:
        time.sleep(.1)
    for pid in pids:
        try:
            # 组件独立进程组；包含未完成的准备子进程，避免恢复时迟到创建。
            if os.getpgid(pid) == pid:
                os.killpg(pid, signal.SIGKILL)
            elif pid_alive(pid):
                os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


def heartbeat_ok(pid):
    """心跳必须来自当前管理进程，旧快照不能证明新实例健康。"""
    try:
        snapshot = read_private_json(RUN/'leases.json')
        return snapshot['manager_pid']==pid and 0 <= time.time()-snapshot['heartbeat'] < 8
    except (OSError, ValueError, KeyError):
        return False


def main():
    """以文件锁限制单个监督实例，按停止旧进程、恢复服务的顺序循环。"""
    RUN.mkdir(parents=True, exist_ok=True)
    os.umask(0o077)
    with (RUN/'supervisor.lock').open('w') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        (RUN/'supervisor.pid').write_text(str(os.getpid()))
        stopping = False
        def stop(*_):
            nonlocal stopping
            stopping = True
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        try:
            while not stopping:
                stop_components()
                if stopping:
                    break
                # leases 保存旧网络恢复信息，不能在重新对账前删除。
                (RUN/'watchdog-heartbeat.json').unlink(missing_ok=True)
                # 重启过程中到达的请求由这次启动满足，不能启动后立刻再杀一次。
                (RUN/'restart-request').unlink(missing_ok=True)
                process = start([sys.executable,'-B','-m','sandbox_model.service'], RUN/'service.log')
                started = time.monotonic()
                while not stopping and process.poll() is None:
                    if (RUN/'restart-request').exists():
                        break
                    if time.monotonic()-started>90 and not heartbeat_ok(process.pid):
                        print('[恢复] 管理服务心跳丢失，重新清理并启动', flush=True)
                        break
                    # 已成功启动过的进程不再享有启动等待窗口。
                    if heartbeat_ok(process.pid):
                        started = min(started, time.monotonic()-90)
                    time.sleep(.5)
                if process.poll() is None:
                    process.terminate()
                stop_components()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait()
                if not stopping:
                    print('[恢复] 旧服务已停止，等待资源对账后恢复', flush=True)
                    time.sleep(2)
        finally:
            stop_components()
            (RUN/'supervisor.pid').unlink(missing_ok=True)


if __name__ == '__main__':
    main()
