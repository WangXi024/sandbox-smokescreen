"""读取可信宿主 cgroup v2 计数；不使用任务进程自报数据。"""
from pathlib import Path
import re
import time

CGROUP = Path('/sys/fs/cgroup')
PROC = Path('/proc')
FIELDS = ('cpu_usage_usec', 'peak_memory_bytes', 'cpu_usage_available',
          'peak_memory_available', 'resource_sample_unix_ms', 'resource_usage_final')


def bind(job, container):
    """只绑定已核对任务标签的执行容器，拒绝节点根组和代理容器。"""
    labels = container.labels or {}
    if labels.get('lazyx.job') != job['request_id'] or not labels.get('opensandbox.io/id'):
        return
    ident = container.id
    if (not re.fullmatch(r'[0-9a-f]{64}', ident)
            or container.attrs['HostConfig']['Runtime'] != 'runsc'):
        return
    try:
        pid = int(container.attrs['State']['Pid'])
        if pid <= 0:return
        value = next(line[3:] for line in (PROC/str(pid)/'cgroup').read_text().splitlines()
                     if line.startswith('0::'))
        path = (CGROUP/value.lstrip('/')).resolve()
        # Docker cgroupfs 与 systemd 的容器路径都必须包含完整容器 ID。
        if (not path.is_relative_to(CGROUP.resolve()) or
                not {ident, 'docker-'+ident+'.scope'}.intersection(path.parts)):
            return
        job['_usage_path'] = path
    except (OSError, ValueError, KeyError, StopIteration):
        return


def sample(job, *, final=False):
    """读取内核累计 CPU 微秒和内存峰值；读不到时保留可用标记而不伪造零值。

    final 用于销毁前的最后一次采样；只有两项都读到才标记最终计量完整。
    """
    path = job.get('_usage_path')
    if path is None:return
    if job.get('_usage_closed') and not final:return
    cpu = memory = False
    try:
        values = dict(line.split() for line in (path/'cpu.stat').read_text().splitlines())
        value = int(values['usage_usec'])
        if not 0 <= value < 2**64:raise ValueError()
        job['cpu_usage_usec'] = max(job.get('cpu_usage_usec', 0), value)
        job['cpu_usage_available'] = cpu = True
    except (OSError, ValueError, KeyError):
        pass
    try:
        value = int((path/'memory.peak').read_text())
        if not 0 <= value < 2**64:raise ValueError()
        job['peak_memory_bytes'] = max(job.get('peak_memory_bytes', 0), value)
        job['peak_memory_available'] = memory = True
    except (OSError, ValueError):
        pass
    if cpu or memory:job['resource_sample_unix_ms'] = int(time.time()*1000)
    if final:
        job['_usage_closed'] = True
        job['resource_usage_final'] = cpu and memory
