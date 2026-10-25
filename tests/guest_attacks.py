"""不可信任务内的合成攻击探针；仅输出判定，不输出环境值或凭据。"""
import json
import os
from pathlib import Path
import socket
import urllib.error
import urllib.request
from urllib.parse import urlsplit


def denied_http(url, headers=None):
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(urllib.request.Request(url, headers=headers or {}), timeout=.8) as response:
            return response.status in (401, 403)
    except urllib.error.HTTPError as error:
        return error.code in (401, 403)
    except (OSError, urllib.error.URLError):
        return True


def denied_tcp(host, port):
    try:
        with socket.create_connection((host, port), timeout=.6):
            return False
    except OSError:
        return True


def spoofed_peer_blocked(gateway, host, option):
    sock = socket.socket()
    sock.settimeout(.7)
    try:
        if option:
            sock.setsockopt(socket.SOL_IP, option, 1)
        sock.bind((gateway, 0))
        sock.connect((host, 44772))
        sock.sendall(b"GET /ping HTTP/1.0\r\nHost: x\r\n\r\n")
        result = sock.recv(256)
        return b" 403 " in result or b" 401 " in result
    except OSError:
        return True
    finally:
        sock.close()


def run(extra_target=None):
    results = {}
    gateway = urlsplit(os.environ["LAZYX_GATEWAY"]).hostname
    results["nonroot_uid"] = os.getuid() == 1000 and os.getgid() == 1000
    status = Path('/proc/self/status').read_text()
    fields = {line.split(':', 1)[0]: line.split(':', 1)[1].strip() for line in status.splitlines() if ':' in line}
    results['zero_capabilities'] = all(int(fields.get(key, '1'), 16) == 0 for key in ('CapEff', 'CapPrm', 'CapAmb'))
    results['no_new_privileges'] = fields.get('NoNewPrivs') == '1'
    secret_names = [name for name in os.environ if any(part in name.upper() for part in ('TOKEN', 'PASSWORD', 'SECRET', 'API_KEY', 'APIKEY', 'PERMIT'))]
    results['no_secret_environment'] = not secret_names
    try:
        os.setuid(0)
        results['cannot_become_root'] = False
    except PermissionError:
        results['cannot_become_root'] = True
    try:
        raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        raw.close()
        results['raw_socket_denied'] = False
    except PermissionError:
        results['raw_socket_denied'] = True
    for name, path in [('rootfs', '/etc/task-write-probe'), ('platform', '/opt/platform/task-write-probe')]:
        try:
            Path(path).write_text('synthetic')
            results[name + '_write_denied'] = False
        except OSError:
            results[name + '_write_denied'] = True
    for name, url in [
        ('loopback_api', 'http://127.0.0.1:44772/ping'),
        ('host_opensandbox', f'http://{gateway}:8080/v1/sandboxes'),
        ('host_service', f'http://{gateway}:18443/'),
        ('metadata', 'http://169.254.169.254/'),
        ('private', 'http://10.0.0.1/'),
    ]:
        results[name + '_denied'] = denied_http(url, {'X-Forwarded-For': gateway, 'X-Real-IP': gateway})
    own_ip = None
    # 找实际eth0地址，不依赖外部DNS；Linux ioctl不需要网络能力。
    try:
        import fcntl
        import struct
        control = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        own_ip = socket.inet_ntoa(fcntl.ioctl(control.fileno(), 0x8915, struct.pack('256s', b'eth0'))[20:24])
        control.close()
    except OSError:
        pass
    results['own_ip_discovered'] = own_ip is not None
    if own_ip:
        results['own_api_denied'] = denied_http(f'http://{own_ip}:44772/ping', {'X-Forwarded-For': gateway})
    for label, option in [('bind', 0), ('freebind', 15), ('transparent', 19)]:
        for destination in ('127.0.0.1', own_ip):
            if destination:
                results[f'control_source_spoof_{label}_{"loopback" if destination == "127.0.0.1" else "own"}_denied'] = spoofed_peer_blocked(gateway, destination, option)
    results['direct_public_denied'] = denied_tcp('1.1.1.1', 443)
    results['alternate_dns_denied'] = denied_tcp('1.1.1.1', 53)
    try:
        ipv6 = socket.socket(socket.AF_INET6)
        ipv6.settimeout(.7)
        ipv6.connect(('2606:4700:4700::1111', 443))
        results['ipv6_denied'] = False
    except OSError:
        results['ipv6_denied'] = True
    finally:
        if 'ipv6' in locals():
            ipv6.close()
    if extra_target:
        results['other_task_control_denied'] = denied_tcp(extra_target, 44772)
        results['other_task_port_denied'] = denied_tcp(extra_target, 9000)
    results['docker_socket_absent'] = not Path('/var/run/docker.sock').exists()
    results['permit_key_absent'] = not Path('/run/sandbox_model/permit.key').exists()
    results['guest_kernel_gvisor'] = 'gvisor' in Path('/proc/version').read_text().lower()
    return results


if __name__ == '__main__':
    Path('/workspace/out/attestation.json').write_text(json.dumps(run(), sort_keys=True))
