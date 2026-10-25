import concurrent.futures
import hashlib
import os
from pathlib import Path
import socket
import ssl
import threading
import time
from urllib.parse import urlsplit

PROXY = urlsplit(os.environ["HTTPS_PROXY"])
GATEWAY = urlsplit(os.environ["LAZYX_GATEWAY"]).hostname


def connect(host, timeout=30, port=443):
    sock = socket.create_connection((PROXY.hostname, PROXY.port), timeout)
    sock.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
    header = b""
    while not header.endswith(b"\r\n\r\n"):
        chunk = sock.recv(1)
        if not chunk or len(header) > 8192:
            sock.close()
            raise OSError("CONNECT header incomplete")
        header += chunk
    status = int(header.split()[1])
    if status != 200:
        sock.close()
        raise OSError("CONNECT denied")
    return sock


def tls(action):
    sock = None
    try:
        host = action.get("host", "allowed.test")
        sock = connect(host, action.get("timeout", 30))
        ctx = ssl._create_unverified_context()  # 仅合成证书；公开网络使用系统验证。
        if action.get("verify"):
            ctx = ssl.create_default_context()
        sni = action.get("sni", host)
        peer = ctx.wrap_socket(sock, server_hostname=sni)
        fingerprint = hashlib.sha256(peer.getpeercert(binary_form=True)).hexdigest()
        path = action.get("path", "/")
        peer.sendall(f"GET {path} HTTP/1.1\r\nHost: {action.get('http_host', host)}\r\nConnection: close\r\n\r\n".encode())
        body = b""
        while len(body) < 65536:
            chunk = peer.recv(4096)
            if not chunk:
                break
            body += chunk
        peer.close()
        status_line = body.split(b"\r\n", 1)[0].split()
        status = int(status_line[1]) if len(status_line) > 1 and status_line[1].isdigit() else None
        return {"tls": True, "certificate": fingerprint, "bytes": len(body),
                "fixture": b"fixture:" in body, "requested_host": host, "sni": sni,
                "http_status": status, "tls_verified": bool(action.get("verify")),
                "example_domain": b"Example Domain" in body}
    except (OSError, ssl.SSLError) as error:
        if sock:
            sock.close()
        return {"tls": False, "error": type(error).__name__,
                "requested_host": action.get("host", "allowed.test"),
                "sni": action.get("sni", action.get("host", "allowed.test"))}


def run(action):
    mode = action.get("mode", "tls")
    if mode == "batch":
        actions = action["actions"]
        if action.get("synchronize") and not 0 < len(actions) <= 12:
            raise ValueError("同步探针必须有1至12个请求")
        barrier = threading.Barrier(len(actions)) if action.get("synchronize") else None
        def request(value):
            if barrier:
                barrier.wait(timeout=5)
            return tls(value)
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            return list(pool.map(request, actions))
    if mode == "capacity":
        held = connect("allowed.test", timeout=3)
        try:
            try:
                other = connect("allowed.test", timeout=3)
                other.close()
                denied = False
            except OSError:
                denied = True
        finally:
            held.close()
        time.sleep(.3)
        return {"overflow_denied": denied, "recovered": tls({}).get("fixture", False)}
    if mode == "plain":
        try:
            sock = connect("allowed.test")
            sock.sendall(b"GET /plain-negative HTTP/1.1\r\nHost: allowed.test\r\n\r\n")
            body = sock.recv(8192)
            sock.close()
            return {"origin_reached": b"fixture:" in body}
        except OSError:
            return {"origin_reached": False}
    if mode == "ech":
        ctx = ssl.create_default_context()
        outgoing = ssl.MemoryBIO()
        peer = ctx.wrap_bio(ssl.MemoryBIO(), outgoing, server_side=False, server_hostname="allowed.test")
        try:
            peer.do_handshake()
        except ssl.SSLWantReadError:
            pass
        wire = outgoing.read()
        hello = bytearray(wire[5:])
        pos = 38
        pos += 1 + hello[pos]
        pos += 2 + int.from_bytes(hello[pos:pos + 2], "big")
        pos += 1 + hello[pos]
        extension = bytes.fromhex("fe0d000400000000")
        hello[pos:pos + 2] = (int.from_bytes(hello[pos:pos + 2], "big") + len(extension)).to_bytes(2, "big")
        hello.extend(extension)
        hello[1:4] = (len(hello) - 4).to_bytes(3, "big")
        wire = wire[:3] + len(hello).to_bytes(2, "big") + hello
        Path("/workspace/out/ech.bin").write_bytes(wire)
        try:
            sock = connect("allowed.test")
            sock.sendall(wire)
            response = sock.recv(8192)
            sock.close()
            return {"tls_record": len(response) >= 5 and response[0] == 22}
        except OSError:
            return {"tls_record": False}
    if mode == "raw":
        allowed = []
        for family, kind, protocol in ((socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW),
                                       (socket.AF_PACKET, socket.SOCK_RAW, 3)):
            try:
                sock = socket.socket(family, kind, protocol)
                sock.close()
                allowed.append(True)
            except OSError:
                allowed.append(False)
        return {"raw_sockets": allowed}
    if mode == "direct":
        results = {}
        addresses = action.get("addresses", [[GATEWAY, 18080], [GATEWAY, 18443],
            [GATEWAY, 44772], ["172.27.250.10", 443], ["1.1.1.1", 443],
            ["169.254.169.254", 80], ["100.100.100.200", 80]])
        for address, port in addresses:
            try:
                sock = socket.create_connection((address, port), .7)
                sock.close()
                results[str(address) + ":" + str(port)] = True
            except OSError:
                results[str(address) + ":" + str(port)] = False
        return results
    if mode == "dns":
        import struct
        name = action["name"]
        wire = b"\0\1\1\0\0\1\0\0\0\0\0\0"
        wire += b"".join(bytes([len(part)]) + part.encode() for part in name.split(".")) + b"\0\0\1\0\1"
        success = []
        for address in ("172.27.250.53", "1.1.1.1", "127.0.0.11"):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(.5)
            try:
                sock.sendto(wire, (address, 53))
                reply = sock.recv(8192)
                success.append(bool(reply and reply[:2] == b"\0\1"))
            except OSError:
                success.append(False)
            finally:
                sock.close()
        return {"dns_responses": success}
    if mode == "ipv6":
        try:
            sock = socket.create_connection(("2606:4700:4700::1111", 443), .7)
            sock.close()
            return {"connected": True}
        except OSError:
            return {"connected": False}
    return tls(action)
