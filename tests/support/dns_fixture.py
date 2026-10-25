"""合成 DNS：在内存中切换 A 记录，用于 DNS 变更与私网回归。仅测试使用。"""
import ipaddress
import json
import socketserver
import struct
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAPPING = {"allowed.test": "172.27.250.10", "second.test": "172.27.250.10"}
QUERIES = []
LOCK = threading.Lock()


def response(wire):
    if len(wire) < 12:
        return b""
    cursor, labels = 12, []
    while cursor < len(wire):
        size = wire[cursor]
        cursor += 1
        if size == 0:
            break
        if size > 63 or cursor + size > len(wire):
            return wire[:2] + b"\x81\x82" + b"\0" * 8
        labels.append(wire[cursor:cursor + size].decode("ascii"))
        cursor += size
    if cursor + 4 > len(wire):
        return b""
    name = ".".join(labels).lower()
    kind, category = struct.unpack("!HH", wire[cursor:cursor + 4])
    question = wire[12:cursor + 4]
    with LOCK:
        address = MAPPING.get(name)
        QUERIES.append({"name": name, "kind": kind, "address": address})
        del QUERIES[:-1000]
    exists = address is not None
    answer = b""
    if address and kind == 1 and category == 1:
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 1, 4) + ipaddress.IPv4Address(address).packed
    flags = 0x8180 if exists else 0x8183
    return wire[:2] + struct.pack("!HHHHH", flags, 1, bool(answer), 0, 0) + question + answer


class UDP(socketserver.BaseRequestHandler):
    def handle(self):
        wire, sock = self.request
        try:
            answer = response(wire)
            if answer:
                sock.sendto(answer, self.client_address)
        except (ValueError, UnicodeError):
            pass


class TCP(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(2)
        header = self.request.recv(2)
        if len(header) != 2:
            return
        size = struct.unpack("!H", header)[0]
        if size > 8192:
            return
        wire = b""
        while len(wire) < size:
            data = self.request.recv(size - len(wire))
            if not data:
                return
            wire += data
        try:
            answer = response(wire)
            self.request.sendall(struct.pack("!H", len(answer)) + answer)
        except (ValueError, UnicodeError):
            pass


class Control(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        with LOCK:
            body = json.dumps({"mapping": MAPPING, "queries": QUERIES}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_PUT(self):
        size = int(self.headers.get("Content-Length", "0"))
        if not 0 < size <= 8192:
            self.send_error(400)
            return
        try:
            mapping = json.loads(self.rfile.read(size))
            if not isinstance(mapping, dict) or len(mapping) > 32:
                raise ValueError()
            validated = {str(name): str(ipaddress.IPv4Address(address))
                         for name, address in mapping.items()}
        except (ValueError, TypeError):
            self.send_error(400)
            return
        with LOCK:
            MAPPING.clear()
            MAPPING.update(validated)
        self.send_response(204)
        self.end_headers()


if __name__ == "__main__":
    udp = socketserver.ThreadingUDPServer(("0.0.0.0", 53), UDP)
    tcp = socketserver.ThreadingTCPServer(("0.0.0.0", 53), TCP)
    threading.Thread(target=udp.serve_forever, daemon=True).start()
    threading.Thread(target=tcp.serve_forever, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", 8053), Control).serve_forever()
