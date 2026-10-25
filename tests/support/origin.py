"""合成 HTTPS 源站：全部请求与断连证据保存在容器 RAM，供独立验收。"""
from collections import deque
import http.server
import json
import os
from pathlib import Path
import ssl
import threading
import time

LOCK = threading.Lock()
REQUESTS = deque(maxlen=1000)
EVENTS = deque(maxlen=1000)
NAME = os.environ.get("ORIGIN_NAME", "public-fixture")


def record(collection, item):
    with LOCK:
        collection.append(item)
        if collection is REQUESTS:
            Path("/dev/shm/requests.jsonl").write_text("".join(json.dumps(value) + "\n" for value in REQUESTS))
        else:
            Path("/dev/shm/stream-events.jsonl").write_text("".join(json.dumps(value) + "\n" for value in EVENTS))


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        if self.path == "/_evidence":
            with LOCK:
                content = json.dumps({"origin": NAME, "requests": list(REQUESTS), "events": list(EVENTS)}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return
        record(REQUESTS, {"host": self.headers.get("Host"), "path": self.path,
                          "origin": NAME, "at": time.monotonic()})
        if self.path.startswith('/quota-download?'):
            self.send_response(200)
            self.send_header('Content-Length', '24576')
            self.end_headers()
            try:self.wfile.write(b'x'*24576)
            except (BrokenPipeError,ConnectionResetError,ssl.SSLError):pass
            return
        if self.path.startswith("/redirect?") or self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "https://blocked.test/redirect-target?" + self.path.partition("?")[2])
            self.end_headers()
            return
        if self.path.startswith("/slow?"):
            time.sleep(20)
        self.send_response(200)
        self.send_header("Connection", "close")
        self.send_header("Content-Type", "application/javascript" if self.path.startswith("/oversize-resource?") else "text/html; charset=utf-8")
        self.end_headers()
        if self.path.startswith("/login?"):
            try:
                self.wfile.write(b'<html><body><form><input type="password"></form></body></html>')
            except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                pass
            return
        if self.path.startswith("/oversize?"):
            try:
                self.wfile.write(b'<html><body>bounded download test<script src="/oversize-resource?' + self.path.partition('?')[2].encode() + b'"></script></body></html>')
            except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                pass
            return
        if self.path.startswith("/oversize-resource?"):
            try:
                self.wfile.write(b'/*' + b'x' * (5 * 1024 * 1024) + b'*/')
            except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                pass
            return
        if self.path.startswith("/stream"):
            stream_id = self.path
            sent = 0
            reason = "completed"
            record(EVENTS, {"event": "start", "stream_id": stream_id, "at": time.monotonic()})
            try:
                for index in range(200):
                    self.wfile.write(f"fixture:{NAME}:{index}\n".encode())
                    self.wfile.flush()
                    sent += 1
                    time.sleep(0.1)
            except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
                reason = "peer_disconnect"
            finally:
                record(EVENTS, {"event": "end", "stream_id": stream_id, "reason": reason,
                               "chunks_sent": sent, "at": time.monotonic()})
            return
        content = f"<!doctype html><html><meta charset='utf-8'><title>Sandbox fixture</title><body><h1>合成公开网页</h1><p>fixture:{NAME}</p><a href='/second'>测试链接</a></body></html>"
        try:
            self.wfile.write(content.encode())
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass

    def do_POST(self):
        if self.path.startswith('/quota-upload?'):
            received=0
            try:
                remaining=min(int(self.headers.get('Content-Length','0')),1048576)
                while remaining:
                    data=self.rfile.read(min(4096,remaining))
                    if not data:break
                    remaining-=len(data);received+=len(data)
                record(EVENTS, {'event':'upload','stream_id':self.path,'bytes':received})
                self.send_response(200);self.end_headers();self.wfile.write(b'OK')
            except (BrokenPipeError,ConnectionResetError,ssl.SSLError):
                record(EVENTS, {'event':'upload','stream_id':self.path,'bytes':received})
            return
        if self.path != "/_reset":
            self.send_error(404)
            return
        with LOCK:
            REQUESTS.clear()
            EVENTS.clear()
            Path("/dev/shm/requests.jsonl").write_text("")
            Path("/dev/shm/stream-events.jsonl").write_text("")
        self.send_response(204)
        self.end_headers()


if __name__ == "__main__":
    plain = http.server.ThreadingHTTPServer(("0.0.0.0", 80), Handler)
    threading.Thread(target=plain.serve_forever, daemon=True).start()
    secure = http.server.ThreadingHTTPServer(("0.0.0.0", 443), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("/fixtures/cert.pem", "/fixtures/key.pem")
    secure.socket = context.wrap_socket(secure.socket, server_side=True)
    secure.serve_forever()
