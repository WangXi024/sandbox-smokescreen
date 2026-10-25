"""管理日志按字节轮转，单组件最多两份、合计 2 MiB，仍只写 /run。"""
from pathlib import Path
import subprocess
import sys
import threading

LIMIT = 1024 * 1024


def consume(stream, path, *, echo=False, limit=LIMIT):
    """按字节分块排空管道，写满后覆盖上一份轮转日志，保持内存日志有界。"""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("ab", buffering=0) as output:
        size = output.tell()
        while chunk := getattr(stream, "read1", stream.read)(16384):
            if echo:
                sys.stdout.buffer.write(chunk)
                sys.stdout.buffer.flush()
            while chunk:
                if size >= limit:
                    output.close()
                    path.replace(path.with_suffix(path.suffix + ".1"))
                    output = path.open("ab", buffering=0)
                    size = 0
                piece, chunk = chunk[:limit-size], chunk[limit-size:]
                output.write(piece)
                size += len(piece)
        output.close()


def start(arguments, path, **kwargs):
    """启动独立进程组并用线程持续收日志，避免管道写满阻塞控制进程。"""
    process = subprocess.Popen(arguments, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               start_new_session=True, **kwargs)
    def drain():
        with process.stdout:
            consume(process.stdout, path)
    threading.Thread(target=drain, daemon=True).start()
    return process


if __name__ == "__main__":
    consume(sys.stdin.buffer, sys.argv[1], echo="--echo" in sys.argv[2:])
