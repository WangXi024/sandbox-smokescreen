#!/usr/bin/env python3
"""停止本项目的 Compose，并删除专用镜像缓存和状态卷。"""
import sys
sys.dont_write_bytecode = True
from compose_host import compose

if __name__ == "__main__":
    # --volumes 会连同本项目的公共镜像缓存和状态元数据一起删除。
    raise SystemExit(compose("down", "--volumes", "--remove-orphans").returncode)
