#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# 有 root 身份才可建立管理端；此专题不挂载 BPF 或 fanotify，只运行管理事件循环的无阻塞回归。
import argparse
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-dir', default='build')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('requires root control-service identity')
    subprocess.run([str(Path(args.build_dir).resolve() / 'secmon-control-loop-tests')], check=True, timeout=5)


if __name__ == '__main__':
    main()
