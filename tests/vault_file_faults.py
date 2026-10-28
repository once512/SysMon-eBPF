#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import argparse
from pathlib import Path
import subprocess
p=argparse.ArgumentParser();p.add_argument('--build-dir',type=Path,default=Path('build'));args=p.parse_args()
subprocess.run([str(args.build_dir.resolve()/'secmon-vault-file-fault-tests')],check=True,timeout=5)
