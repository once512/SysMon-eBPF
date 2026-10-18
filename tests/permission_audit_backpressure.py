#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise fanotify-only and shared BPF/fanotify audit output under real backpressure."""
import sys
from audit_backpressure import main

if __name__ == '__main__':
    for module in ([], ['--fanotify-only']):
        main([*sys.argv[1:], '--permission-audit', *module])
