#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import argparse
import subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--binary',type=Path,required=True);args=p.parse_args()
binary=str(args.binary.resolve())
assert subprocess.run([binary,'--help'],capture_output=True).returncode==0
base=['--policy','/etc/secmon/policy.conf','--socket','/run/secmon/control']
for cmd in ([],['bogus'],['status'],['status',*base,'--id','1'],['status',*base,'--policy','/again'],
            ['open',*base],['close',*base,'--id','0'],['lock',*base],
            ['open',*base,'--program','/client','--uid','-1','--target','/secret','--mode','read','--duration-ms','100'],
            ['open',*base,'--program','/client','--uid','0','--target','/secret','--mode','write','--duration-ms','100'],
            ['open',*base,'--program','relative','--uid','0','--target','/secret','--mode','read','--duration-ms','100'],
            ['close',*base,'--id','18446744073709551616'],['lock',*base,'--target','/secret','--expect-revision','0']):
 r=subprocess.run([binary,*cmd],capture_output=True,timeout=3)
 assert r.returncode==2,(cmd,r.returncode,r.stderr)
print('PASS vaultctl help and command/option/numeric boundaries')
