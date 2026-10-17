#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# 同一授权程序的目标/检查点矩阵：区分新打开和已有 FD，验证重命名双操作数、别名位合并与规则撤销。
import argparse
from contextlib import ExitStack
import errno
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from management_harness import call
from monitor_harness import MonitorRun
from writer_harness import WriterProcess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-dir', default='build')
    args = parser.parse_args()
    assert os.geteuid() == 0
    build = Path(args.build_dir).resolve()
    with tempfile.TemporaryDirectory(prefix='secmon-writer-scope-') as temporary, ExitStack() as stack:
        root = Path(temporary)
        root.chmod(0o755)
        private = root / 'private'
        private.mkdir(mode=0o700)
        trusted, outsider = root / 'trusted', root / 'outsider'
        for path in (trusted, outsider):
            shutil.copyfile(build / 'secmon-writer-scenario', path)
            path.chmod(0o755)
        alias = root / 'program-alias'
        os.link(trusted, alias)
        files = [root / name for name in ('a', 'b', 'c')]
        for path in files:
            path.write_bytes(b'data'.ljust(4096, b'.'))
            path.chmod(0o666)
        a, b, c = files
        config, control = private / 'policy', private / 'control'
        revision = 0
        monitor = None
        # 在保护启用前创建实验别名；测试进程本身不会获得 link/rename 例外。
        target_alias, src, dst = root / 'target-alias', root / 'rename-src', root / 'rename-dst'
        os.link(a, target_alias)
        os.link(a, src)
        os.link(b, dst)

        def publish(rules, paths=files, failure='ok'):
            nonlocal revision
            revision += 1
            text = f'revision {revision}\n' + ''.join(f'protect "{p}"\n' for p in paths)
            text += ''.join(f'allow-writer "{program}" {uid} "{target}" {operations}\n'
                            for program, uid, target, operations in rules)
            stage = private / 'staging'
            stage.write_text(text)
            stage.chmod(0o600)
            stage.replace(config)
            if monitor is not None:
                reply = call(build / 'secmon', 'reload', control, failure)
                if failure == 'ok':
                    assert reply['revision'] == revision and reply['writer_paths'] == len(rules)
                return reply

        def grant(target, operations, program=trusted, uid=0):
            return program, uid, target, operations

        def attempt(action, target=a, extra=(), expected=0, program=trusted):
            result = subprocess.run([str(program), action, str(target), *map(str, extra)],
                                    capture_output=True, timeout=5)
            assert result.returncode == expected, (action, target, expected, result.returncode, result.stderr)

        live_a = stack.enter_context(WriterProcess(trusted, a))
        live_b = stack.enter_context(WriterProcess(trusted, b))
        other = stack.enter_context(WriterProcess(outsider, a))
        publish([grant(a, 'open-write,write'), grant(b, 'setattr')])
        monitor = stack.enter_context(MonitorRun(build / 'secmon', ['--policy', str(config), '--self-protect', str(control)], seconds=180))
        try:
            baseline = len(list(Path(f'/proc/{monitor.process.pid}/fd').iterdir()))
            assert live_a.request('w') == live_a.request('o') == 0
            assert live_b.request('w') == live_b.request('o') == other.request('w') == errno.EACCES
            for command in ('t', 'm', 'p'):
                assert live_a.request(command) == errno.EACCES
            assert live_a.request('v') == 0
            attempt('write')
            attempt('write', b, expected=errno.EACCES)
            attempt('write', c, expected=errno.EACCES)
            attempt('chmod', b)
            for action in ('chmod', 'utime', 'truncate'):
                attempt(action, expected=errno.EACCES)
            attempt('link', extra=[root / 'denied-link'], expected=errno.EACCES)
            attempt('rename', extra=[root / 'denied-rename'], expected=errno.EACCES)
            attempt('unlink', expected=errno.EACCES)
            # 仅允许已有 FD 写：open-write 与 write 是独立检查点。
            publish([grant(a, 'write')])
            assert live_a.request('w') == 0 and live_a.request('o') == errno.EACCES
            attempt('open-write', expected=errno.EACCES)
            publish([grant(a, 'open-write')])
            attempt('open-write')
            attempt('write', expected=errno.EACCES)
            assert live_a.request('w') == errno.EACCES
            # mmap/mprotect 入口共用 mmap-write，已有 FD 避开新打开的独立授权条件。
            publish([grant(a, 'mmap-write')])
            assert live_a.request('m') == live_a.request('p') == 0
            assert live_a.request('w') == errno.EACCES
            attempt('mmap', expected=errno.EACCES)
            # 本机 FD/路径截断均经过 truncate 与 setattr；只授予其中一个不能完成截断。
            for operations, expected in (('truncate', errno.EACCES), ('setattr', errno.EACCES),
                                         ('truncate,setattr', 0), ('open-write,truncate,setattr', 0), ('all', 0)):
                publish([grant(a, operations)])
                assert live_a.request('t') == expected
                attempt('truncate', expected=expected)
            # 同一执行 inode 的别名、不同目标、不同操作分别合并，不能以最后一条覆盖旧规则位。
            publish([grant(a, 'write'), grant(b, 'write', alias)])
            assert live_a.request('w') == live_b.request('w') == 0
            reply = publish([grant(a, 'all'), grant(b, 'all', alias, 65534)], failure='prepare_failed')
            assert reply['writer_paths'] == 2
            assert live_a.request('w') == live_b.request('w') == 0
            assert len(list(Path(f'/proc/{monitor.process.pid}/fd').iterdir())) == baseline
            # 指向同一目标 inode 的别名规则也应合并，程序对象自身保护优先于任何授权。
            publish([grant(a, 'open-write'), grant(target_alias, 'write', alias), grant(trusted, 'all')],
                    paths=[a, b, c, target_alias, trusted])
            attempt('write')
            attempt('write', target_alias)
            attempt('write', trusted, expected=errno.EACCES)
            # rename 覆盖必须同时有源与被覆盖对象的 rename 权限。
            publish([grant(a, 'rename')])
            attempt('rename', src, [dst], errno.EACCES)
            publish([grant(a, 'rename'), grant(b, 'rename')])
            attempt('rename', src, [dst])
            # link/unlink 作用于固定 inode 的任意硬链接；授权不会扩散到另一个保护对象。
            publish([grant(a, 'link,unlink')])
            linked = root / 'allowed-link'
            attempt('link', a, [linked])
            attempt('unlink', linked)
            attempt('unlink', b, expected=errno.EACCES)
            # 规则重排后位编号变化，旧授权不能误落到新目标；撤销不移除普通 protect。
            publish([grant(b, 'write'), grant(a, 'open-write')])
            assert live_b.request('w') == 0 and live_a.request('w') == errno.EACCES
            publish([])
            assert live_a.request('w') == live_b.request('w') == errno.EACCES
            assert len(list(Path(f'/proc/{monitor.process.pid}/fd').iterdir())) == baseline - 2
        finally:
            call(build / 'secmon', 'stop', control)
            monitor.process.wait(timeout=5)
        print('PASS per-target/checkpoint grants, existing FDs, aliases, rename operands, same-inode UID conflict, reorder/revoke and FD recovery')


if __name__ == '__main__':
    main()
