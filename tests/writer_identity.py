#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# root 专题：按真实执行对象和 EUID 授权，验证 fork/exec、别名、路径替换、撤销与失败回滚。
# 只复制专用小程序，不把系统解释器或 shell 加入授权列表；临时对象退出后全部回收。
import argparse
import errno
import os
from pathlib import Path
import shutil
import sys
import subprocess
import tempfile
from monitor_harness import MonitorRun
from writer_harness import WriterProcess
from management_harness import call


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-dir', default='build')
    args = parser.parse_args()
    assert os.geteuid() == 0
    build = Path(args.build_dir).resolve()
    binary = build / 'secmon'
    with tempfile.TemporaryDirectory(prefix='secmon-writers-') as tmp:
        root = Path(tmp)
        os.chmod(root, 0o755)
        programs = root / 'programs'
        programs.mkdir()
        trusted, other = programs / 'trusted', root / 'other'
        for path in (trusted, other):
            shutil.copyfile(build / 'secmon-writer-scenario', path)
            path.chmod(0o755)
        alias = root / 'alias'
        os.link(trusted, alias)
        target = root / 'target'
        target.write_bytes(b'original' + b'\0' * 4096)
        target.chmod(0o666)
        private = root / 'private'
        private.mkdir(mode=0o700)
        config, control = root / 'policy', private / 'control'

        def publish(revision, writers, paths=None):
            staging = root / 'staging'
            staging.write_text('revision ' + str(revision) + '\n' +
                               ''.join(f'protect "{p}"\n' for p in ([target] if paths is None else paths)) +
                               ''.join(f'allow-writer "{p}" {uid}\n' for p, uid in writers))
            staging.chmod(0o600)
            staging.replace(config)

        def run(exe, action='write', path=target, extra=(), expected=0):
            result = subprocess.run([str(exe), action, str(path), *map(str, extra)],
                                    capture_output=True, timeout=5)
            assert result.returncode == expected, (exe, action, result.returncode, expected, result.stderr)

        publish(1, [(trusted, 0)])
        with WriterProcess(trusted, target) as live_trusted, WriterProcess(other, target) as live_other, \
                MonitorRun(binary, ['--policy', str(config), '--self-protect', str(control)], seconds=180) as monitor:
            try:
                base_fds = len(list(Path(f'/proc/{monitor.process.pid}/fd').iterdir()))
                assert live_trusted.request() == 0 and live_other.request() == errno.EACCES
                run(other, expected=errno.EACCES)
                run(trusted)
                run(alias)
                run(trusted, 'fork-write')
                run(trusted, 'exec-write', extra=[other], expected=errno.EACCES)
                run(other, 'exec-write', extra=[trusted])
                run(trusted, 'uid-write', extra=[65534], expected=errno.EACCES)
                run(trusted, 'mmap')
                for command in ('w', 'o', 't', 'm', 'p'):
                    assert live_trusted.request(command) == 0
                    assert live_other.request(command) == errno.EACCES
                assert live_trusted.request('v') == live_other.request('v') == 0
                # argv[0]、同名文件和脚本路径不构成执行对象身份。
                spoofed = subprocess.run([str(trusted), 'write', str(target)], executable=str(other),
                                         capture_output=True, timeout=5)
                assert spoofed.returncode == errno.EACCES
                data_alias = root / 'data-alias'
                run(trusted, 'link', target, [data_alias])
                run(other, path=data_alias, expected=errno.EACCES)
                run(trusted, 'utime')
                run(other, 'utime', expected=errno.EACCES)
                run(trusted, 'unlink', data_alias)
                relocated = root / 'relocated-data'
                run(trusted, 'rename', target, [relocated])
                run(other, path=relocated, expected=errno.EACCES)
                run(trusted, 'rename', relocated, [target])
                # 选中的程序 inode 即使来自授权调用者也禁止属性修改/删除；未运行时同样受到保护。
                run(trusted, 'chmod', trusted, expected=errno.EACCES)
                run(other, 'chmod', trusted, expected=errno.EACCES)
                run(trusted, 'unlink', alias, expected=errno.EACCES)
                run(trusted, 'link', alias, [root / 'new-program-alias'], errno.EACCES)
                run(trusted, 'rename', alias, [root / 'renamed-alias'], errno.EACCES)
                replacement = root / 'replacement'
                replacement.write_bytes(b'not executable content')
                run(trusted, 'rename', replacement, [alias], errno.EACCES)
                # 父目录不受递归保护；改变路径解析不会把授权转移给同名新 inode。
                programs.rename(root / 'moved')
                programs.mkdir()
                shutil.copyfile(other, trusted)
                trusted.chmod(0o755)
                run(trusted, expected=errno.EACCES)
                moved = root / 'moved' / 'trusted'
                run(moved)
                initial_status = call(binary, 'status', control)
                assert initial_status['revision'] == 1 and initial_status['writer_paths'] == 1
                # 缺失/非普通/末尾 symlink/不安全权限，以及一个 inode 的冲突 UID 都必须保留旧版。
                unsafe = root / 'unsafe'
                shutil.copyfile(other, unsafe)
                unsafe.chmod(0o777)
                noexec, not_root = root / 'noexec', root / 'not-root'
                for path in (noexec, not_root):
                    shutil.copyfile(other, path)
                noexec.chmod(0o600)
                not_root.chmod(0o755)
                os.chown(not_root, 65534, 65534)
                link = root / 'symlink'
                link.symlink_to(moved)
                for writers in ([(root / 'missing', 0)], [(root, 0)], [(link, 0)], [(unsafe, 0)], [(noexec, 0)], [(not_root, 0)],
                                [(moved, 0), (alias, 65534)]):
                    publish(2, writers)
                    reply = call(binary, 'reload', control, 'prepare_failed')
                    assert reply['revision'] == 1
                    run(moved)
                    run(trusted, expected=errno.EACCES)
                    assert len(list(Path(f'/proc/{monitor.process.pid}/fd').iterdir())) == base_fds
                # 同一候选修正后仍可用 revision 2；动态读取有效 UID，root 不拥有隐式例外。
                publish(2, [(moved, 65534)])
                call(binary, 'reload', control)
                run(moved, expected=errno.EACCES)
                run(moved, 'uid-write', extra=[65534])
                run(other, 'uid-write', extra=[65534], expected=errno.EACCES)
                assert live_trusted.request() == errno.EACCES
                publish(3, [])
                assert call(binary, 'reload', control)['writer_paths'] == 0
                run(moved, 'uid-write', extra=[65534], expected=errno.EACCES)
                for command in ('w', 'o', 't', 'm', 'p'):
                    assert live_trusted.request(command) == live_other.request(command) == errno.EACCES
                assert live_trusted.request('v') == live_other.request('v') == 0
                # 授权撤销也释放程序自动保护；目标的普通 protect 仍然有效。
                run(other, 'chmod', moved)
                assert len(list(Path(f'/proc/{monitor.process.pid}/fd').iterdir())) == base_fds - 1
                publish(4, [], [])
                call(binary, 'reload', control)
                run(other)
                assert live_trusted.request() == 0 and live_other.request() == 0
                # shebang 脚本自身不是 mm->exe_file；只信任脚本 inode 不会误授权系统解释器。
                script = root / 'script-writer'
                script.write_text('#!' + sys.executable + '\nimport os, sys\n'
                                  'try:\n fd = os.open(sys.argv[1], os.O_WRONLY); os.close(fd)\n'
                                  'except OSError as error:\n sys.exit(error.errno)\n')
                script.chmod(0o755)
                publish(5, [(script, 0)])
                assert call(binary, 'reload', control)['writer_paths'] == 1
                scripted = subprocess.run([str(script), str(target)], capture_output=True, timeout=5)
                assert scripted.returncode == errno.EACCES, scripted.stderr
                publish(6, [], [])
                call(binary, 'reload', control)
            finally:
                subprocess.run([str(binary), '--stop', str(control)], check=True, capture_output=True, timeout=5)
                monitor.process.wait(timeout=5)
        print('PASS executable inode/EUID authorization, aliases, fork/exec, path replacement, immutable identity, rollback and revoke')


if __name__ == '__main__':
    main()
