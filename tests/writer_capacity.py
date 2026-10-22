#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# 把 256 个保护对象与 64 个执行对象同时装入真实候选 Map，核对极限容量、重复键合并和回滚。
import argparse
import errno
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from monitor_harness import MonitorRun
from management_harness import call
from file_policy_map import PolicyMapView, key_for, policy_outer_ids


def denied(operation):
    try:
        operation()
    except OSError as error:
        assert error.errno == errno.EACCES, error
        return
    raise AssertionError('protected operation accepted')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-dir', default='build')
    args = parser.parse_args()
    assert os.geteuid() == 0
    build = Path(args.build_dir).resolve()
    with tempfile.TemporaryDirectory(prefix='secmon-writer-capacity-') as tmp:
        root = Path(tmp)
        root.chmod(0o700)
        files = [root / f'data-{i}' for i in range(256)]
        writers = [root / f'writer-{i}' for i in range(64)]
        for path in files:
            path.write_bytes(b'data')
        for path in writers:
            shutil.copyfile(build / 'secmon-writer-scenario', path)
            path.chmod(0o755)
        config, control = root / 'policy', root / 'control'

        def publish(revision, paths, identities):
            stage = root / 'staging'
            stage.write_text(f'revision {revision}\n' +
                             ''.join(f'protect "{p}"\n' for p in paths) +
                             ''.join(f'allow-writer "{p}" 0 "{paths[0]}" all\n' for p in identities))
            stage.chmod(0o600)
            stage.replace(config)

        def mutate(path):
            fd = os.open(path, os.O_WRONLY | os.O_CLOEXEC)
            os.close(fd)

        publish(1, [], [])
        before_maps = policy_outer_ids()
        with MonitorRun(build / 'secmon', ['--policy', str(config), '--self-protect', str(control)], seconds=120) as monitor:
            try:
                created = policy_outer_ids() - before_maps
                assert len(created) == 1, 'ambiguous monitor creation; do not choose another instance Map'
                outer_id = created.pop()
                def fds(): return len(list(Path(f'/proc/{monitor.process.pid}/fd').iterdir()))
                baseline = fds()
                publish(2, files, writers)
                reply = call(build / 'secmon', 'reload', control)
                assert reply['protected_paths'] == 256 and reply['writer_paths'] == 64
                assert fds() == baseline + 320
                old_view = PolicyMapView(outer_id)
                try:
                    entries = old_view.entries()
                    assert len(entries) == 320
                    detailed = old_view.entries(full=True)
                    # 第 63 位也必须保留；所有规则只授予 files[0]，不能扩散到其余 255 个对象。
                    assert detailed[key_for(files[0])][3] == ((1 << 64) - 1,) * 13
                    assert all(detailed[key_for(p)][3] == (0,) * 13 for p in files[1:])
                    assert all(detailed[key_for(p)][2] == 1 << i for i, p in enumerate(writers))
                    assert all(entries[key_for(p)] == (1, 0) for p in files)
                    assert all(entries[key_for(p)] == (6, 0) for p in writers)
                except BaseException:
                    old_view.close()
                    raise
                for path in files:
                    denied(lambda p=path: mutate(p))
                for writer in writers:
                    denied(lambda p=writer: p.chmod(0o700))
                    subprocess.run([str(writer), 'write', str(files[0])], check=True, timeout=5)
                # 最后一个 writer 准备失败，已准备的 319 个资源必须全部回收，旧满容量策略不变。
                publish(3, files, writers[:-1] + [root / 'missing'])
                assert call(build / 'secmon', 'reload', control, 'prepare_failed')['revision'] == 2
                assert fds() == baseline + 320
                # 一个对象同时有 readonly/writer/identity 位时，identity 的强制只读优先。
                publish(3, [files[0], writers[0]], [writers[0]])
                call(build / 'secmon', 'reload', control)
                with PolicyMapView(outer_id) as current:
                    assert current.map_id != old_view.map_id
                    assert current.entries() == {key_for(files[0]): (1, 0), key_for(writers[0]): (7, 0)}
                    assert old_view.entries(full=True) == detailed
                    assert old_view.entries() == entries  # 外层已切换，显式持有的旧 Map 仍完整可读。
                old_view.close()
                old_view.wait_gone(old_view.map_id)
                assert fds() == baseline + 3  # 按路径持有 FD；Map 中实际只有两个 key。
                subprocess.run([str(writers[0]), 'write', str(files[0])], check=True, timeout=5)
                denied(lambda: writers[0].chmod(0o700))
                publish(4, [writers[0]], [])
                call(build / 'secmon', 'reload', control)
                assert fds() == baseline + 1
                denied(lambda: writers[0].chmod(0o700))
                publish(5, [], [])
                call(build / 'secmon', 'reload', control)
                assert fds() == baseline
                writers[0].chmod(0o755)
            finally:
                if 'old_view' in locals():
                    old_view.close()
                subprocess.run([str(build / 'secmon'), '--stop', str(control)], check=True, capture_output=True, timeout=5)
                monitor.process.wait(timeout=5)
        print('PASS 320 distinct inodes, 64 writers, full candidate rollback, combined flags, old Map reclamation and exact FD recovery')


if __name__ == '__main__':
    main()
