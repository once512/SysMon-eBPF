#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# 用固定随机种子构建独立 Python 规则模型，逐字核对真实内层 Map，并验证每次确认后的新写操作。
# 只检查本专题启动前后唯一新增的外层 Map，不写其他实例 Map；观察 FD 关闭后旧表应可回收。
import argparse
import errno
import os
from pathlib import Path
import random
import shutil
import subprocess
import tempfile
from file_policy_map import PolicyMapView, key_for, policy_outer_ids
from management_harness import call
from monitor_harness import MonitorRun

OPERATIONS = ('open-write', 'write', 'truncate', 'unlink', 'rename', 'link', 'setattr', 'mmap-write', 'setxattr', 'removexattr', 'setacl', 'removeacl', 'ioctl-write')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--build-dir', default='build')
    parser.add_argument('--iterations', type=int, default=40, help='1..1000; service lifetime scales with iteration count')
    parser.add_argument('--seed', type=int, default=0x53434D)
    args = parser.parse_args()
    if not 1 <= args.iterations <= 1000:
        parser.error('iterations must be 1..1000')
    if os.geteuid() != 0:
        parser.error('requires root/BPF permissions')
    rng = random.Random(args.seed)
    build = Path(args.build_dir).resolve()
    with tempfile.TemporaryDirectory(prefix='secmon-writer-matrix-') as temporary:
        root = Path(temporary)
        programs, targets = [root / f'writer-{i}' for i in range(4)], [root / f'data-{i}' for i in range(4)]
        for program in programs:
            shutil.copyfile(build / 'secmon-writer-scenario', program)
            program.chmod(0o755)
        for target in targets:
            target.write_bytes(b'data')
        program_alias, target_alias = root / 'exe-alias', root / 'target-alias'
        os.link(programs[0], program_alias)
        os.link(targets[0], target_alias)
        paths = [*targets, target_alias, programs[0]]
        source_programs, source_targets = [*programs, program_alias], paths
        config, control = root / 'policy', root / 'control'
        initial = [(program, 0, targets[0], 255) for program in programs]

        def publish(revision, rules):
            protected_rows = [f'protect "{path}"' for path in paths]
            rows = []
            for program, uid, target, mask in rules:
                operations = ','.join(name for bit, name in enumerate(OPERATIONS) if mask & (1 << bit))
                rows.append(f'allow-writer "{program}" {uid} "{target}" {operations}')
            # 规则编号取决于文件中 writer 的相对顺序；只打散 protect 位置，不改变模型采用的编号。
            rng.shuffle(protected_rows)
            for row in protected_rows:
                rows.insert(rng.randrange(len(rows) + 1), row)
            stage = root / 'staging'
            stage.write_text(f'revision {revision}\n' + '\n'.join(rows) + '\n')
            stage.chmod(0o600)
            stage.replace(config)

        def model(rules):
            result = {key_for(path): [1, 0, 0, [0] * len(OPERATIONS)] for path in paths}
            for index, (program, uid, target, mask) in enumerate(rules):
                value = result.setdefault(key_for(program), [0, 0, 0, [0] * len(OPERATIONS)])
                value[0] |= 6
                value[1] = uid
                value[2] |= 1 << index
                selected = result[key_for(target)]
                for operation in range(len(OPERATIONS)):
                    if mask & (1 << operation):
                        selected[3][operation] |= 1 << index
            return {key: (flags, uid, bits, tuple(allowed)) for key, (flags, uid, bits, allowed) in result.items()}

        def inspect():
            with PolicyMapView(outer_id) as view:
                return view.entries(full=True)

        publish(1, initial)
        before = policy_outer_ids()
        with MonitorRun(build / 'secmon', ['--policy', str(config), '--self-protect', str(control)], # 默认 40 次仍给 180 秒；较长研究运行保留余量，总时长仍在主服务 3600 秒上限内。
                        seconds=max(180, args.iterations * 3 + 60)) as monitor:
            try:
                created = policy_outer_ids() - before
                assert len(created) == 1, 'ambiguous creation; refusing to inspect unrelated Map'
                outer_id = created.pop()
                assert inspect() == model(initial)
                floor = len(list(Path(f'/proc/{monitor.process.pid}/fd').iterdir())) - len(paths) - len(initial)
                rejected = 0
                for iteration in range(args.iterations):
                    revision = iteration + 2
                    uids = {key_for(program): rng.choice((0, 65534)) for program in programs}
                    pairs = [(program, target) for program in source_programs for target in source_targets]
                    # 每个实际程序至少一条规则，使程序对象一直保持身份保护，不被行为探针改写。
                    mandatory = [(program, targets[0]) for program in programs]
                    rng.shuffle(pairs)
                    selected = mandatory + [pair for pair in pairs[:rng.randrange(len(pairs) + 1)] if pair not in mandatory]
                    rng.shuffle(selected)
                    rules = [(program, uids[key_for(program)], target, rng.randrange(1, 1 << len(OPERATIONS))) for program, target in selected]
                    if iteration % 7 == 0:
                        old = inspect()
                        # 同 inode 不同路径/UID，解析可通过而候选准备必须整体拒绝。
                        publish(revision, [(programs[0], 0, targets[0], 255), (program_alias, 65534, targets[1], 255)])
                        call(build / 'secmon', 'reload', control, 'prepare_failed')
                        rejected += 1
                        assert inspect() == old
                    publish(revision, rules)
                    reply = call(build / 'secmon', 'reload', control)
                    expected = model(rules)
                    assert inspect() == expected, (args.seed, iteration)
                    assert reply['rejections'] == rejected and reply['writer_paths'] == len(rules)
                    assert len(list(Path(f'/proc/{monitor.process.pid}/fd').iterdir())) == floor + len(paths) + len(rules)
                    for program in programs:
                        subject = expected[key_for(program)]
                        for target in [*targets, programs[0]]:
                            flags, _, _, permitted = expected[key_for(target)]
                            allowed = not (flags & 4) and subject[1] == 0 and all(subject[2] & permitted[operation] for operation in (0, 1))
                            result = subprocess.run([str(program), 'write', str(target)], capture_output=True, timeout=5)
                            assert result.returncode == (0 if allowed else errno.EACCES), (args.seed, iteration, program, target, result.returncode)
                    if (iteration + 1) % 10 == 0:
                        print(f'progress seed={args.seed} commits={iteration+1} rejected={rejected}', flush=True)
            finally:
                call(build / 'secmon', 'stop', control)
                monitor.process.wait(timeout=5)
        print(f'PASS independent scoped matrix model: seed={args.seed} commits={args.iterations} rejected={rejected}')


if __name__ == '__main__':
    main()
