#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# 在忽略的构建目录生成边界种子，避免把 64 KiB 填充和数百行重复规则塞进源码仓库。
import argparse
from pathlib import Path
import shutil


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', default='build/fuzz-corpus')
    args = parser.parse_args()
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    for source in (Path(__file__).parent / 'fuzz_corpus' / 'policy').glob('*.conf'):
        shutil.copyfile(source, output / source.name)
    capacity = 'revision 1\n' + ''.join(f'protect "/data-{i}"\n' for i in range(256))
    capacity += ''.join(f'allow-writer "/writer-{i}" {i} "/data-{i}" all\n' for i in range(64))
    (output / 'capacity.conf').write_text(capacity)
    prefix = 'revision 1\n#'
    exact = prefix + 'x' * (65536 - len(prefix))
    (output / 'exact-bytes.conf').write_text(exact)
    (output / 'over-bytes.conf').write_text(exact + 'x')
    path = '/' + 'p' * 4094
    (output / 'path-limit.conf').write_text(f'revision 1\nprotect "{path}"\nallow-writer "/exe" 4294967294 "{path}" all\n')
    print(f'Prepared boundary seeds in {output}; arbitrary fuzzer mutations remain local to this directory')


if __name__ == '__main__':
    main()
