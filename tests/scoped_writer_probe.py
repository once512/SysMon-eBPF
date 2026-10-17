# SPDX-License-Identifier: MIT
# 联合负载的原生授权探针；在监听前保留 FD，每次确认后检查目标/非目标、已有 FD/新打开四个维度。
import errno
from pathlib import Path
import shutil
from writer_harness import WriterProcess

class ScopedWriterProbe:
    def __init__(self, build, root, stack):
        self.program, self.other = root / 'scoped-writer', root / 'outsider'
        self.target, self.off_target = root / 'protected', root / 'ungranted'
        for program in (self.program, self.other):
            shutil.copyfile(Path(build) / 'secmon-writer-scenario', program)
            program.chmod(0o755)
        for target in (self.target, self.off_target):
            target.write_bytes(b'data')
        self.selected = stack.enter_context(WriterProcess(self.program, self.target))
        self.unselected = stack.enter_context(WriterProcess(self.program, self.off_target))
        self.outsider = stack.enter_context(WriterProcess(self.other, self.target))

    def policy(self, revision):
        text = f'protect "{self.target}"\nprotect "{self.off_target}"\n'
        if revision % 2:
            text += f'allow-writer "{self.program}" 0 "{self.target}" open-write,write\n'
        return text

    def check(self, revision):
        for command in ('w', 'o'):
            assert self.selected.request(command) == (0 if revision % 2 else errno.EACCES)
            assert self.unselected.request(command) == self.outsider.request(command) == errno.EACCES
