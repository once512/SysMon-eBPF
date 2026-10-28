# SPDX-License-Identifier: MIT
# 管理 CLI 的 JSON 输出与退出码同步核验；只有配置/请求成功才应返回 0。
import json
import subprocess


def call(binary, command, control, code='ok'):
    result = subprocess.run([str(binary), '--' + command, str(control)], capture_output=True,
                            text=True, timeout=5)
    assert (result.returncode == 0) == (code == 'ok'), (result.returncode, result.stdout, result.stderr)
    reply = json.loads(result.stdout)
    assert reply['protocol_version'] == 10 and reply['command'] == command and reply['code'] == code, reply
    return reply
