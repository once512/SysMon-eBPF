# SPDX-License-Identifier: MIT
"""Read-only inspection of the credential Map owned by one running audit host."""
import ctypes
import ctypes.util
import errno
import json
import os
from pathlib import Path
import subprocess
import time


class TaskKey(ctypes.Structure):
    _fields_ = [('id', ctypes.c_uint64), ('start_ns', ctypes.c_uint64)]


class Credentials(ctypes.Structure):
    _fields_ = [('uid', ctypes.c_uint32), ('euid', ctypes.c_uint32), ('caps', ctypes.c_uint64)]


class CredentialMap:
    def __init__(self, monitor_pid):
        self.fd = -1
        self.lib = ctypes.CDLL(ctypes.util.find_library('bpf'), use_errno=True)
        self.lib.bpf_map_get_fd_by_id.argtypes = [ctypes.c_uint]
        self.lib.bpf_map_get_fd_by_id.restype = ctypes.c_int
        self.lib.bpf_map_get_next_key.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
        self.lib.bpf_map_get_next_key.restype = ctypes.c_int
        self.lib.bpf_map_lookup_elem.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
        self.lib.bpf_map_lookup_elem.restype = ctypes.c_int
        ids = set()
        for info in Path(f'/proc/{monitor_pid}/fdinfo').iterdir():
            try:
                content = info.read_text()
            except FileNotFoundError:
                continue
            for line in content.splitlines():
                if line.startswith('map_id:'):
                    ids.add(int(line.split(':', 1)[1]))
        for map_id in sorted(ids):
            result = subprocess.run(['bpftool', '-j', 'map', 'show', 'id', str(map_id)],
                                    capture_output=True, text=True, timeout=5, check=True)
            info = json.loads(result.stdout)
            if info['name'] == 'cred_map':
                assert info['type'] == 'hash' and info['bytes_key'] == ctypes.sizeof(TaskKey)
                assert info['bytes_value'] == ctypes.sizeof(Credentials)
                self.fd = self.lib.bpf_map_get_fd_by_id(map_id)
                if self.fd < 0:
                    raise OSError(ctypes.get_errno(), 'open credential Map')
                return
        raise RuntimeError('credential Map not found among this audit host\'s FDs')

    def keys_for_group(self, pid):
        found = set()
        current = None
        deadline = time.monotonic() + 3
        # Other system tasks can concurrently delete keys. A deleted iterator key
        # can restart a HASH walk, so bound work and deduplicate observations.
        while time.monotonic() < deadline:
            following = TaskKey()
            pointer = None if current is None else ctypes.byref(current)
            if self.lib.bpf_map_get_next_key(self.fd, pointer, ctypes.byref(following)):
                error = ctypes.get_errno()
                if error == errno.ENOENT:
                    return found
                raise OSError(error, 'iterate credential Map')
            if following.id >> 32 == pid:
                found.add((following.id & 0xffffffff, following.start_ns))
            current = following
        raise RuntimeError('credential Map iteration could not complete under concurrent changes')

    def credentials(self, pid, key):
        tid, start_ns = key
        raw = TaskKey((pid << 32) | tid, start_ns)
        value = Credentials()
        if self.lib.bpf_map_lookup_elem(self.fd, ctypes.byref(raw), ctypes.byref(value)):
            raise OSError(ctypes.get_errno(), 'read credential baseline')
        return value.uid, value.euid, value.caps

    def close(self):
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
