# SPDX-License-Identifier: MIT
# Inspection/injection is restricted to the unique map created by this test.
import ctypes
import ctypes.util
import errno
import json
import os
import subprocess
import time


class ResponseState(ctypes.Structure):
    _fields_ = [('lock', ctypes.c_uint32), ('reserved', ctypes.c_uint32),
                ('epoch', ctypes.c_uint64), ('deadline_boot_ns', ctypes.c_uint64)]


def response_ids():
    result = subprocess.run(['bpftool', '-j', 'map', 'show'], check=True,
                            capture_output=True, text=True, timeout=5)
    return {item['id'] for item in json.loads(result.stdout)
            if item.get('name') == 'responses' and item['type'] == 'hash'}


class ResponseMap:
    def __init__(self, map_id):
        self.lib = ctypes.CDLL(ctypes.util.find_library('bpf'), use_errno=True)
        self.lib.bpf_map_get_fd_by_id.argtypes = [ctypes.c_uint]
        self.lib.bpf_map_get_fd_by_id.restype = ctypes.c_int
        for name in ('bpf_map_lookup_elem', 'bpf_map_get_next_key'):
            function = getattr(self.lib, name)
            function.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
            function.restype = ctypes.c_int
        self.lib.bpf_map_update_elem.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64]
        self.lib.bpf_map_update_elem.restype = ctypes.c_int
        self.lib.bpf_map_delete_elem.argtypes = [ctypes.c_int, ctypes.c_void_p]
        self.lib.bpf_map_delete_elem.restype = ctypes.c_int
        self.fd = self.lib.bpf_map_get_fd_by_id(map_id)
        if self.fd < 0:
            raise OSError(ctypes.get_errno(), 'open response map')

    def entries(self):
        result, previous = {}, None
        for _ in range(4097):
            key = ctypes.c_uint64()
            if self.lib.bpf_map_get_next_key(self.fd, None if previous is None else ctypes.byref(previous), ctypes.byref(key)):
                assert ctypes.get_errno() == errno.ENOENT
                return result
            value = ResponseState()
            # BPF_F_LOCK copies under the value's kernel spin lock.
            self.lib.bpf_map_lookup_elem_flags.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64]
            self.lib.bpf_map_lookup_elem_flags.restype = ctypes.c_int
            if self.lib.bpf_map_lookup_elem_flags(self.fd, ctypes.byref(key), ctypes.byref(value), 4):
                raise OSError(ctypes.get_errno(), 'read response state')
            result[key.value] = (value.epoch, value.deadline_boot_ns)
            previous = key
        raise AssertionError('response map exceeded capacity')

    def wait_keys(self, expected):
        until = time.monotonic() + 3
        while True:
            actual = set(self.entries())
            if actual == set(expected):
                return
            assert time.monotonic() < until, (actual, expected)
            time.sleep(0.01)

    def insert(self, key, epoch, deadline):
        key, value = ctypes.c_uint64(key), ResponseState(0, 0, epoch, deadline)
        if self.lib.bpf_map_update_elem(self.fd, ctypes.byref(key), ctypes.byref(value), 1):
            raise OSError(ctypes.get_errno(), 'insert fake capacity entry')

    def delete(self, key):
        key = ctypes.c_uint64(key)
        if self.lib.bpf_map_delete_elem(self.fd, ctypes.byref(key)):
            raise OSError(ctypes.get_errno(), 'delete fake capacity entry')

    def close(self):
        os.close(self.fd)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
