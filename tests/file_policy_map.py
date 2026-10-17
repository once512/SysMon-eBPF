# SPDX-License-Identifier: MIT
# 只读检查本专题新建实例的外层引用及一份固定内层 Map；检查 FD 故意延长旧快照寿命，用于观察切换语义。
# 用户态 lookup ARRAY_OF_MAPS 得到内层 Map ID，BPF helper lookup 得到可用于后续 helper 的 Map 指针，两者不同。
import ctypes
import ctypes.util
import errno
import json
import os
import subprocess
import time


class FileKey(ctypes.Structure):
    _fields_ = [('major', ctypes.c_uint32), ('minor', ctypes.c_uint32), ('ino', ctypes.c_uint64)]


class FileValue(ctypes.Structure):
    _fields_ = [('flags', ctypes.c_uint32), ('euid', ctypes.c_uint32)]


def map_info(map_id):
    result = subprocess.run(['bpftool', '-j', 'map', 'show', 'id', str(map_id)],
                            capture_output=True, text=True, check=True, timeout=5)
    return json.loads(result.stdout)


def policy_outer_ids():
    result = subprocess.run(['bpftool', '-j', 'map', 'show'], capture_output=True,
                            text=True, check=True, timeout=5)
    return {item['id'] for item in json.loads(result.stdout)
            if item.get('name') == 'protected_files' and item['type'] == 'array_of_maps'}


class PolicyMapView:
    def __init__(self, outer_id):
        self.outer = self.inner = -1
        self.lib = ctypes.CDLL(ctypes.util.find_library('bpf'), use_errno=True)
        self.lib.bpf_map_get_fd_by_id.argtypes = [ctypes.c_uint]
        self.lib.bpf_map_get_fd_by_id.restype = ctypes.c_int
        for name in ('bpf_map_lookup_elem', 'bpf_map_get_next_key'):
            function = getattr(self.lib, name)
            function.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
            function.restype = ctypes.c_int
        try:
            # 外层 ID 由启动前后差集唯一确定；不因自保护拒绝 proc fdinfo 就在全局同名 Map 中任选。
            info = map_info(outer_id)
            assert info['name'] == 'protected_files' and info['type'] == 'array_of_maps'
            assert info['max_entries'] == 1
            self.outer = self.open_id(outer_id)
            slot, identifier = ctypes.c_uint32(0), ctypes.c_uint32()
            if self.lib.bpf_map_lookup_elem(self.outer, ctypes.byref(slot), ctypes.byref(identifier)):
                raise OSError(ctypes.get_errno(), 'read active policy Map ID')
            self.map_id = identifier.value
            self.inner = self.open_id(self.map_id)
            info = map_info(self.map_id)
            assert info['type'] == 'hash' and info['max_entries'] == 320
            assert info['bytes_key'] == ctypes.sizeof(FileKey) == 16
            assert info['bytes_value'] == ctypes.sizeof(FileValue) == 8
        except BaseException:
            self.close()
            raise

    def open_id(self, map_id):
        fd = self.lib.bpf_map_get_fd_by_id(map_id)
        if fd < 0:
            raise OSError(ctypes.get_errno(), 'open policy inspection FD')
        return fd

    def entries(self):
        # 本项目发布后不原地修改内层 Map，本 FD 固定的版本可完整遍历；不宣称通用 HASH 并发快照。
        result, previous = {}, None
        for _ in range(321):
            key = FileKey()
            if self.lib.bpf_map_get_next_key(self.inner, None if previous is None else ctypes.byref(previous), ctypes.byref(key)):
                assert ctypes.get_errno() == errno.ENOENT
                return result
            value = FileValue()
            if self.lib.bpf_map_lookup_elem(self.inner, ctypes.byref(key), ctypes.byref(value)):
                raise OSError(ctypes.get_errno(), 'read fixed policy entry')
            result[(key.major, key.minor, key.ino)] = (value.flags, value.euid)
            previous = key
        raise AssertionError('policy iteration exceeded bounded capacity')

    def wait_gone(self, map_id):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            fd = self.lib.bpf_map_get_fd_by_id(map_id)
            if fd < 0:
                assert ctypes.get_errno() == errno.ENOENT
                return
            os.close(fd)
            time.sleep(0.01)
        raise AssertionError('retired policy Map still referenced after closing inspection FD')

    def close(self):
        for name in ('inner', 'outer'):
            fd = getattr(self, name)
            if fd >= 0:
                os.close(fd)
                setattr(self, name, -1)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def key_for(path):
    info = os.stat(path)
    return os.major(info.st_dev), os.minor(info.st_dev), info.st_ino
