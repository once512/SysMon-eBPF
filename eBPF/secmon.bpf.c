// SPDX-License-Identifier: GPL-2.0-only
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "secmon.h"

#include "upchk.bpf.c"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("lsm/bprm_check_security")
int BPF_PROG(lsm_bprm_check_security, struct linux_binprm *bprm) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    // 提权检测
    if (upchk_lv1(task)) {
        bpf_printk("FATAL: Stateless LPE Detected by upchk_lv1!\n");
        return -1; // 阻断
    }

    if (upchk_lv2(task)) {
        bpf_printk("FATAL: Stateful LPE Detected by upchk_lv2!\n");
        return -1; // 阻断
    }

    // 日志采集
    struct exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    u64 id = bpf_get_current_pid_tgid();
    e->pid = id >> 32;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    e->caller_uid = BPF_CORE_READ(task, cred, uid.val);
    e->target_euid = BPF_CORE_READ(bprm, cred, euid.val);

    struct file *file_ptr = BPF_CORE_READ(bprm, file);
    struct inode *inode_ptr = BPF_CORE_READ(file_ptr, f_inode);
    e->file_mode = BPF_CORE_READ(inode_ptr, i_mode);

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    const char *filename_ptr = BPF_CORE_READ(bprm, filename);
    bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), filename_ptr);

    bpf_ringbuf_submit(e, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
