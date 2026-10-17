// SPDX-License-Identifier: GPL-2.0-only
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "secmon.h"
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);
} events SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, SECMON_STAT_COUNT);
    __type(key, u32);
    __type(value, u64);
} stats SEC(".maps");
static __always_inline void count_stat(u32 index)
{
    u64 *value = bpf_map_lookup_elem(&stats, &index);
    if (value)
        (*value)++;
}
#include "upchk.bpf.c"
static __always_inline void emit_exec(struct task_struct *task,
                                     struct linux_binprm *bprm,
                                     u32 kind, u32 old_tid, u32 flags)
{
    struct exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        count_stat(SECMON_DROPPED);
        return;
    }
    __builtin_memset(e, 0, sizeof(*e));
    e->version = SECMON_ABI_VERSION;
    e->kind = kind;
    e->old_tid = old_tid;
    e->size = sizeof(*e);
    e->timestamp_ns = bpf_ktime_get_ns();
    e->start_ns = BPF_CORE_READ(task, start_boottime);
    u64 id = bpf_get_current_pid_tgid();
    e->pid = id >> 32;
    e->tid = (u32)id;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->caller_uid = BPF_CORE_READ(task, cred, uid.val);
    e->caller_euid = BPF_CORE_READ(task, cred, euid.val);
    e->caps = BPF_CORE_READ(task, cred, cap_effective.val);
    e->target_euid = BPF_CORE_READ(bprm, cred, euid.val);
    e->file_mode = BPF_CORE_READ(bprm, file, f_inode, i_mode);
    e->flags = flags;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    bpf_probe_read_kernel_str(e->filename, sizeof(e->filename),
                              BPF_CORE_READ(bprm, filename));
    bpf_ringbuf_submit(e, 0);
}
SEC("lsm/bprm_check_security")
int BPF_PROG(on_exec_check, struct linux_binprm *bprm, int ret)
{
    if (ret)
        return ret;
    struct task_struct *task = bpf_get_current_task_btf();
    emit_exec(task, bprm, SECMON_EXEC_CHECK, (u32)bpf_get_current_pid_tgid(),
              credential_flags(task));
    return 0;
}
SEC("tp_btf/sched_process_exec")
int BPF_PROG(on_exec_complete, struct task_struct *task, pid_t old_pid,
             struct linux_binprm *bprm)
{
    /* de_thread() may change both identity and start time. Remove by the
     * original identity at sched_prepare_exec, before that transformation. */
    save_baseline(task);
    emit_exec(task, bprm, SECMON_EXEC_SUCCESS, (u32)old_pid, 0);
    return 0;
}
#include "fileguard.bpf.c"
char LICENSE[] SEC("license") = "GPL";
