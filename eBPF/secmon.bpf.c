// SPDX-License-Identifier: GPL-2.0-only
/* 内核侧总入口：本文件由 clang 编译成 BPF ELF，再交给 libbpf 加载和挂载，而非普通内核模块。 */
/* SEC 段名声明程序类型/挂载目标或 Map；libbpf 读取它们，内核 verifier（校验器）检查指针、边界及 helper 使用。 */
/* 先读共享 ABI，再看 upchk 的凭证记录、这里的执行事件，最后看 fileguard/selfguard 的 LSM 拒绝。 */
/* BTF（BPF Type Format）描述内核类型；vmlinux.h 从它导出，不依赖传统内核头文件的完整编译环境。 */
/* CO-RE（一次编译、按目标类型重定位）：BPF_CORE_READ 保留字段访问重定位信息，libbpf 加载时按目标 BTF 调整偏移。 */
/* CO-RE 主要解决类型布局差异，并不保证所需挂载点和 helper 在任意内核都可用。 */
#include <vmlinux.h>
/* helper 是内核向 BPF 暴露的受限接口；不能像内核模块那样任意调用内核函数或解引用任意地址。 */
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "secmon.h"
/* Map 是内核管理的共享状态对象，BPF 用 helper 访问，宿主通过 Map FD 操作；不同类型有不同 key/value 和生命周期语义。 */
/* 这些 __uint/__type 是 libbpf 的 BTF Map 声明约定，不是宿主实际分配出来的 C 容器。 */
/* RINGBUF 的 max_entries 是字节容量；下面统计 ARRAY 的 max_entries 才是元素数量。 */
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
/* PERCPU_ARRAY 每个可能 CPU 各有一份计数，减少 CPU 之间共享写入；宿主读取时必须汇总所有副本。 */
static __always_inline void count_stat(u32 index)
{
    /* PERCPU_ARRAY lookup 返回当前 CPU 的槽位； */
    /* 无需把每次事件计数串行化到一个共享全局计数器。 */
    u64 *value = bpf_map_lookup_elem(&stats, &index);
    if (value)
        (*value)++;
}
#include "upchk.bpf.c"
static __always_inline void emit_exec(struct task_struct *task,
                                     struct linux_binprm *bprm,
                                     u32 kind, u32 old_tid, u32 flags)
{
    /* reserve 返回 ring buffer 中可填写的记录；申请失败只记丢失数，不等待用户态。 */
    struct exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        count_stat(SECMON_DROPPED);
        return;
    }
    /* 包括填充和未使用字段在内全部清零，避免输出未初始化内容；verifier 也会检查可读写内存范围。 */
    __builtin_memset(e, 0, sizeof(*e));
    e->version = SECMON_ABI_VERSION;
    e->kind = kind;
    e->old_tid = old_tid;
    e->size = sizeof(*e);
    e->timestamp_ns = bpf_ktime_get_ns();
    e->start_ns = BPF_CORE_READ(task, start_boottime);
    /* helper 返回高 32 位 TGID、低 32 位线程 PID；本项目 JSON 的 pid/tid 分别使用这两部分。 */
    /* helper 使用初始 PID namespace 的编号，不能直接与容器内部 getpid() 比较；用 NSpid 做关联。 */
    u64 id = bpf_get_current_pid_tgid();
    e->pid = id >> 32;
    e->tid = (u32)id;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->caller_uid = BPF_CORE_READ(task, cred, uid.val);
    e->caller_euid = BPF_CORE_READ(task, cred, euid.val);
    e->caps = BPF_CORE_READ(task, cred, cap_effective.val);
    /* At bprm_check_security the candidate may predate setuid evaluation.
     * After exec commits credentials, bprm->cred is NULL: use committed task creds. */
    /* 执行检查阶段的 bprm->cred 可能尚未完成 setuid 计算；执行成功后它已被提交消耗，须读 task 当前凭证。 */
    e->target_euid = kind == SECMON_EXEC_SUCCESS ? e->caller_euid :
                     BPF_CORE_READ(bprm, cred, euid.val);
    e->file_mode = BPF_CORE_READ(bprm, file, f_inode, i_mode);
    e->flags = flags;
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    /* filename 仅用于有界审计展示，过长会截断； */
    /* 文件授权不能依赖这里截断后的路径文本。 */
    bpf_probe_read_kernel_str(e->filename, sizeof(e->filename),
                              BPF_CORE_READ(bprm, filename));
    /* submit 后记录归消费者所有，本程序不能继续写；每次成功 reserve 都应走 submit 或 discard。 */
    bpf_ringbuf_submit(e, 0);
}
/* LSM 挂载可影响授权结果；BPF_PROG 负责把底层上下文参数解包成这里可读的函数形参。 */
/* ret 来自前序 BPF LSM 程序，非零拒绝必须原样保留；本项目此执行钩子只审计，不额外阻断。 */
SEC("lsm/bprm_check_security")
int BPF_PROG(on_exec_check, struct linux_binprm *bprm, int ret)
{
    /* 对可串联的 BPF LSM 程序，非零 ret 代表前面的拒绝； */
    /* 当前审计器不能用返回 0 覆盖它。 */
    if (ret)
        return ret;
    struct task_struct *task = bpf_get_current_task_btf();
    emit_exec(task, bprm, SECMON_EXEC_CHECK, (u32)bpf_get_current_pid_tgid(),
              credential_flags(task));
    return 0;
}
/* tp_btf 是带 BTF 类型信息的跟踪点，用来观察执行完成，返回 0 不代表能够批准/拒绝这次执行。 */
/* 非主线程 exec 的 de_thread 可能改变 TID，old_pid 用于关联转换前线程，不等同于新 TGID。 */
SEC("tp_btf/sched_process_exec")
int BPF_PROG(on_exec_complete, struct task_struct *task, pid_t old_pid,
             struct linux_binprm *bprm)
{
    /* de_thread() may change both identity and start time. Remove by the
     * original identity at sched_prepare_exec, before that transformation. */
    /* 完成跟踪点只观察已发生的 exec，返回值不能推翻执行； */
    /* 它同时建立转换后线程身份的观测基线。 */
    save_baseline(task);
    emit_exec(task, bprm, SECMON_EXEC_SUCCESS, (u32)old_pid, 0);
    return 0;
}
#include "fileguard.bpf.c"
#include "selfguard.bpf.c"
char LICENSE[] SEC("license") = "GPL";
