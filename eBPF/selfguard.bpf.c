/* 进程自保护：TASK_STORAGE 把策略绑定到实际 task 生命周期，而不是可能复用的数字 PID。 */
/* 用户态通过 pidfd 指定目标；内核侧把线程统一归到 group_leader，覆盖同一线程组。 */
/* Task local storage is attached through a pidfd, independent of PID reuse. */
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    /* TASK_STORAGE 按 task 生命周期分配，不能像固定数组一样预先给所有潜在任务分配条目。 */
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, u32);
} protected_tasks SEC(".maps");

static __always_inline int guard_task(struct task_struct *target, u32 operation, int sig)
{
    /* Preserve the BTF pointer type for task-storage helpers. A probe-read
     * copies pointer bytes into a scalar and loses verifier provenance. */
    /* 此直接访问保留 verifier 识别的 BTF task 指针；helper 需要它，不能先 probe-read 成无类型地址标量。 */
    struct task_struct *leader = target->group_leader;
    if (!leader) return 0;
    struct task_struct *controller = leader;
    if (!bpf_task_storage_get(&protected_tasks, leader, 0, 0)) {
        /* Privileged direct helpers hold group/policy capabilities. Anchor
         * their protection in the actual parent's task storage, not a PID.
         * Dropped-UID scanners are deliberately outside this root-helper rule.
         * Direct BTF accesses preserve the helper's task pointer provenance. */
        struct task_struct *parent = leader->real_parent;
        if (!parent) return 0;
        controller = parent->group_leader;
        if (!controller || !bpf_task_storage_get(&protected_tasks, controller, 0, 0) ||
            BPF_CORE_READ(leader, cred, uid.val) || BPF_CORE_READ(leader, cred, euid.val)) return 0;
    }
    struct task_struct *current = bpf_get_current_task_btf();
    /* 只允许目标自身或它的受保护宿主操作；外部root仍需走管理socket。 */
    struct task_struct *caller = BPF_CORE_READ(current, group_leader);
    if (caller == leader || caller == controller) return 0;
    count_stat(SECMON_SELF_DENIED);
    struct exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    /* 先决定拒绝，再尽力写审计； */
    /* ring buffer 无空间时仍返回 EPERM，不能把记录成功当成拒绝前提。 */
    if (e) {
        __builtin_memset(e, 0, sizeof(*e));
        e->version = SECMON_ABI_VERSION;
        e->size = sizeof(*e);
        e->kind = SECMON_SELF_DENIED_EVENT;
        e->operation = operation;
        e->target_pid = BPF_CORE_READ(leader, tgid);
        e->signal = sig;
        e->timestamp_ns = bpf_ktime_get_ns();
        e->start_ns = BPF_CORE_READ(current, start_boottime);
        e->process_inode = process_inode(current);
        u64 id = bpf_get_current_pid_tgid();
        e->pid = id >> 32;
        e->tid = (u32)id;
        e->caller_uid = BPF_CORE_READ(current, cred, uid.val);
        e->caller_euid = BPF_CORE_READ(current, cred, euid.val);
        bpf_get_current_comm(e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);
    } else count_stat(SECMON_DROPPED);
    return -1; /* EPERM */
}
/* 覆盖经过此 LSM 检查的用户态发信号路径；信号 0 只探测存在性，不应据此拒绝健康检查。 */
SEC("lsm/task_kill")
int BPF_PROG(guard_signal, struct task_struct *target, struct kernel_siginfo *info,
             int sig, const struct cred *cred, int ret)
{
    if (ret) return ret;
    /* Signal 0 only probes existence/permissions. */
    return sig ? guard_task(target, SECMON_OP_SIGNAL, sig) : 0;
}
/* 某些 /proc 内存访问也走 ptrace 权限检查；当前策略保守拒绝，不细分只读观察与注入。 */
SEC("lsm/ptrace_access_check")
int BPF_PROG(guard_ptrace, struct task_struct *target, unsigned int mode, int ret)
{
    if (ret) return ret;
    return guard_task(target, SECMON_OP_PTRACE, 0);
}
