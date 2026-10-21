/* 授权读取当前任务已提交的 mm->exe_file，不用 comm、argv、用户路径或容易复用的 PID。 */
/* 普通 fork 保留同一 mm/可执行对象；exec 换成新对象后，下次操作重新匹配，因此不永久继承授权。 */
/* 脚本执行时该对象通常是解释器，信任通用解释器会放行它执行的所有代码，不能区分脚本。 */
/* 返回 1 表示主体例外，0 表示不匹配，-1 表示匹配但租期已过；这不是 LSM 的返回语义。 */
static __always_inline int authorized_writer(void *policy, const struct file_policy_value *target, u32 operation)
{
    struct task_struct *task = bpf_get_current_task_btf();
    /* 此处读已经生效的进程执行对象，不读 exec 请求的文件名； */
    /* 因此 fork/exec 的身份变化自然反映在后续检查。 */
    struct inode *inode = BPF_CORE_READ(task, mm, exe_file, f_inode);
    if (!inode) return 0; /* 内核线程或没有可执行对象：不授予例外。 */
    u32 dev = BPF_CORE_READ(inode, i_sb, s_dev);
    struct file_key key = { .major = dev >> 20, .minor = dev & ((1U << 20) - 1),
                            .ino = BPF_CORE_READ(inode, i_ino) };
    /* 目标上的 READONLY 与这里的 WRITER 是两种角色； */
    /* 命中普通保护项本身不会使调用者获得授权。 */
    struct file_policy_value *writer = bpf_map_lookup_elem(policy, &key);
    /* 目标已需要保护时，调用程序未命中 WRITER 就没有例外，外层文件钩子仍会返回 EACCES。 */
    if (!writer || !(writer->flags & SECMON_FILE_WRITER)) return 0;
    // kuid.val 是内核全局 UID 坐标，不是容器内自行解释的 UID 数字。
    if (writer->writer_euid != BPF_CORE_READ(task, cred, euid.val)) return 0;
    /* 显式界限也让 verifier 能证明下面动态索引始终在 value 的八个元素内。 */
    if (!operation || operation > SECMON_FILE_OPERATION_COUNT) return 0;
    /* 主体与目标都在同一只读候选 Map 中：切换不会混用两版规则位编号。 */
    if (!(writer->writer_rules & target->allowed_writers[operation - 1])) return 0;
    // Expiry is enforced in-kernel even if the service is delayed/stopped.
    // A lease never revokes a writable mapping already granted before expiry.
    if (writer->writer_deadline_boot_ns && bpf_ktime_get_boot_ns() >= writer->writer_deadline_boot_ns)
        return -1;
    return 1;
}

/* Vault sessions use separate per-target slots, each with its own UID/deadline.
 * Slot numbering is private to one immutable policy snapshot. */
static __always_inline int vault_read_operation(u32 operation)
{
    return operation == SECMON_OP_OPEN_READ || operation == SECMON_OP_READ ||
           operation == SECMON_OP_MMAP_READ;
}
static __always_inline int authorized_vault_session(void *policy, const struct file_policy_value *target, u32 operation)
{
    u32 access = vault_read_operation(operation) ? SECMON_VAULT_READ :
        (operation == SECMON_OP_OPEN_WRITE || operation == SECMON_OP_WRITE ||
         operation == SECMON_OP_TRUNCATE || operation == SECMON_OP_MMAP_WRITE) ? SECMON_VAULT_WRITE : 0;
    /* Sessions do not authorize deleting, linking, renaming or changing metadata. */
    if (!access) return 0;
    struct task_struct *task = bpf_get_current_task_btf();
    struct inode *inode = BPF_CORE_READ(task, mm, exe_file, f_inode);
    if (!inode) return 0;
    u32 dev = BPF_CORE_READ(inode, i_sb, s_dev);
    struct file_key key = { .major = dev >> 20, .minor = dev & ((1U << 20) - 1),
                            .ino = BPF_CORE_READ(inode, i_ino) };
    const struct file_policy_value *subject = bpf_map_lookup_elem(policy, &key);
    if (!subject || !subject->vault_subjects) return 0;
    u32 uid = BPF_CORE_READ(task, cred, euid.val);
    u64 now = bpf_ktime_get_boot_ns();
    int expired = 0;
#pragma unroll
    for (u32 index = 0; index < SECMON_MAX_VAULT_SESSIONS; ++index) {
        if (!(subject->vault_subjects & (1ULL << index))) continue;
        const struct vault_session_grant *grant = &target->vault_sessions[index];
        if (!(grant->access & access) || grant->euid != uid) continue;
        if (!grant->deadline_boot_ns || now >= grant->deadline_boot_ns) { expired = -1; continue; }
        return 1;
    }
    return expired;
}
