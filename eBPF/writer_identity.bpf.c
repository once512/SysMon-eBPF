/* 授权读取当前任务已提交的 mm->exe_file，不用 comm、argv、用户路径或容易复用的 PID。 */
/* 普通 fork 保留同一 mm/可执行对象；exec 换成新对象后，下次操作重新匹配，因此不永久继承授权。 */
/* 脚本执行时该对象通常是解释器，信任通用解释器会放行它执行的所有代码，不能区分脚本。 */
static __always_inline int authorized_writer(void *policy)
{
    struct task_struct *task = bpf_get_current_task_btf();
    struct inode *inode = BPF_CORE_READ(task, mm, exe_file, f_inode);
    if (!inode) return 0; /* 内核线程或没有可执行对象：不授予例外。 */
    u32 dev = BPF_CORE_READ(inode, i_sb, s_dev);
    struct file_key key = { .major = dev >> 20, .minor = dev & ((1U << 20) - 1),
                            .ino = BPF_CORE_READ(inode, i_ino) };
    struct file_policy_value *writer = bpf_map_lookup_elem(policy, &key);
    if (!writer || !(writer->flags & SECMON_FILE_WRITER)) return 0;
    // kuid.val 是内核全局 UID 坐标，不是容器内自行解释的 UID 数字。
    return writer->writer_euid == BPF_CORE_READ(task, cred, euid.val);
}
