/* 凭证观测模块，由 secmon.bpf.c 包含以共享 Map 和统计函数，不单独编译加载。 */
/* HASH Map 保存每个线程已观测到的凭证；这不是授权数据库，正常 commit_creds 也不能证明调用可信。 */
/* Included by secmon.bpf.c. Baselines describe observed committed credentials,
 * not proof that a credential transition was authorized. */
/* 把 TGID/TID 与 start_boottime 组合，避免数字 PID 复用后继承旧基线；结构清零保证键字节稳定。 */
struct task_key { u64 id; u64 start_ns; };
struct cred_baseline { u32 uid; u32 euid; u64 caps; };
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct task_key);
    __type(value, struct cred_baseline);
} cred_map SEC(".maps");

static __always_inline struct task_key task_key_for(struct task_struct *task)
{
    struct task_key key = {};
    /* task 的原始 pid/tgid 与上述 helper 使用同一全局编号，局部 PID=1 不会彼此覆盖。 */
    key.id = ((u64)BPF_CORE_READ(task, tgid) << 32) | BPF_CORE_READ(task, pid);
    key.start_ns = BPF_CORE_READ(task, start_boottime);
    return key;
}
static __always_inline struct cred_baseline read_creds(struct task_struct *task)
{
    struct cred_baseline base = {};
    base.uid = BPF_CORE_READ(task, cred, uid.val);
    base.euid = BPF_CORE_READ(task, cred, euid.val);
    base.caps = BPF_CORE_READ(task, cred, cap_effective.val);
    return base;
}
static __always_inline void save_baseline(struct task_struct *task)
{
    struct task_key key = task_key_for(task);
    struct cred_baseline base = read_creds(task);
    /* BPF_ANY 表示新增或覆盖；HASH Map 达到容量或更新失败时计数，不把缺失记录当作已授权凭证。 */
    if (bpf_map_update_elem(&cred_map, &key, &base, BPF_ANY))
        count_stat(SECMON_BASELINE_FAILED);
}
/* fexit 在目标函数返回时运行；此时读取的是 task 已提交凭证，不能在这里追溯批准这次变更。 */
SEC("fexit/commit_creds")
int BPF_PROG(on_commit_creds, struct cred *new, int ret)
{
    if (!ret)
        save_baseline(bpf_get_current_task_btf());
    return 0;
}
/* fork/clone 后记录 child：线程也有独立 TID 和生命周期，不能只维护进程组的一条记录。 */
SEC("tp_btf/sched_process_fork")
int BPF_PROG(on_fork, struct task_struct *parent, struct task_struct *child)
{
    save_baseline(child);
    return 0;
}
/* 每个退出线程删除自己的键，防止 HASH Map 因长期创建任务而积累无用条目。 */
SEC("tp_btf/sched_process_exit")
int BPF_PROG(on_exit, struct task_struct *task)
{
    struct task_key key = task_key_for(task);
    bpf_map_delete_elem(&cred_map, &key);
    return 0;
}
/* 在不可回退的 exec 准备点删除旧身份，早于 de_thread 改写任务身份；后续提交/完成建立新键。 */
SEC("tp_btf/sched_prepare_exec")
int BPF_PROG(on_exec_prepare, struct task_struct *task, struct linux_binprm *bprm)
{
    /* Point of no return: remove the pre-exec key before de_thread().
     * commit_creds/exec completion will establish the new identity. */
    struct task_key key = task_key_for(task);
    bpf_map_delete_elem(&cred_map, &key);
    return 0;
}
static __always_inline u32 credential_flags(struct task_struct *task)
{
    struct task_key key = task_key_for(task);
    struct cred_baseline current = read_creds(task);
    struct cred_baseline *base = bpf_map_lookup_elem(&cred_map, &key);
    /* 挂载之前就存在的线程没有历史记录，首次见到只能建立观测基线，不能推导此前是否发生过攻击。 */
    if (!base) {
        /* Processes predating attach get an observed, not trusted, baseline. */
        save_baseline(task);
        return 0;
    }
    /* 只设置不一致标志；flags=0 也不是可信证明，恶意路径若正常调用 commit_creds 同样会刷新观测值。 */
    return (base->uid != current.uid || base->euid != current.euid ||
            base->caps != current.caps) ? SECMON_BASELINE_MISMATCH : 0;
}
