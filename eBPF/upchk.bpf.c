/* Included by secmon.bpf.c. Baselines describe observed committed credentials,
 * not proof that a credential transition was authorized. */
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
    if (bpf_map_update_elem(&cred_map, &key, &base, BPF_ANY))
        count_stat(SECMON_BASELINE_FAILED);
}
SEC("fexit/commit_creds")
int BPF_PROG(on_commit_creds, struct cred *new, int ret)
{
    if (!ret)
        save_baseline(bpf_get_current_task_btf());
    return 0;
}
SEC("tp_btf/sched_process_fork")
int BPF_PROG(on_fork, struct task_struct *parent, struct task_struct *child)
{
    save_baseline(child);
    return 0;
}
SEC("tp_btf/sched_process_exit")
int BPF_PROG(on_exit, struct task_struct *task)
{
    struct task_key key = task_key_for(task);
    bpf_map_delete_elem(&cred_map, &key);
    return 0;
}
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
    if (!base) {
        /* Processes predating attach get an observed, not trusted, baseline. */
        save_baseline(task);
        return 0;
    }
    return (base->uid != current.uid || base->euid != current.euid ||
            base->caps != current.caps) ? SECMON_BASELINE_MISMATCH : 0;
}
