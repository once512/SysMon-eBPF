/* Included by secmon.bpf.c. Exact-inode, read-only policy. */
struct file_policy_map {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct file_key);
    __type(value, u32);
} file_policy_template SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, 1);
    __type(key, u32);
    __array(values, struct file_policy_map);
} protected_files SEC(".maps") = {
    .values = { [0] = &file_policy_template },
};

static __always_inline void *active_file_policy(void)
{
    u32 slot = 0;
    return bpf_map_lookup_elem(&protected_files, &slot);
}

static __always_inline int guard_inode_policy(struct inode *inode, u32 operation, void *policy)
{
    if (!inode || !policy) return 0;
    struct file_key key = {};
    u32 dev = BPF_CORE_READ(inode, i_sb, s_dev);
    key.major = dev >> 20;
    key.minor = dev & ((1U << 20) - 1);
    key.ino = BPF_CORE_READ(inode, i_ino);
    if (!bpf_map_lookup_elem(policy, &key)) return 0;
    count_stat(SECMON_POLICY_DENIED);
    struct exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        count_stat(SECMON_DROPPED);
        return -13; /* EACCES, independent of audit delivery. */
    }
    __builtin_memset(e, 0, sizeof(*e));
    e->version = SECMON_ABI_VERSION;
    e->size = sizeof(*e);
    e->kind = SECMON_FILE_DENIED;
    e->operation = operation;
    e->file = key;
    e->timestamp_ns = bpf_ktime_get_ns();
    struct task_struct *task = bpf_get_current_task_btf();
    e->start_ns = BPF_CORE_READ(task, start_boottime);
    u64 id = bpf_get_current_pid_tgid();
    e->pid = id >> 32;
    e->tid = (u32)id;
    e->caller_uid = BPF_CORE_READ(task, cred, uid.val);
    e->caller_euid = BPF_CORE_READ(task, cred, euid.val);
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return -13;
}
static __always_inline int guard_inode(struct inode *inode, u32 operation)
{
    return guard_inode_policy(inode, operation, active_file_policy());
}
SEC("lsm/file_open")
int BPF_PROG(guard_open, struct file *file, int ret)
{
    if (ret) return ret;
    return (BPF_CORE_READ(file, f_mode) & 2) ?
        guard_inode(BPF_CORE_READ(file, f_inode), SECMON_OP_OPEN_WRITE) : 0;
}
SEC("lsm/file_permission")
int BPF_PROG(guard_permission, struct file *file, int mask, int ret)
{
    if (ret) return ret;
    return (mask & 2) ? guard_inode(BPF_CORE_READ(file, f_inode), SECMON_OP_WRITE) : 0;
}
SEC("lsm/path_truncate")
int BPF_PROG(guard_truncate, const struct path *path, int ret)
{
    if (ret) return ret;
    return guard_inode(BPF_CORE_READ(path, dentry, d_inode), SECMON_OP_TRUNCATE);
}
SEC("lsm/file_truncate")
int BPF_PROG(guard_file_truncate, struct file *file, int ret)
{
    if (ret) return ret;
    return guard_inode(BPF_CORE_READ(file, f_inode), SECMON_OP_TRUNCATE);
}
SEC("lsm/inode_unlink")
int BPF_PROG(guard_unlink, struct inode *dir, struct dentry *dentry, int ret)
{
    if (ret) return ret;
    return guard_inode(BPF_CORE_READ(dentry, d_inode), SECMON_OP_UNLINK);
}
SEC("lsm/inode_rename")
int BPF_PROG(guard_rename, struct inode *old_dir, struct dentry *old_dentry,
             struct inode *new_dir, struct dentry *new_dentry, int ret)
{
    if (ret) return ret;
    /* Both operands use the same snapshot even if userspace swaps the slot. */
    void *policy = active_file_policy();
    int denied = guard_inode_policy(BPF_CORE_READ(old_dentry, d_inode), SECMON_OP_RENAME, policy);
    return denied ? denied : guard_inode_policy(BPF_CORE_READ(new_dentry, d_inode), SECMON_OP_RENAME, policy);
}
SEC("lsm/inode_link")
int BPF_PROG(guard_link, struct dentry *old_dentry, struct inode *dir,
             struct dentry *new_dentry, int ret)
{
    if (ret) return ret;
    return guard_inode(BPF_CORE_READ(old_dentry, d_inode), SECMON_OP_LINK);
}
SEC("lsm/inode_setattr")
int BPF_PROG(guard_setattr, struct mnt_idmap *idmap, struct dentry *dentry,
             struct iattr *attr, int ret)
{
    if (ret) return ret;
    return guard_inode(BPF_CORE_READ(dentry, d_inode), SECMON_OP_SETATTR);
}
SEC("lsm/mmap_file")
int BPF_PROG(guard_mmap, struct file *file, unsigned long reqprot,
             unsigned long prot, unsigned long flags, int ret)
{
    if (ret) return ret;
    /* MAP_SHARED=1, MAP_SHARED_VALIDATE=3; MAP_PRIVATE=2. */
    return (file && (prot & 2) && (flags & 1)) ?
        guard_inode(BPF_CORE_READ(file, f_inode), SECMON_OP_MMAP_WRITE) : 0;
}
SEC("lsm/file_mprotect")
int BPF_PROG(guard_mprotect, struct vm_area_struct *vma, unsigned long reqprot,
             unsigned long prot, int ret)
{
    if (ret) return ret;
    struct file *file = BPF_CORE_READ(vma, vm_file);
    /* VM_SHARED=0x8, PROT_WRITE=0x2. */
    return (file && (prot & 2) && (BPF_CORE_READ(vma, vm_flags) & 8)) ?
        guard_inode(BPF_CORE_READ(file, f_inode), SECMON_OP_MMAP_WRITE) : 0;
}
