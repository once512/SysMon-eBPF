/* 文件只读保护：与传统 LSM 类似在操作前返回负 errno；并非在用户态收到事件后再撤销操作。 */
/* 策略按设备号和 inode 匹配，路径只用于用户态首次选中并固定对象；不递归保护目录。 */
/* 外层 ARRAY_OF_MAPS 指向一份完整 HASH 策略，更新引用即可切换，避免逐条修改产生半份策略。 */
/* Included by secmon.bpf.c. Exact-inode, read-only policy. */
/* 内层模板规定 key/value/容量，用户态新建的候选 HASH 必须符合该布局才能装入外层 Map。 */
struct file_policy_map {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, SECMON_POLICY_CAPACITY);
    __type(key, struct file_key);
    __type(value, struct file_policy_value);
} file_policy_template SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, 1);
    __type(key, u32);
    __array(values, struct file_policy_map);
} protected_files SEC(".maps") = {
    .values = { [0] = &file_policy_template },
};

/* 一次取出当前内层 Map 引用；切换前已取到旧引用的在途 BPF 程序可继续访问它，内核管理其生命周期。 */
static __always_inline void *active_file_policy(void)
{
    /* ARRAY_OF_MAPS 这里只有一个活动槽； */
    /* BPF 得到的是后续 lookup 可用的 Map 引用，不是用户态管理 FD。 */
    u32 slot = 0;
    return bpf_map_lookup_elem(&protected_files, &slot);
}

#include "writer_identity.bpf.c"

static __always_inline int guard_inode_policy(struct inode *inode, u32 operation, void *policy)
{
    if (!inode || !policy) return 0;
    struct file_key key = {};
    /* 这里读的是内核 dev_t 编码，按主次设备号拆开；用户态以 major/minor(st_dev) 构造同样的键。 */
    u32 dev = BPF_CORE_READ(inode, i_sb, s_dev);
    key.major = dev >> 20;
    key.minor = dev & ((1U << 20) - 1);
    key.ino = BPF_CORE_READ(inode, i_ino);
    /* 目标 inode 与调用程序身份必须查同一个 policy 快照，否则重载中可能混用旧目标规则与新主体授权。 */
    struct file_policy_value *entry = bpf_map_lookup_elem(policy, &key);
    /* 这里查的是目标集合：未选中的 inode 不施加本层限制，不是给未知调用程序授予写权限。 */
    if (!entry) return 0;
    // 授权程序文件自身永不获得写例外；否则获授权进程可替换授权代码而保留同一 inode。
    u32 denial_flags = 0;
    if (vault_read_operation(operation) && !(entry->flags & SECMON_FILE_VAULT)) return 0;
    if ((entry->flags & SECMON_FILE_VAULT) &&
        (vault_read_operation(operation) || !(entry->flags & SECMON_FILE_IDENTITY))) {
        int session = authorized_vault_session(policy, entry, operation);
        if (session > 0) return 0;
        if (session < 0) denial_flags |= SECMON_VAULT_SESSION_EXPIRED;
    } else if (!(entry->flags & SECMON_FILE_IDENTITY)) {
        if (!(entry->flags & SECMON_FILE_READONLY)) return 0;
        int writer = authorized_writer(policy, entry, operation);
        if (writer > 0) return 0;
        if (writer < 0) denial_flags |= SECMON_WRITER_LEASE_EXPIRED;
    }
    count_stat(SECMON_POLICY_DENIED);
    struct exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    /* 审计记录申请失败仍返回 EACCES：日志拥塞不能把原本应拒绝的写入变成允许。 */
    if (!e) {
        count_stat(SECMON_DROPPED);
        return -13; /* EACCES, independent of audit delivery. */
    }
    /* 同一事件结构还用于其他事件种类； */
    /* 先清零所有未使用字段和填充，避免把无关内存作为审计数据发出。 */
    __builtin_memset(e, 0, sizeof(*e));
    e->version = SECMON_ABI_VERSION;
    e->size = sizeof(*e);
    e->kind = SECMON_FILE_DENIED;
    e->operation = operation;
    e->flags = denial_flags;
    e->file = key;
    e->timestamp_ns = bpf_ktime_get_ns();
    struct task_struct *task = bpf_get_current_task_btf();
    e->start_ns = BPF_CORE_READ(task, start_boottime);
    e->process_inode = process_inode(task);
    u64 id = bpf_get_current_pid_tgid();
    e->pid = id >> 32;
    e->tid = (u32)id;
    e->caller_uid = BPF_CORE_READ(task, cred, uid.val);
    e->caller_euid = BPF_CORE_READ(task, cred, euid.val);
    bpf_get_current_comm(e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return -13;
}
/* 通用入口每次只取一份活动表； */
/* rename 需要检查两个操作数，因此另行显式传递同一个快照。 */
static __always_inline int guard_inode(struct inode *inode, u32 operation)
{
    return guard_inode_policy(inode, operation, active_file_policy());
}
/* 以下 LSM 程序都保留前序 ret；f_mode 的 FMODE_WRITE=2 表示文件以可写方式打开。 */
SEC("lsm/file_open")
int BPF_PROG(guard_open, struct file *file, int ret)
{
    if (ret) return ret;
    void *policy = active_file_policy();
    u32 mode = BPF_CORE_READ(file, f_mode);
    struct inode *inode = BPF_CORE_READ(file, f_inode);
    int denied = (mode & 1) ? guard_inode_policy(inode, SECMON_OP_OPEN_READ, policy) : 0;
    return denied ? denied : (mode & 2) ? guard_inode_policy(inode, SECMON_OP_OPEN_WRITE, policy) : 0;
}
/* 已有写入 FD 也需在普通写权限检查点拦截；只拦 file_open 无法限制保护启用前打开的 FD。 */
SEC("lsm/file_permission")
int BPF_PROG(guard_permission, struct file *file, int mask, int ret)
{
    if (ret) return ret;
    void *policy = active_file_policy();
    struct inode *inode = BPF_CORE_READ(file, f_inode);
    int denied = (mask & 4) ? guard_inode_policy(inode, SECMON_OP_READ, policy) : 0;
    return denied ? denied : (mask & 2) ? guard_inode_policy(inode, SECMON_OP_WRITE, policy) : 0;
}
/* 路径截断与文件 FD 截断的内核入口不同，分别挂载；实际拒绝可能先发生在更早的权限钩子。 */
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
/* unlink 检查的是将被删除的 dentry inode，不是 dir； */
/* 保护对象不等于递归保护其父目录。 */
SEC("lsm/inode_unlink")
int BPF_PROG(guard_unlink, struct inode *dir, struct dentry *dentry, int ret)
{
    if (ret) return ret;
    return guard_inode(BPF_CORE_READ(dentry, d_inode), SECMON_OP_UNLINK);
}
/* rename 必须同时检查源和被覆盖目标；两次判断共用同一策略快照，不能在中途重新取活动 Map。 */
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
/* 新增硬链接也引用原 inode，因此按对象身份检查，不尝试规范化或逐个列出所有路径别名。 */
SEC("lsm/inode_link")
int BPF_PROG(guard_link, struct dentry *old_dentry, struct inode *dir,
             struct dentry *new_dentry, int ret)
{
    if (ret) return ret;
    return guard_inode(BPF_CORE_READ(old_dentry, d_inode), SECMON_OP_LINK);
}
/* 对保护对象保守拒绝此入口的属性修改，包括常见 chmod/时间更新；不等于覆盖所有文件系统专属操作。 */
SEC("lsm/inode_setattr")
int BPF_PROG(guard_setattr, struct mnt_idmap *idmap, struct dentry *dentry,
             struct iattr *attr, int ret)
{
    if (ret) return ret;
    struct inode *inode = BPF_CORE_READ(dentry, d_inode);
    void *policy = active_file_policy();
    // A normal truncate reaches setattr too. Only a vault's size-only
    // attributes use its write session; legacy writer operation scopes stay
    // unchanged and chmod/chown/explicit timestamps remain forbidden.
    u32 valid = BPF_CORE_READ(attr, ia_valid);
    const u32 size_attributes = (1U << 3) | (1U << 5) | (1U << 6) |
        (1U << 11) | (1U << 12) | (1U << 13) | (1U << 14) | (1U << 15);
    if (inode && policy && (valid & (1U << 3)) && !(valid & ~size_attributes)) {
        u32 dev = BPF_CORE_READ(inode, i_sb, s_dev);
        struct file_key key = { .major = dev >> 20, .minor = dev & ((1U << 20) - 1),
                                .ino = BPF_CORE_READ(inode, i_ino) };
        struct file_policy_value *entry = bpf_map_lookup_elem(policy, &key);
        if (entry && (entry->flags & SECMON_FILE_VAULT))
            return guard_inode_policy(inode, SECMON_OP_TRUNCATE, policy);
    }
    return guard_inode_policy(inode, SECMON_OP_SETATTR, policy);
}
/* 新增共享可写映射可以绕开 write 系统调用；这里检查映射建立，下面检查后续 mprotect 增加写权限。 */
/* 私有映射写入自己的页而不写回原文件；策略不撤销启用之前已经存在的共享可写映射。 */
SEC("lsm/mmap_file")
int BPF_PROG(guard_mmap, struct file *file, unsigned long reqprot,
             unsigned long prot, unsigned long flags, int ret)
{
    if (ret) return ret;
    /* MAP_SHARED=1, MAP_SHARED_VALIDATE=3; MAP_PRIVATE=2. */
    if (!file) return 0;
    void *policy = active_file_policy();
    struct inode *inode = BPF_CORE_READ(file, f_inode);
    // Private writable and executable mappings also expose file contents.
    int denied = prot ? guard_inode_policy(inode, SECMON_OP_MMAP_READ, policy) : 0;
    return denied ? denied : ((prot & 2) && (flags & 1)) ?
        guard_inode_policy(inode, SECMON_OP_MMAP_WRITE, policy) : 0;
}
SEC("lsm/file_mprotect")
int BPF_PROG(guard_mprotect, struct vm_area_struct *vma, unsigned long reqprot,
             unsigned long prot, int ret)
{
    if (ret) return ret;
    /* 匿名 VMA 没有 file，直接跳过； */
    /* 对文件共享 VMA 增加写权限时，再按原文件 inode 判断。 */
    struct file *file = BPF_CORE_READ(vma, vm_file);
    /* VM_SHARED=0x8, PROT_WRITE=0x2. */
    if (!file) return 0;
    void *policy = active_file_policy();
    struct inode *inode = BPF_CORE_READ(file, f_inode);
    int denied = prot ? guard_inode_policy(inode, SECMON_OP_MMAP_READ, policy) : 0;
    return denied ? denied : ((prot & 2) && (BPF_CORE_READ(vma, vm_flags) & 8)) ?
        guard_inode_policy(inode, SECMON_OP_MMAP_WRITE, policy) : 0;
}
