/**
 * 该文件职责为提权检测
*/

#include "vmlinux.h"
#define CAP_SETUID 7    // 内核中 CAP_SETUID 的能力位编号是 7

struct cred_baseline {
    u32 euid;
    u64 caps;
};
// 用于存储进程合法凭证基线的 Hash Map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32); // PID (TGID)
    __type(value, struct cred_baseline);
    __uint(max_entries, 10240);
} cred_map SEC(".maps");

// 在权限凭证变更时被触发，记录合法的权限变更
SEC("lsm/cred_prepare")
int BPF_PROG(lsm_cred_prepare, struct cred *new, const struct cred *old, gfp_t gfp)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct cred_baseline base = {};
    base.euid = BPF_CORE_READ(new, euid.val);
    base.caps = BPF_CORE_READ(new, cap_effective.val);
    bpf_map_update_elem(&cred_map, &pid, &base, BPF_ANY);
    return 0;
}

// 在新进程task_struct创建时被触发
// 面对的场景是fork、clone的子进、线程
// 若不记录，会导致 upchk_lv2 校验查表失败，提权进程被防误报逻辑放行
SEC("lsm/task_alloc")
int BPF_PROG(lsm_task_alloc, struct task_struct *task, unsigned long clone_flags)
{
    // 此时 task 指向刚刚分配好、还没开始运行的子进程，可以直接读出新 PID
    u32 child_pid = BPF_CORE_READ(task, tgid);
    // 当前 CPU 上下文依然是父进程
    struct task_struct *parent = (struct task_struct *)bpf_get_current_task();
    struct cred_baseline base = {};
    // 读取父进程的合法权限，作为子进程的初始基线
    base.euid = BPF_CORE_READ(parent, cred, euid.val);
    base.caps = BPF_CORE_READ(parent, cred, cap_effective.val);
    // 将子进程的初始基线写入 Map，完成状态的继承
    bpf_map_update_elem(&cred_map, &child_pid, &base, BPF_ANY);
    return 0;
}

// 进程退出时清理基线，防止 PID 轮转复用导致误报
SEC("lsm/task_free")
int BPF_PROG(lsm_task_free, struct task_struct *task)
{
    u32 pid = BPF_CORE_READ(task, tgid);
    bpf_map_delete_elem(&cred_map, &pid);
    return 0;
}

// 应对仅基于内存修改的粗糙提权
static inline bool upchk_lv1(struct task_struct *task)
{
    // 提取当前进程内存中的实际凭证状态
    u32 current_euid = BPF_CORE_READ(task, cred, euid.val);
    u32 current_suid = BPF_CORE_READ(task, cred, suid.val);
    u64 caps = BPF_CORE_READ(task, cred, cap_effective.val);
    // 如果 EUID 是 0，但 SUID 不是 0
    if (current_euid == 0 && current_suid != 0) {
        // 并且该进程并不具备合法提权的能力 (没有 CAP_SETUID)
        if (!(caps & (1ULL << CAP_SETUID))) {
            // 这说明进程的 cred 结构体极大概率被内核漏洞直接覆写了！
            // 黑客即使提权成功，也无法执行任何后续的 Shell 或命令，攻击链在此彻底断裂。
            return true;
        }
    }
    return false;
}

// 应对完美提权：运行过程中利用ROP链，
// 在内核将权限完美提升，导致与启动时的权限不匹配
static inline bool upchk_lv2(struct task_struct *task)
{
    u32 pid = BPF_CORE_READ(task, tgid);
    struct cred_baseline *base;

    // 从 Map 提取合法基线
    base = bpf_map_lookup_elem(&cred_map, &pid);
    if (!base) {
        // 找不到基线，这可能是探针启动前就已经存在的进程
        return false;
    }

    u32 current_euid = BPF_CORE_READ(task, cred, euid.val);
    // 合法基线中该进程不是 root，但现在的实际内存里它却是 root
    if (base->euid != 0 && current_euid == 0) {
        return true;
    }
    return false;
}
