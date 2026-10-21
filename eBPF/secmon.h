// 内核与用户态共同包含的事件 ABI：类型、字段顺序和对齐都属于接口，不能只改一侧。
// 每条事件携带 version/size，宿主校验后才解读；这里不是磁盘格式或跨架构网络协议。
#ifndef SECMON_H
#define SECMON_H
#include <secmon/policy_limits.h>
#include <secmon/file_operations.h>
/* 当前唯一事件布局标识，供宿主检错；不存在历史事件解码或兼容分支。 */
#define SECMON_ABI_VERSION 5
#define SECMON_COMM_LEN 16
#define SECMON_PATH_LEN 256
#define SECMON_BASELINE_MISMATCH 1U
#define SECMON_WRITER_LEASE_EXPIRED 2U
enum secmon_event_kind { SECMON_EXEC_CHECK = 1, SECMON_EXEC_SUCCESS = 2, SECMON_FILE_DENIED = 3, SECMON_SELF_DENIED_EVENT = 4 };
// inode 号只在相应文件系统/设备身份内有意义，不能单独作为跨设备策略键。
/* 同样的 ino 数字可以同时存在于不同文件系统； */
/* 键还需设备身份，且用户态必须持有 inode 引用防止回收复用。 */
struct file_key {
    unsigned int major;
    unsigned int minor;
    unsigned long long ino;
};
// 策略 Map 的私有布局，不改变审计事件 ABI；候选与模板必须使用相同容量和 value 大小。
#define SECMON_FILE_READONLY 1U
#define SECMON_FILE_WRITER 2U
#define SECMON_FILE_IDENTITY 4U
/* writer_euid 只有 WRITER 位存在时才有效； */
/* 默认零值不是“所有 root 程序自动可信”。 */
struct file_policy_value {
    unsigned int flags;
    unsigned int writer_euid;
    /* 本程序 inode 对应的授权规则位；多个路径/目标规则合并为同一主体身份。 */
    unsigned long long writer_rules;
    /* 每个操作对应一组规则位；只有主体规则与目标操作规则存在交集才允许。 */
    unsigned long long allowed_writers[SECMON_FILE_OPERATION_COUNT];
    /* CLOCK_BOOTTIME nanoseconds, including suspend. Zero means no lease. */
    unsigned long long writer_deadline_boot_ns;
};
// 同一个结构承载多类事件，kind 决定哪些字段有效；所有事件先清零，宿主再按 kind 输出。
struct exec_event {
    unsigned int version;
    unsigned int size;
    unsigned int kind;
    unsigned int old_tid;
    struct file_key file;
    unsigned int operation;
    unsigned int target_pid;
    int signal;
    // timestamp_ns 是事件发生时的单调时间；start_ns 来自任务启动时间，用于生命周期身份，均不是墙上时钟日期。
    unsigned long long timestamp_ns;
    // 该启动时间与上面的事件时间来源不同，不直接相减计算运行时长；此处只用它区分任务生命周期。
    unsigned long long start_ns;
    // Boot-scoped pidfs inode of the process TGID; zero when unavailable.
    unsigned long long process_inode;
    unsigned long long caps;
    unsigned int pid;
    unsigned int tid;
    unsigned int ppid;
    unsigned int caller_uid;
    unsigned int caller_euid;
    /* Check: preliminary bprm candidate, not final setuid prediction.
     * Success: committed task EUID (bprm->cred has been consumed). */
    unsigned int target_euid;
    // 位 0 仅表示执行检查时当前凭证偏离观测基线；exec_success 的 0 不表示又做了一轮异常检测。
    unsigned int flags;
    unsigned short file_mode;
    char comm[SECMON_COMM_LEN];
    char filename[SECMON_PATH_LEN];
};
enum secmon_stat { SECMON_DROPPED, SECMON_BASELINE_FAILED, SECMON_POLICY_DENIED, SECMON_SELF_DENIED, SECMON_STAT_COUNT };
#endif
