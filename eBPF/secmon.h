#ifndef SECMON_H
#define SECMON_H
#define SECMON_ABI_VERSION 4
#define SECMON_COMM_LEN 16
#define SECMON_PATH_LEN 256
#define SECMON_BASELINE_MISMATCH 1U
enum secmon_event_kind { SECMON_EXEC_CHECK = 1, SECMON_EXEC_SUCCESS = 2, SECMON_FILE_DENIED = 3, SECMON_SELF_DENIED_EVENT = 4 };
struct file_key {
    unsigned int major;
    unsigned int minor;
    unsigned long long ino;
};
enum secmon_file_operation {
    SECMON_OP_OPEN_WRITE = 1, SECMON_OP_WRITE, SECMON_OP_TRUNCATE,
    SECMON_OP_UNLINK, SECMON_OP_RENAME, SECMON_OP_LINK, SECMON_OP_SETATTR,
    SECMON_OP_MMAP_WRITE, SECMON_OP_SIGNAL, SECMON_OP_PTRACE
};
struct exec_event {
    unsigned int version;
    unsigned int size;
    unsigned int kind;
    unsigned int old_tid;
    struct file_key file;
    unsigned int operation;
    unsigned int target_pid;
    int signal;
    unsigned long long timestamp_ns;
    unsigned long long start_ns;
    unsigned long long caps;
    unsigned int pid;
    unsigned int tid;
    unsigned int ppid;
    unsigned int caller_uid;
    unsigned int caller_euid;
    /* Check: preliminary bprm candidate, not final setuid prediction.
     * Success: committed task EUID (bprm->cred has been consumed). */
    unsigned int target_euid;
    unsigned int flags;
    unsigned short file_mode;
    char comm[SECMON_COMM_LEN];
    char filename[SECMON_PATH_LEN];
};
enum secmon_stat { SECMON_DROPPED, SECMON_BASELINE_FAILED, SECMON_POLICY_DENIED, SECMON_SELF_DENIED, SECMON_STAT_COUNT };
#endif
