#ifndef SECMON_H
#define SECMON_H
#define SECMON_ABI_VERSION 2
#define SECMON_COMM_LEN 16
#define SECMON_PATH_LEN 256
#define SECMON_BASELINE_MISMATCH 1U
enum secmon_event_kind { SECMON_EXEC_CHECK = 1, SECMON_EXEC_SUCCESS = 2 };
struct exec_event {
    unsigned int version;
    unsigned int size;
    unsigned int kind;
    unsigned int old_tid;
    unsigned long long timestamp_ns;
    unsigned long long start_ns;
    unsigned long long caps;
    unsigned int pid;
    unsigned int tid;
    unsigned int ppid;
    unsigned int caller_uid;
    unsigned int caller_euid;
    unsigned int target_euid;
    unsigned int flags;
    unsigned short file_mode;
    char comm[SECMON_COMM_LEN];
    char filename[SECMON_PATH_LEN];
};
enum secmon_stat { SECMON_DROPPED, SECMON_BASELINE_FAILED, SECMON_STAT_COUNT };
#endif
