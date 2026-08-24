#ifndef __SECMON_H
#define __SECMON_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256

// Linux 标准的 SUID 和 SGID 掩码
#define CORE_S_ISUID 04000
#define CORE_S_ISGID 02000

struct exec_event {
    unsigned int pid;
    unsigned int ppid;
    unsigned int caller_uid;
    unsigned int target_euid;
    unsigned short file_mode;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
};

#endif /* __SECMON_H */
