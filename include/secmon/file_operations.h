/* SPDX-License-Identifier: MIT */
/* 操作号与审计事件共用；授权掩码包含文件修改检查点；事件操作号与授权位通过显式映射分离。 */
#ifndef SECMON_FILE_OPERATIONS_H
#define SECMON_FILE_OPERATIONS_H
enum secmon_file_operation {
    SECMON_OP_OPEN_WRITE = 1, SECMON_OP_WRITE, SECMON_OP_TRUNCATE,
    SECMON_OP_UNLINK, SECMON_OP_RENAME, SECMON_OP_LINK, SECMON_OP_SETATTR,
    SECMON_OP_MMAP_WRITE, SECMON_OP_SIGNAL, SECMON_OP_PTRACE,
    SECMON_OP_OPEN_READ, SECMON_OP_READ, SECMON_OP_MMAP_READ, SECMON_OP_TASK_CREATE, SECMON_OP_EXEC,
    SECMON_OP_SETXATTR, SECMON_OP_REMOVEXATTR, SECMON_OP_SETACL, SECMON_OP_REMOVEACL,
    SECMON_OP_IOCTL_WRITE, SECMON_OP_IOCTL_CONTROL
};
#define SECMON_FILE_OPERATION_COUNT 13U
#define SECMON_FILE_OPERATION_MASK ((1U << SECMON_FILE_OPERATION_COUNT) - 1U)
/* Existing operation IDs and their grant bits stay stable. Reads and task
 * operations must never accidentally become writer grants. */
static inline unsigned secmon_writer_operation_index(unsigned operation)
{
    if (operation >= SECMON_OP_OPEN_WRITE && operation <= SECMON_OP_MMAP_WRITE)
        return operation - SECMON_OP_OPEN_WRITE;
    if (operation >= SECMON_OP_SETXATTR && operation <= SECMON_OP_IOCTL_WRITE)
        return 8U + operation - SECMON_OP_SETXATTR;
    return SECMON_FILE_OPERATION_COUNT;
}
#endif
