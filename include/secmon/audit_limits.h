/* SPDX-License-Identifier: MIT */
/* 审计队列只约束用户态出口，不替代内核 ring buffer 丢失计数。 */
#ifndef SECMON_AUDIT_LIMITS_H
#define SECMON_AUDIT_LIMITS_H
#define SECMON_AUDIT_MAX_RECORDS 1024U
#define SECMON_AUDIT_MAX_BYTES 1048576U
#define SECMON_AUDIT_MAX_LINE_BYTES 4096U
#endif
