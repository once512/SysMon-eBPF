// SPDX-License-Identifier: MIT
// fanotify 后端的只读快照适配；查询不会处理到期请求、读取配置或探测/重启分析器。
#pragma once
#include "options.h"
#include "management/protocol.h"
class PermissionGate;
void fill_fanotify_status(management::Reply &reply, const FanotifyOptions &options,
                                 const PermissionGate &gate);
