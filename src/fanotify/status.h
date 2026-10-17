// SPDX-License-Identifier: MIT
// fanotify 后端的只读快照适配；查询不会处理到期请求、读取配置或探测/重启分析器。
#pragma once
#include "gate.h"
#include "options.h"
#include "policy_runtime.h"
management::Reply fanotify_status(const PolicyRuntime &runtime, const FanotifyOptions &options,
                                 const PermissionGate &gate);
