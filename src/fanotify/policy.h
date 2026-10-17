// SPDX-License-Identifier: MIT
// 配置适配边界：共享文本模型不依赖 fanotify 运行类，本模块负责转换与不可在线变更字段比较。
#pragma once
#include "options.h"
#include "policy_config.h"
// Convert the shared format to runtime types; neither opens a fanotify group.
void apply_fanotify_policy(const PolicyConfig &policy, FanotifyOptions &options);
// These fields identify the existing mark/worker and require a restart to change.
bool same_fanotify_backend(const FanotifyOptions &left, const FanotifyOptions &right);
