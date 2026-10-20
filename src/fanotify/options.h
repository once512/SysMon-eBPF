// SPDX-License-Identifier: MIT
// fanotify 启动参数；配置文件模式与逐项策略参数互斥，避免两个来源存在隐含覆盖顺序。
#pragma once
#include "decisions.h"
#include "event_kind.h"
#include "analysis/client.h"
#include <string>
#include <vector>

struct FanotifyOptions {
    std::vector<std::string> paths;
    PermissionEvent event = PermissionEvent::open;
    DecisionConfig decision;
    AnalyzerConfig analyzer;
};
// 仅转换逐项 fanotify CLI 参数；公共服务选项由统一入口解析。
void parse_fanotify_options(int argc, char **argv, FanotifyOptions &options);
