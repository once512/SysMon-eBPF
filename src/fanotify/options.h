// SPDX-License-Identifier: MIT
// fanotify 启动参数；配置文件模式与逐项策略参数互斥，避免两个来源存在隐含覆盖顺序。
#pragma once
#include "decisions.h"
#include "event_kind.h"
#include "analysis/client.h"
#include <string>

struct FanotifyOptions {
    std::string path;
    std::string policy_path;
    std::string control_path;
    enum class Action { run, stop, reload, status } action = Action::run;
    PermissionEvent event = PermissionEvent::open;
    DecisionConfig decision;
    AnalyzerConfig analyzer;
    unsigned int seconds = 0;
};
// Returns false for --help, throws std::invalid_argument for malformed options.
bool parse_fanotify_options(int argc, char **argv, FanotifyOptions &options);
