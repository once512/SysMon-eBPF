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
// 解析成功仅得到运行意图，不会创建 mark 或连接控制端；
// 返回 true 时还需按 action 区分服务与管理命令。
bool parse_fanotify_options(int argc, char **argv, FanotifyOptions &options);
