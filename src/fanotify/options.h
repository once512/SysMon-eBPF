// SPDX-License-Identifier: MIT
#pragma once
#include "decisions.h"
#include "event_kind.h"
#include "analysis/client.h"
#include <string>

struct FanotifyOptions {
    std::string path;
    std::string policy_path;
    std::string control_path;
    enum class Action { run, stop, reload } action = Action::run;
    PermissionEvent event = PermissionEvent::open;
    DecisionConfig decision;
    AnalyzerConfig analyzer;
    unsigned int seconds = 0;
};
// Returns false for --help, throws std::invalid_argument for malformed options.
bool parse_fanotify_options(int argc, char **argv, FanotifyOptions &options);
