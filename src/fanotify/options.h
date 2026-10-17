// SPDX-License-Identifier: MIT
#pragma once
#include "decisions.h"
#include <string>

struct FanotifyOptions {
    std::string path;
    DecisionConfig decision;
    unsigned int seconds = 0;
};
// Returns false for --help, throws std::invalid_argument for malformed options.
bool parse_fanotify_options(int argc, char **argv, FanotifyOptions &options);
