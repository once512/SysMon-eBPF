// SPDX-License-Identifier: MIT
#pragma once
#include <string>
#include <vector>

struct Options {
    bool check = false;
    std::vector<std::string> paths;
    std::string control_path;
    unsigned int run_seconds = 0;
};
enum class CliAction { run, help, stop };
// Throws std::invalid_argument for malformed options; performs no BPF/socket I/O.
CliAction parse_options(int argc, char **argv, Options &options);
