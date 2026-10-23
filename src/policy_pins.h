// SPDX-License-Identifier: MIT
#pragma once
#include "owned_fd.h"
#include <functional>
#include <map>
#include <string>
#include <sys/stat.h>
#include <vector>
// One bounded preparation child; a scoped cache supplies the exact returned
// O_PATH references during the later, non-yielding backend transaction.
class PolicyPins {
    struct Entry { OwnedFd fd; struct stat attributes; };
    std::map<std::string, Entry> files_;
    static thread_local const PolicyPins *active_;
public:
    PolicyPins(const std::vector<std::string> &paths, const std::function<void()> &progress);
    ~PolicyPins();
    PolicyPins(const PolicyPins &) = delete;
    PolicyPins &operator=(const PolicyPins &) = delete;
    static void reap() noexcept;
    static bool copy(const std::string &path, OwnedFd &fd, struct stat &attributes);
};
