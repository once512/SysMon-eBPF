// SPDX-License-Identifier: MIT
#pragma once
#include "owned_fd.h"
#include <string>
namespace vault {
// Narrow writer for a private root policy, not a general policy storage layer.
// All cooperating vaultctl writers hold the adjacent lock across publish/reload.
class PolicyFile {
    OwnedFd directory_, lock_;
    std::string name_;
public:
    explicit PolicyFile(const std::string &path, bool exclusive);
    std::string read() const;
    // Compare current bytes before atomic replacement; callers serialize other
    // root editors. Returns only after file and containing directory fsync.
    void replace(const std::string &expected, const std::string &contents) const;
};
}
