// SPDX-License-Identifier: MIT
#pragma once
#include "protocol.h"
#include <string>

namespace analysis {
// Literal marker rule, not a malware classifier. Only bounded regular-file reads.
Response scan(int fd, std::uint64_t id, const std::string &marker, std::uint32_t limit);
}
