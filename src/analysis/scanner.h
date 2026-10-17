// SPDX-License-Identifier: MIT
// 有界字节标记扫描器：输入已打开 FD，输出 allow/deny/error；它是机制示例，不是恶意软件分类器。
#pragma once
#include "protocol.h"
#include <string>

namespace analysis {
// Literal marker rule, not a malware classifier. Only bounded regular-file reads.
Response scan(int fd, std::uint64_t id, const std::string &marker, std::uint32_t limit);
}
