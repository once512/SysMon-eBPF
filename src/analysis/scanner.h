// SPDX-License-Identifier: MIT
// 有界字节标记扫描器：输入已打开 FD，输出 allow/deny/error；它是机制示例，不是恶意软件分类器。
#pragma once
#include "protocol.h"
#include <string>

namespace analysis {
// Literal marker rule, not a malware classifier. Only bounded regular-file reads.
// 借用 fd，不关闭也不改变共享文件偏移；
// id 原样带回，limit 的单位是字节，marker 是区分大小写的字面字节串。
// allow 只说明本次有界完整读取未命中规则，不证明文件无恶意，更不代表它之后不会变化。
Response scan(int fd, std::uint64_t id, const std::string &marker, std::uint32_t limit);
}
