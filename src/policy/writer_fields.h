// SPDX-License-Identifier: MIT
// 配置操作名到固定掩码的转换；名称表示内核检查点，不能把一个名字解释为所有相关系统调用授权。
#pragma once
#include <cstdint>
#include <string>
std::uint32_t parse_writer_operations(const std::string &text);
