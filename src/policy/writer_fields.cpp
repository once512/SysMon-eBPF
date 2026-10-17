// SPDX-License-Identifier: MIT
// 显式 all 仅授予指定目标上的全部文件操作；空项、重复名、未知名和 all 混合列表均拒绝。
#include "writer_fields.h"
#include "fields.h"
#include <secmon/file_operations.h>
#include <array>
#include <string_view>
#include <utility>
std::uint32_t parse_writer_operations(const std::string &text)
{
    if (text == "all") return SECMON_FILE_OPERATION_MASK;
    constexpr std::array<std::pair<std::string_view, unsigned>, SECMON_FILE_OPERATION_COUNT> names = {{
        {"open-write", SECMON_OP_OPEN_WRITE}, {"write", SECMON_OP_WRITE}, {"truncate", SECMON_OP_TRUNCATE},
        {"unlink", SECMON_OP_UNLINK}, {"rename", SECMON_OP_RENAME}, {"link", SECMON_OP_LINK},
        {"setattr", SECMON_OP_SETATTR}, {"mmap-write", SECMON_OP_MMAP_WRITE}}};
    std::uint32_t result = 0;
    std::size_t start = 0;
    for (;;) {
        const auto end = text.find(',', start);
        const auto part = std::string_view(text).substr(start, end == std::string::npos ? end : end - start);
        std::uint32_t bit = 0;
        for (const auto &[name, operation] : names)
            if (part == name) bit = 1U << (operation - 1);
        if (!bit || (result & bit)) policy_fields::invalid("unknown, empty or duplicate writer operation");
        result |= bit;
        if (end == std::string::npos) return result;
        start = end + 1;
    }
}
