// SPDX-License-Identifier: MIT
// 文本字段的无副作用小工具：检查整段数字和显式引号，不接受合法前缀后面的尾随垃圾。
#pragma once
#include <secmon/policy_limits.h>
#include <charconv>
#include <cstdint>
#include <iomanip>
#include <istream>
#include <stdexcept>
#include <string>
namespace policy_fields {
[[noreturn]] inline void invalid(const std::string &detail) { throw std::runtime_error(detail); }
inline std::string word(std::istream &input)
{
    std::string value;
    if (!(input >> value)) invalid("missing field value");
    return value;
}
inline std::string quoted(std::istream &input, std::size_t maximum)
{
    input >> std::ws;
    std::string value;
    if (input.peek() != '"' || !(input >> std::quoted(value)) || value.empty() || value.size() > maximum)
        invalid("expected nonempty bounded double-quoted value");
    return value;
}
inline std::string path(std::istream &input)
{
    auto value = quoted(input, SECMON_POLICY_MAX_PATH_BYTES);
    if (value.front() != '/') invalid("path must be absolute");
    return value;
}
template<class Number> Number number(const std::string &value, Number minimum, Number maximum)
{
    Number result = 0;
    const auto parsed = std::from_chars(value.data(), value.data() + value.size(), result);
    if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size() || result < minimum || result > maximum)
        invalid("number outside allowed range or not an unsigned decimal");
    return result;
}
inline bool allow(const std::string &value)
{
    if (value != "allow" && value != "deny") invalid("expected allow or deny");
    return value == "allow";
}
}
