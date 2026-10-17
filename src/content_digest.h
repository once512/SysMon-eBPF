// SPDX-License-Identifier: MIT
// 配置原始字节的 SHA-256 指纹，仅用于核对内容身份；没有签名、授权或持久防回滚语义。
#pragma once
#include <array>
#include <cstdint>
#include <string>
#include <string_view>
using ContentDigest = std::array<std::uint8_t, 32>;
// bytes 是不要求末尾 NUL 的字节视图；
// 返回固定 32 字节值，调用结束后不保留输入指针。
ContentDigest content_digest(std::string_view bytes);
std::string digest_hex(const ContentDigest &digest);
