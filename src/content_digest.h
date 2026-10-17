// SPDX-License-Identifier: MIT
// 配置原始字节的 SHA-256 指纹，仅用于核对内容身份；没有签名、授权或持久防回滚语义。
#pragma once
#include <array>
#include <cstdint>
#include <string>
#include <string_view>
using ContentDigest = std::array<std::uint8_t, 32>;
ContentDigest content_digest(std::string_view bytes);
std::string digest_hex(const ContentDigest &digest);
