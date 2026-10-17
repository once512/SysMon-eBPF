// SPDX-License-Identifier: MIT
// 使用系统 OpenSSL 的 EVP 摘要接口，避免自行实现密码算法；哈希输入包含注释、空白与末尾换行。
#include "content_digest.h"
#include <openssl/evp.h>
#include <stdexcept>
ContentDigest content_digest(std::string_view bytes)
{
    ContentDigest digest{};
    unsigned int length = 0;
    // 使用系统密码库计算字节摘要；
    // 这里没有密钥或签名，因此相同摘要只能帮助核对来源内容。
    if (EVP_Digest(bytes.data(), bytes.size(), digest.data(), &length, EVP_sha256(), nullptr) != 1 || length != digest.size())
        throw std::runtime_error("Cannot compute policy SHA-256");
    return digest;
}
std::string digest_hex(const ContentDigest &digest)
{
    constexpr char hex[] = "0123456789abcdef";
    std::string text;
    text.reserve(digest.size() * 2);
    for (const auto byte : digest) {
        text += hex[byte >> 4];
        text += hex[byte & 15];
    }
    return text;
}
