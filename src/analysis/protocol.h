// SPDX-License-Identifier: MIT
// 宿主与降权分析进程之间的私有二进制协议：本机、同架构固定布局，不传用户指针和文件路径。
// 请求正文携带 ID，真实文件通过 SCM_RIGHTS 另传一个 FD；响应只携带结果，不应返回 FD。
#pragma once
#include <cstdint>

// Local-only, fixed-width protocol. No pointers, paths, or task authorization.
namespace analysis {
constexpr std::uint32_t magic = 0x53434d41;
constexpr std::uint16_t version = 2;
// id=0 留给 Ready 握手，普通请求从非零 ID 开始；正文不包含 FD 数字，FD 通过辅助消息单独传递。
struct Request {
    std::uint32_t magic_value = magic;
    std::uint16_t abi = version;
    std::uint16_t size = sizeof(Request);
    std::uint64_t id = 0;
};
// error 表示无法完成可靠扫描，最终放行还是拒绝由父服务的错误回退决定，不是直接等同 deny。
enum class Result : std::uint32_t { allow = 1, deny = 2, error = 3, ready = 4 };
struct Response {
    std::uint32_t magic_value = magic;
    std::uint16_t abi = version;
    std::uint16_t size = sizeof(Response);
    std::uint64_t id = 0;
    Result result = Result::error;
    std::uint32_t bytes_scanned = 0;
};
// 用编译期检查固定本机布局；没有字节序转换，不能直接用于跨架构或跨版本网络通信。
static_assert(sizeof(Request) == 16 && sizeof(Response) == 24);
}
