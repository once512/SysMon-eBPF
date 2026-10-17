// SPDX-License-Identifier: MIT
// 宿主与降权分析进程之间的私有二进制协议：本机、同架构固定布局，不传用户指针和文件路径。
// 请求正文携带 ID，真实文件通过 SCM_RIGHTS 另传一个 FD；响应只携带结果，不应返回 FD。
#pragma once
#include <cstdint>
#include <cstddef>

// Local-only, fixed-width protocol. No pointers, paths, or task authorization.
namespace analysis {
constexpr std::uint32_t magic = 0x53434d41;
constexpr std::uint16_t version = 3;
// id=0 留给 Ready 握手，普通请求从非零 ID 开始；正文不包含 FD 数字，FD 通过辅助消息单独传递。
// id 用于关联本实例内的请求，不是业务 PID；
// 文件能力随附件 FD 传递，而不是把正文某个整数当作远端 FD。
struct Request {
    std::uint32_t magic_value = magic;
    std::uint16_t abi = version;
    std::uint16_t size = sizeof(Request);
    std::uint64_t id = 0;
};
// error 表示无法完成可靠扫描，最终放行还是拒绝由父服务的错误回退决定，不是直接等同 deny。
enum class Result : std::uint32_t { allow = 1, deny = 2, error = 3, ready = 4 };
// 扫描失败与后端离线分开：这些原因由扫描器报告，后端协议/进程故障由宿主另行统计。
enum class ScanError : std::uint32_t {
    none = 0, invalid_input = 1, bad_descriptor = 2, unsupported_descriptor = 3,
    metadata_failed = 4, oversized = 5, read_failed = 6, changed = 7, resource_exhausted = 8
};
constexpr std::size_t scan_error_count = 9;
inline const char *scan_error_name(ScanError error)
{
    switch (error) {
    case ScanError::none: return "none";
    case ScanError::invalid_input: return "invalid_input";
    case ScanError::bad_descriptor: return "bad_descriptor";
    case ScanError::unsupported_descriptor: return "unsupported_descriptor";
    case ScanError::metadata_failed: return "metadata_failed";
    case ScanError::oversized: return "oversized";
    case ScanError::read_failed: return "read_failed";
    case ScanError::changed: return "changed";
    case ScanError::resource_exhausted: return "resource_exhausted";
    }
    return nullptr;
}
// 这里验证原因与 errno 的组合，不验证 Response 的全部字段；
// Ready/结果/ID/附件数量还需接收方校验。
inline bool valid_scan_error(ScanError error, std::int32_t system_errno)
{
    if (!scan_error_name(error) || system_errno < 0 || system_errno > 4095) return false;
    const bool needs_errno = error == ScanError::bad_descriptor || error == ScanError::metadata_failed ||
        error == ScanError::read_failed || error == ScanError::resource_exhausted;
    return needs_errno ? system_errno > 0 : system_errno == 0;
}
// 默认 result=error 可防止未完成扫描直接变成 allow；
// 真正的 error 回复还必须填写有效的非 none 原因。
struct Response {
    std::uint32_t magic_value = magic;
    std::uint16_t abi = version;
    std::uint16_t size = sizeof(Response);
    std::uint64_t id = 0;
    Result result = Result::error;
    std::uint32_t bytes_scanned = 0;
    ScanError error = ScanError::none;
    std::int32_t system_errno = 0;
};
// 用编译期检查固定本机布局；没有字节序转换，不能直接用于跨架构或跨版本网络通信。
static_assert(sizeof(Request) == 16 && sizeof(Response) == 32);
}
