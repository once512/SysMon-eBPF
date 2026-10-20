// SPDX-License-Identifier: MIT
// libFuzzer 的语法/归一化属性：接受的文本必须能按完整值模型重编码并稳定重解析。
// 仅解析内存，使用虚构路径；不读取实际文件、不创建 socket、不加载 BPF/fanotify。
#include "policy_config.h"
#include <secmon/policy_limits.h>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <optional>
#include <sstream>
#include <string>

namespace {
std::string canonical(const PolicyConfig &policy)
{
    std::ostringstream out;
    out << "revision " << policy.revision << '\n';
    for (const auto &path : policy.paths) out << "protect " << std::quoted(path) << '\n';
    // 数字 mask 不属于配置语法；测试编码器把每个有效位明确还原为操作名。
    const char *names[] = {"open-write", "write", "truncate", "unlink", "rename", "link", "setattr", "mmap-write"};
    for (const auto &writer : policy.writers) {
        out << "allow-writer " << std::quoted(writer.path) << ' ' << writer.euid << ' ' << std::quoted(writer.target) << ' ';
        bool first = true;
        for (unsigned operation = 0; operation < 8; ++operation) {
            if (!(writer.operations & (1U << operation))) continue;
            if (!first) out << ',';
            out << names[operation];
            first = false;
        }
        out << '\n';
    }
    if (policy.fanotify) {
        const auto &fan = *policy.fanotify;
        for (const auto &path : fan.paths) out << "fanotify-file " << std::quoted(path) << '\n';
        out << "fanotify-event " << fan.event
            << "\nfanotify-timeout-ms " << fan.timeout_ms << "\nfanotify-max-pending " << fan.max_pending
            << "\nfanotify-timeout-decision " << (fan.timeout_allow ? "allow" : "deny")
            << "\nfanotify-overload-decision " << (fan.overload_allow ? "allow" : "deny") << '\n';
        if (fan.analyzer.empty()) {
            out << "fanotify-decision " << fan.decision << "\nfanotify-delay-ms " << fan.delay_ms << '\n';
        } else {
            out << "fanotify-analyzer " << std::quoted(fan.analyzer) << "\nfanotify-marker " << std::quoted(fan.marker)
                << "\nfanotify-scan-limit-bytes " << fan.scan_limit
                << "\nfanotify-error-decision " << (fan.analyzer_error_allow ? "allow" : "deny") << '\n';
        }
    }
    return out.str();
}
}
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size)
{
    std::optional<PolicyConfig> accepted;
    try {
        std::istringstream input(std::string(reinterpret_cast<const char *>(data), size));
        accepted = parse_policy(input);
    } catch (const std::runtime_error &) {
        return 0; // 非法输入被明确拒绝属于正常结果；只在这层捕获预期的解析拒绝。
    }
    const auto encoded = canonical(*accepted);
    // 重编码会显式展开默认值/操作名，可能比原输入长；超过文本预算不属于解析器错误。
    if (encoded.size() > SECMON_POLICY_MAX_BYTES) return 0;
    std::istringstream input(encoded);
    const auto reparsed = parse_policy(input); // 接受的模型若无法重解析，不捕获此异常，交给 fuzzer 记录最小输入。
    if (canonical(reparsed) != encoded) std::abort();
    return 0;
}
