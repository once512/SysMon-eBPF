// SPDX-License-Identifier: MIT
// 配置解析与安全读取：先完整校验文本，再由调用方准备运行资源；本模块不修改 Map 或 fanotify mark。
// 先用 O_PATH 固定配置，再读取同一对象；fanotify 重载排除自己的目标 inode，防止自等裁决。
#include "policy_config.h"
#include "owned_fd.h"
#include <charconv>
#include <cerrno>
#include <fcntl.h>
#include <iomanip>
#include <set>
#include <sstream>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>

namespace {
constexpr std::size_t max_bytes = 65536;
[[noreturn]] void invalid() { throw std::runtime_error("Invalid policy: expected positive revision and valid bounded policy directives"); }
}
PolicyConfig parse_policy(std::istream &input)
{
    PolicyConfig result;
    FanotifyPolicy gate;
    std::set<std::string> gate_keys;
    std::set<std::string> unique;
    std::set<std::string> writer_paths;
    std::size_t bytes = 0;
    std::string line;
    // 逐行累计原始长度并拒绝 NUL；
    // 先得到完整候选数据，再由后端访问文件/Map，解析本身没有挂载副作用。
    while (std::getline(input, line)) {
        bytes += line.size() + (input.eof() ? 0 : 1);
        if (bytes > max_bytes || line.find('\0') != std::string::npos) invalid();
        std::istringstream fields(line);
        std::string key, value, extra;
        if (!(fields >> key) || key.front() == '#') continue;
        if (key == "protect") {
            fields >> std::ws;
            if (fields.peek() != '"' || !(fields >> std::quoted(value)) ||
                value.empty() || value.front() != '/' || value.size() > 4095 ||
                !unique.insert(value).second || result.paths.size() == 256) invalid();
            result.paths.push_back(value);
        // 这里去重的是路径文本；
        // 硬链接是否指向同一 inode、是否配置冲突 UID，要到后端固定对象后才能判断。
        } else if (key == "allow-writer") {
            fields >> std::ws;
            if (fields.peek() != '"' || !(fields >> std::quoted(value)) ||
                value.empty() || value.front() != '/' || value.size() > 4095 ||
                !writer_paths.insert(value).second || result.writers.size() == 64) invalid();
            std::string uid;
            std::uint32_t number = 0;
            if (!(fields >> uid)) invalid();
            const auto parsed = std::from_chars(uid.data(), uid.data() + uid.size(), number);
            // (uid_t)-1 是内核无效 UID，不能成为授权主体。
            if (parsed.ec != std::errc{} || parsed.ptr != uid.data() + uid.size() || number == UINT32_MAX) invalid();
            result.writers.push_back({value, number});
        } else if (key.compare(0, 9, "fanotify-") == 0) {
            if (!gate_keys.insert(key).second) invalid();
            if (key == "fanotify-file" || key == "fanotify-analyzer" || key == "fanotify-marker") {
                fields >> std::ws;
                if (fields.peek() != '"' || !(fields >> std::quoted(value))) invalid();
                if (key == "fanotify-marker") {
                    if (value.empty() || value.size() > 256) invalid();
                    gate.marker = value;
                } else {
                    if (value.empty() || value.front() != '/' || value.size() > 4095) invalid();
                    (key == "fanotify-file" ? gate.path : gate.analyzer) = value;
                }
            } else {
                if (!(fields >> value)) invalid();
                // from_chars 同时检查转换结果与结束位置，避免把 100ms 或 12abc 的合法前缀当作完整数值。
                auto numeric = [&](unsigned int minimum, unsigned int maximum) {
                    unsigned int number = 0;
                    const auto parsed = std::from_chars(value.data(), value.data() + value.size(), number);
                    if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size() ||
                        number < minimum || number > maximum) invalid();
                    return number;
                };
                auto allow = [&]() {
                    if (value != "allow" && value != "deny") invalid();
                    return value == "allow";
                };
                if (key == "fanotify-event") {
                    if (value != "open" && value != "access" && value != "exec") invalid();
                    gate.event = value;
                } else if (key == "fanotify-decision") { (void)allow(); gate.decision = value; }
                else if (key == "fanotify-delay-ms") gate.delay_ms = numeric(0, 60000);
                else if (key == "fanotify-timeout-ms") gate.timeout_ms = numeric(1, 60000);
                else if (key == "fanotify-max-pending") gate.max_pending = numeric(1, 4096);
                else if (key == "fanotify-scan-limit-bytes") gate.scan_limit = numeric(1, 1048576);
                else if (key == "fanotify-timeout-decision") gate.timeout_allow = allow();
                else if (key == "fanotify-overload-decision") gate.overload_allow = allow();
                else if (key == "fanotify-error-decision") gate.analyzer_error_allow = allow();
                else invalid();
            }
        } else {
            if (!(fields >> value)) invalid();
            if (key == "revision" && !result.revision) {
                const auto parsed = std::from_chars(value.data(), value.data() + value.size(), result.revision);
                if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size() || !result.revision) invalid();
            } else invalid();
        }
        // 每行恰好消费允许的字段；
        // 多余参数或行尾注释都拒绝，避免不同读取者产生不同解释。
        if (fields >> extra) invalid();
    }
    if (input.bad() || !result.revision) invalid();
    // 字段逐条解析后再校验整体约束，允许字段换序，但禁止混用静态决策与分析器专属字段。
    // 整体约束在读完后统一检查，故字段可换序；
    // 静态模式和分析模式的互斥不能只靠单行语法决定。
    if (!gate_keys.empty()) {
        if (gate.path.empty()) invalid();
        if (gate.analyzer.empty()) {
            if (gate.decision.empty() || gate_keys.count("fanotify-marker") ||
                gate_keys.count("fanotify-scan-limit-bytes") || gate_keys.count("fanotify-error-decision")) invalid();
        } else if (gate.marker.empty() || !gate.decision.empty() || gate_keys.count("fanotify-delay-ms")) invalid();
        result.fanotify = std::move(gate);
    }
    return result;
}
PolicyConfig load_policy(const std::string &path, int forbidden_inode_fd)
{
    if (path.empty() || path.front() != '/') throw std::runtime_error("Policy file must be absolute");
    OwnedFd pinned(open(path.c_str(), O_PATH | O_NOFOLLOW | O_CLOEXEC));
    struct stat before{}, after{};
    if (pinned.get() < 0 || fstat(pinned.get(), &before) || !S_ISREG(before.st_mode) ||
        before.st_uid != 0 || (before.st_mode & 022) || before.st_size > static_cast<off_t>(max_bytes))
        throw std::runtime_error("Policy must be a root-owned regular file, not writable by group/others, at most 64 KiB");
    // 必须在 O_RDONLY 打开之前排除监听器自身目标：否则 open/access 权限事件会让服务等待自己的裁决。
    if (forbidden_inode_fd >= 0) {
        struct stat forbidden{};
        if (fstat(forbidden_inode_fd, &forbidden)) throw std::runtime_error("Cannot inspect excluded policy inode");
        if (before.st_dev == forbidden.st_dev && before.st_ino == forbidden.st_ino)
            throw std::runtime_error("Fanotify policy file cannot be the marked inode (including hard links)");
    }
    // Reopen the pinned object, not the mutable pathname. O_PATH above emits no permission event.
    const auto reference = "/proc/self/fd/" + std::to_string(pinned.get());
    OwnedFd fd(open(reference.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC));
    if (fd.get() < 0) throw std::runtime_error("Cannot open pinned policy for reading");
    // 原始字节另行保留用于 SHA-256；
    // 摘要包含注释/空白，与解析后相同语义的配置不一定相同。
    std::string contents;
    char chunk[4096];
    for (;;) {
        const auto count = read(fd.get(), chunk, sizeof(chunk));
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) throw std::runtime_error("Cannot read policy");
        if (!count) break;
        contents.append(chunk, static_cast<std::size_t>(count));
        if (contents.size() > max_bytes) throw std::runtime_error("Policy exceeds 64 KiB");
    }
    // 比较元数据可发现普通并发修改，但不是不可变快照；部署时仍应使用可信目录中的原子文件替换。
    if (fstat(fd.get(), &after) || before.st_size != after.st_size ||
        before.st_mtim.tv_sec != after.st_mtim.tv_sec || before.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
        before.st_ctim.tv_sec != after.st_ctim.tv_sec || before.st_ctim.tv_nsec != after.st_ctim.tv_nsec)
        throw std::runtime_error("Policy changed while reading; retry with an atomic file replacement");
    std::istringstream input(contents);
    auto parsed = parse_policy(input);
    // 摘要随成功加载的候选返回；
    // 是否成为活动摘要由 PolicyRuntime 的后端提交结果决定。
    parsed.source_digest = content_digest(contents);
    return parsed;
}
