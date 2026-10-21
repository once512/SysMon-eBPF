// SPDX-License-Identifier: MIT
// 把路径转换为稳定的文件对象身份，并构建内核 HASH Map；O_PATH 固定对象但不取得读写访问 FD。
// 候选全部准备完成后只更新一次外层 Map；候选析构回收失败路径资源，不触碰活动策略。
#include <secmon/policy_limits.h>
#include <bpf/bpf.h>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>
#include <map>
#include <time.h>
#include <limits>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include "secmon.h"

#include "file_policy.h"
#include "owned_fd.h"
#include "writer_identity.h"

namespace {
std::uint64_t lease_deadline(unsigned int milliseconds)
{
    // /proc/PID/timens_offsets describes the namespace for children. Only use
    // its offset when that is also the current clock namespace.
    struct stat current{}, children{};
    if (stat("/proc/self/ns/time", &current) || stat("/proc/self/ns/time_for_children", &children) ||
        current.st_dev != children.st_dev || current.st_ino != children.st_ino)
        throw std::runtime_error("Cannot resolve current boot-clock namespace for writer lease");
    std::ifstream offsets("/proc/self/timens_offsets");
    std::string line;
    long long offset_seconds = 0, offset_nanoseconds = 0;
    bool found = false;
    while (std::getline(offsets, line)) {
        std::istringstream fields(line);
        std::string clock;
        fields >> clock;
        if (clock != "boottime") continue;
        if (found || !(fields >> offset_seconds >> offset_nanoseconds) ||
            offset_nanoseconds < 0 || offset_nanoseconds >= 1000000000LL)
            throw std::runtime_error("Invalid boot-clock namespace offset");
        found = true;
    }
    if (!found || offsets.bad()) throw std::runtime_error("Cannot read boot-clock namespace offset");
    timespec now{};
    if (clock_gettime(CLOCK_BOOTTIME, &now)) throw std::runtime_error("Cannot read boot-time lease clock");
    // GNU++17 wide arithmetic handles both signed offsets and overflow before
    // conversion. BPF's boot-time helper uses the unshifted kernel clock.
    const __int128 global = static_cast<__int128>(now.tv_sec) * 1000000000 + now.tv_nsec -
                            (static_cast<__int128>(offset_seconds) * 1000000000 + offset_nanoseconds);
    const __int128 deadline = global + static_cast<__int128>(milliseconds) * 1000000;
    if (global < 0 || deadline > std::numeric_limits<std::uint64_t>::max())
        throw std::runtime_error("Writer lease deadline outside global clock range");
    return static_cast<std::uint64_t>(deadline);
}
}

void ProtectedFiles::install(int map_fd, const PolicyConfig &config)
{
    static_assert(sizeof(file_policy_value) == 88);
    static_assert(SECMON_MAX_WRITER_RULES <= 64, "Rule bitmap must fit uint64");
    const auto &paths = config.paths;
    if (config.writers.size() > SECMON_MAX_WRITER_RULES) throw std::runtime_error("Too many authorized writers");
    if (paths.size() > SECMON_MAX_PROTECTED_PATHS) throw std::runtime_error("Too many protected paths");
    // candidate 是未发布的事务资源集合；
    // 异常只销毁候选，当前对象仍持有活动策略的全部 inode。
    ProtectedFiles candidate;
    // 先分配保存 FD 的空间，再逐个 open；接管 FD 时不再触发 vector 扩容，减少异常路径泄漏风险。
    candidate.descriptors_.reserve(paths.size() + config.writers.size());
    // 这里创建的是内核 Map 对象，得到的是管理 FD；向 HASH 填充时尚未影响正在运行的钩子。
    OwnedFd policy_map(bpf_map_create(BPF_MAP_TYPE_HASH, "file_policy", sizeof(file_key),
                                     sizeof(file_policy_value), SECMON_POLICY_CAPACITY, nullptr));
    if (policy_map.get() < 0) throw std::runtime_error("Cannot create candidate policy map");
    std::map<std::string, file_key> target_keys;
    std::vector<file_key> writer_keys;
    writer_keys.reserve(config.writers.size());
    for (const auto &path : paths) {
        auto pinned = pin_policy_file(path, false);
        // 移动 FD 后仍可读取 pinned.key；
        // 键是值数据，FD 则已有唯一的新所有者。
        candidate.descriptors_.push_back(std::move(pinned.fd));
        const auto key = pinned.key;
        target_keys.emplace(path, key);
        file_policy_value policy{};
        policy.flags = SECMON_FILE_READONLY;
        if (bpf_map_update_elem(policy_map.get(), &key, &policy, BPF_ANY))
            throw std::runtime_error("Cannot install policy for " + path + ": " + std::strerror(errno));
        std::cerr << "Prepared policy inode " << key.major << ':' << key.minor << ':' << key.ino
                  << " path=" << path << '\n';
    }
    for (std::size_t index = 0; index < config.writers.size(); ++index) {
        const auto &writer = config.writers[index];
        const auto selected = target_keys.find(writer.target);
        if (selected == target_keys.end() || !writer.operations || (writer.operations & ~SECMON_FILE_OPERATION_MASK))
            throw std::runtime_error("Writer grant requires a protected target and valid operations");
        const auto rule = 1ULL << index;
        auto pinned = pin_policy_file(writer.path, true);
        candidate.descriptors_.push_back(std::move(pinned.fd));
        // 先读候选表已有值以合并 protect/writer 标志；
        // 不能直接覆盖，否则重合 inode 会丢失原角色。
        file_policy_value value{};
        // 同一 inode 可同时是 protect 对象和 writer；别名重复且 UID 不同则拒绝整个候选。
        if (bpf_map_lookup_elem(policy_map.get(), &pinned.key, &value) && errno != ENOENT)
            throw std::runtime_error("Cannot inspect candidate writer identity");
        if ((value.flags & SECMON_FILE_WRITER) && value.writer_euid != writer.euid)
            throw std::runtime_error("Conflicting UIDs for one writer inode");
        value.flags |= SECMON_FILE_WRITER | SECMON_FILE_IDENTITY;
        value.writer_euid = writer.euid;
        value.writer_rules |= rule;
        writer_keys.push_back(pinned.key);
        if (bpf_map_update_elem(policy_map.get(), &pinned.key, &value, BPF_ANY))
            throw std::runtime_error("Cannot prepare writer identity");
        // 从本候选已固定的 protect 对象引用取键，不额外解析目标路径，避免同一候选内路径替换。
        file_policy_value target{};
        if (bpf_map_lookup_elem(policy_map.get(), &selected->second, &target))
            throw std::runtime_error("Cannot inspect candidate grant target");
        for (unsigned int operation = 0; operation < SECMON_FILE_OPERATION_COUNT; ++operation)
            if (writer.operations & (1U << operation)) target.allowed_writers[operation] |= rule;
        if (bpf_map_update_elem(policy_map.get(), &selected->second, &target, BPF_EXIST))
            throw std::runtime_error("Cannot prepare scoped writer grant");
        std::cerr << "Prepared writer inode " << pinned.key.major << ':' << pinned.key.minor
                  << ':' << pinned.key.ino << " euid=" << writer.euid << " path=" << writer.path
                  << " target=" << writer.target << " operations=" << writer.operations << '\n';
    }
    if (config.writer_lease_ms) {
        if (writer_keys.empty() || config.writer_lease_ms < 100 || config.writer_lease_ms > 3600000)
            throw std::runtime_error("Invalid writer lease");
        const auto deadline = lease_deadline(config.writer_lease_ms);
        // Only the unpublished candidate changes. Lease timing begins just
        // before map population/activation, conservatively before confirmation.
        for (const auto &key : writer_keys) {
            file_policy_value value{};
            if (bpf_map_lookup_elem(policy_map.get(), &key, &value))
                throw std::runtime_error("Cannot inspect leased writer");
            value.writer_deadline_boot_ns = deadline;
            if (bpf_map_update_elem(policy_map.get(), &key, &value, BPF_EXIST))
                throw std::runtime_error("Cannot prepare leased writer");
        }
    }
    const unsigned int slot = 0;
    // 外层 Map update 的 value 是内层 Map FD；内核保存对象引用，成功后可关闭宿主的这个管理 FD。
    // 注意三种不同结果：用户态更新外层传 FD，用户态查询外层得到 Map ID，BPF 查询外层得到 Map 指针。
    const int candidate_fd = policy_map.get();
    if (bpf_map_update_elem(map_fd, &slot, &candidate_fd, BPF_ANY))
        throw std::runtime_error("Cannot activate candidate policy map");
    // 提交后交换固定文件集合；candidate 析构释放旧集合，活动对象持有新集合，失败则不会走到此处。
    descriptors_.swap(candidate.descriptors_);
}
