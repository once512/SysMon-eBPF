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
#include <set>
#include <tuple>
#include <limits>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include "secmon.h"

#include "file_policy.h"
#include "owned_fd.h"
#include "writer_identity.h"
#include "boot_clock.h"


void ProtectedFiles::install(int map_fd, const PolicyConfig &config, const std::vector<int> &reader_targets)
{
    static_assert(sizeof(file_policy_value) == 408);
    static_assert(SECMON_MAX_WRITER_RULES <= 64, "Rule bitmap must fit uint64");
    const auto &paths = config.paths;
    if (config.writers.size() > SECMON_MAX_WRITER_RULES) throw std::runtime_error("Too many authorized writers");
    if (paths.size() > SECMON_MAX_PROTECTED_PATHS) throw std::runtime_error("Too many protected paths");
    // candidate 是未发布的事务资源集合；
    // 异常只销毁候选，当前对象仍持有活动策略的全部 inode。
    ProtectedFiles candidate;
    candidate.sessions_ = sessions_;
    candidate.last_response_epoch_ = last_response_epoch_;
    if (!config.canaries.empty() && !config.canary_response)
        throw std::runtime_error("Canary requires a response policy");
    if (config.canary_response) {
        const auto &r = *config.canary_response;
        if (!r.epoch || r.duration_ms < 100 || r.duration_ms > 3600000 ||
            (r.epoch <= last_response_epoch_ &&
             (r.epoch != active_response_epoch_ || r.duration_ms != response_duration_ms_)))
            throw std::runtime_error("Response epoch is retired, decreased, or changed; use a higher epoch");
        candidate.last_response_epoch_ = candidate.active_response_epoch_ = r.epoch;
        candidate.response_duration_ms_ = r.duration_ms;
    }
    for (auto &[id, record] : candidate.sessions_) { (void)id; record.active = false; }
    if (config.vault_sessions.size() > SECMON_MAX_VAULT_SESSIONS)
        throw std::runtime_error("Too many vault sessions");
    const std::set<std::string> vaults(config.vaults.begin(), config.vaults.end());
    const std::set<std::string> canaries(config.canaries.begin(), config.canaries.end());
    std::set<std::tuple<unsigned int, unsigned int, unsigned long long>> reader_keys;
    if (!vaults.empty()) for (const int fd : reader_targets) {
        struct stat value{};
        if (fstat(fd, &value)) throw std::runtime_error("Cannot inspect fanotify reader target");
        reader_keys.emplace(major(value.st_dev), minor(value.st_dev), value.st_ino);
    }
    const auto boot = config.vault_sessions.empty() ? std::string() : secmon_clock::boot_id();
    // 先分配保存 FD 的空间，再逐个 open；接管 FD 时不再触发 vector 扩容，减少异常路径泄漏风险。
    candidate.descriptors_.reserve(paths.size() + config.writers.size() + config.vault_sessions.size());
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
        // Merge aliases conservatively: a vault inode cannot become read-only
        // merely because another protect path names the same object.
        file_policy_value existing{};
        if (!bpf_map_lookup_elem(policy_map.get(), &key, &existing)) policy = existing;
        else if (errno != ENOENT) throw std::runtime_error("Cannot inspect candidate target");
        if (vaults.count(path)) policy.flags |= SECMON_FILE_VAULT;
        if ((policy.flags & SECMON_FILE_VAULT) && reader_keys.count({key.major, key.minor, key.ino}))
            throw std::runtime_error("Vault inode cannot be a fanotify target; listener requires read access");
        if (canaries.count(path)) policy.flags |= SECMON_FILE_CANARY;
        if ((policy.flags & SECMON_FILE_VAULT) && (policy.flags & SECMON_FILE_CANARY))
            throw std::runtime_error("Vault and canary cannot name the same inode");
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
        file_policy_value selected_value{};
        if (bpf_map_lookup_elem(policy_map.get(), &selected->second, &selected_value) ||
            (selected_value.flags & (SECMON_FILE_VAULT | SECMON_FILE_CANARY)))
            throw std::runtime_error("Writer grant cannot target a vault or canary inode (including aliases)");
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
        const auto deadline = secmon_clock::deadline_after(config.writer_lease_ms);
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
    for (std::size_t index = 0; index < config.vault_sessions.size(); ++index) {
        const auto &session = config.vault_sessions[index];
        // A configuration may survive reboot. A different boot's grant must
        // remain inert, without pinning a possibly absent old executable.
        if (session.boot_id != boot) { ++candidate.stale_sessions_; continue; }
        const auto selected = target_keys.find(session.target);
        if (!vaults.count(session.target) || selected == target_keys.end() ||
            (session.access != SECMON_VAULT_READ && session.access != (SECMON_VAULT_READ | SECMON_VAULT_WRITE)) ||
            session.duration_ms < 100 || session.duration_ms > 3600000 ||
            !secmon_clock::valid_boot_id(session.boot_id) || !session.issued_boot_ns ||
            session.issued_boot_ns > std::numeric_limits<std::uint64_t>::max() -
                static_cast<std::uint64_t>(session.duration_ms) * 1000000 ||
            session.issued_boot_ns > secmon_clock::global_boot_ns())
            throw std::runtime_error("Invalid vault session");
        auto pinned = pin_policy_file(session.program, true);
        candidate.descriptors_.push_back(std::move(pinned.fd));
        auto record = candidate.sessions_.find(session.id);
        std::uint64_t deadline;
        if (record != candidate.sessions_.end()) {
            const auto old = sessions_.find(session.id);
            const auto &saved = record->second;
            const auto &spec = saved.specification;
            const auto same_key = [](const file_key &a, const file_key &b) {
                return a.major == b.major && a.minor == b.minor && a.ino == b.ino;
            };
            if (old == sessions_.end() || !old->second.active ||
                std::tie(spec.program, spec.euid, spec.target, spec.access, spec.duration_ms, spec.boot_id, spec.issued_boot_ns) !=
                std::tie(session.program, session.euid, session.target, session.access, session.duration_ms, session.boot_id, session.issued_boot_ns) ||
                !same_key(saved.program, pinned.key) || !same_key(saved.target, selected->second))
                throw std::runtime_error("Vault session ID is retired or changed; use a new ID");
            deadline = saved.deadline; // unrelated reloads and reordering never renew.
            record->second.active = true;
        } else {
            if (!session.id || candidate.sessions_.size() == SECMON_MAX_VAULT_SESSION_HISTORY)
                throw std::runtime_error("Vault session history exhausted or invalid ID");
            deadline = session.issued_boot_ns + static_cast<std::uint64_t>(session.duration_ms) * 1000000;
            candidate.sessions_.emplace(session.id, SessionRecord{session, pinned.key, selected->second, deadline, true});
        }
        file_policy_value subject{};
        if (bpf_map_lookup_elem(policy_map.get(), &pinned.key, &subject) && errno != ENOENT)
            throw std::runtime_error("Cannot inspect vault subject");
        subject.flags |= SECMON_FILE_IDENTITY;
        subject.vault_subjects |= 1ULL << index;
        if (bpf_map_update_elem(policy_map.get(), &pinned.key, &subject, BPF_ANY))
            throw std::runtime_error("Cannot prepare vault subject");
        file_policy_value target{};
        if (bpf_map_lookup_elem(policy_map.get(), &selected->second, &target))
            throw std::runtime_error("Cannot inspect vault target");
        target.vault_sessions[index] = {deadline, session.euid, session.access};
        if (bpf_map_update_elem(policy_map.get(), &selected->second, &target, BPF_EXIST))
            throw std::runtime_error("Cannot prepare vault session");
        std::cerr << "Prepared vault session id=" << session.id << " deadline_boot_ns=" << deadline
                  << " access=" << session.access << " target=" << session.target << '\n';
    }
    if (config.canary_response) {
        const file_key key{SECMON_RESPONSE_KEY_MAJOR, 0, 0};
        file_policy_value value{};
        value.flags = SECMON_RESPONSE_CONFIG;
        value.response_epoch = candidate.active_response_epoch_;
        value.response_duration_ns = static_cast<std::uint64_t>(candidate.response_duration_ms_) * 1000000;
        if (bpf_map_update_elem(policy_map.get(), &key, &value, BPF_NOEXIST))
            throw std::runtime_error("Cannot prepare canary response configuration");
    }
    const unsigned int slot = 0;
    // 外层 Map update 的 value 是内层 Map FD；内核保存对象引用，成功后可关闭宿主的这个管理 FD。
    // 注意三种不同结果：用户态更新外层传 FD，用户态查询外层得到 Map ID，BPF 查询外层得到 Map 指针。
    const int candidate_fd = policy_map.get();
    if (bpf_map_update_elem(map_fd, &slot, &candidate_fd, BPF_ANY))
        throw std::runtime_error("Cannot activate candidate policy map");
    // 提交后交换固定文件集合；candidate 析构释放旧集合，活动对象持有新集合，失败则不会走到此处。
    descriptors_.swap(candidate.descriptors_);
    sessions_.swap(candidate.sessions_);
    std::swap(stale_sessions_, candidate.stale_sessions_);
    std::swap(last_response_epoch_, candidate.last_response_epoch_);
    std::swap(active_response_epoch_, candidate.active_response_epoch_);
    std::swap(response_duration_ms_, candidate.response_duration_ms_);
}

void ProtectedFiles::snapshot(management::Reply &reply) const
{
    reply.response_epoch = active_response_epoch_;
    reply.response_duration_ms = response_duration_ms_;
    reply.vault_session_history = sessions_.size();
    reply.vault_stale_sessions = stale_sessions_;
    reply.vault_sessions = stale_sessions_;
    reply.vault_live_sessions = 0;
    reply.vault_next_deadline_boot_ns = 0;
    std::uint64_t now = 0;
    // /proc access may have changed after installation. Unknown clock state
    // must not be rendered as a trustworthy live-session count.
    try { now = secmon_clock::deadline_after(0); reply.vault_clock_valid = 1; }
    catch (const std::exception &) { reply.vault_clock_valid = 0; }
    for (const auto &[id, record] : sessions_) {
        (void)id;
        if (!record.active) continue;
        ++reply.vault_sessions;
        if (reply.vault_clock_valid && now < record.deadline) ++reply.vault_live_sessions;
        if (!reply.vault_next_deadline_boot_ns || record.deadline < reply.vault_next_deadline_boot_ns)
            reply.vault_next_deadline_boot_ns = record.deadline;
    }
}
