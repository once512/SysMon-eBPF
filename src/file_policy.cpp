// SPDX-License-Identifier: MIT
// 把路径转换为稳定的文件对象身份，并构建内核 HASH Map；O_PATH 固定对象但不取得读写访问 FD。
// 候选全部准备完成后只更新一次外层 Map；候选析构回收失败路径资源，不触碰活动策略。
#include <bpf/bpf.h>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <unistd.h>
#include <vector>
#include "secmon.h"

#include "file_policy.h"
#include "owned_fd.h"
#include "writer_identity.h"

ProtectedFiles::~ProtectedFiles() { for (int fd : descriptors_) close(fd); }

void ProtectedFiles::install(int map_fd, const PolicyConfig &config)
{
    const auto &paths = config.paths;
    if (config.writers.size() > 64) throw std::runtime_error("Too many authorized writers");
    if (paths.size() > 256) throw std::runtime_error("Too many protected paths");
    ProtectedFiles candidate;
    // 先分配保存 FD 的空间，再逐个 open；接管 FD 时不再触发 vector 扩容，减少异常路径泄漏风险。
    candidate.descriptors_.reserve(paths.size() + config.writers.size());
    // 这里创建的是内核 Map 对象，得到的是管理 FD；向 HASH 填充时尚未影响正在运行的钩子。
    OwnedFd policy_map(bpf_map_create(BPF_MAP_TYPE_HASH, "file_policy", sizeof(file_key),
                                     sizeof(file_policy_value), SECMON_POLICY_CAPACITY, nullptr));
    if (policy_map.get() < 0) throw std::runtime_error("Cannot create candidate policy map");
    for (const auto &path : paths) {
        auto pinned = pin_policy_file(path, false);
        candidate.descriptors_.push_back(pinned.fd.release());
        const auto key = pinned.key;
        file_policy_value policy{SECMON_FILE_READONLY, 0};
        if (bpf_map_update_elem(policy_map.get(), &key, &policy, BPF_ANY))
            throw std::runtime_error("Cannot install policy for " + path + ": " + std::strerror(errno));
        std::cerr << "Prepared policy inode " << key.major << ':' << key.minor << ':' << key.ino
                  << " path=" << path << '\n';
    }
    for (const auto &writer : config.writers) {
        auto pinned = pin_policy_file(writer.path, true);
        candidate.descriptors_.push_back(pinned.fd.release());
        file_policy_value value{};
        // 同一 inode 可同时是 protect 对象和 writer；别名重复且 UID 不同则拒绝整个候选。
        if (bpf_map_lookup_elem(policy_map.get(), &pinned.key, &value) && errno != ENOENT)
            throw std::runtime_error("Cannot inspect candidate writer identity");
        if ((value.flags & SECMON_FILE_WRITER) && value.writer_euid != writer.euid)
            throw std::runtime_error("Conflicting UIDs for one writer inode");
        value.flags |= SECMON_FILE_WRITER | SECMON_FILE_IDENTITY;
        value.writer_euid = writer.euid;
        if (bpf_map_update_elem(policy_map.get(), &pinned.key, &value, BPF_ANY))
            throw std::runtime_error("Cannot prepare writer identity");
        std::cerr << "Prepared writer inode " << pinned.key.major << ':' << pinned.key.minor
                  << ':' << pinned.key.ino << " euid=" << writer.euid << " path=" << writer.path << '\n';
    }
    const unsigned int slot = 0;
    // 外层 Map update 的 value 是内层 Map FD；内核保存对象引用，成功后可关闭宿主的这个管理 FD。
    const int candidate_fd = policy_map.get();
    if (bpf_map_update_elem(map_fd, &slot, &candidate_fd, BPF_ANY))
        throw std::runtime_error("Cannot activate candidate policy map");
    // 提交后交换固定文件集合；candidate 析构释放旧集合，活动对象持有新集合，失败则不会走到此处。
    descriptors_.swap(candidate.descriptors_);
}
