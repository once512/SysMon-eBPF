// SPDX-License-Identifier: MIT
#include <bpf/bpf.h>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include <vector>
#include "secmon.h"

#include "file_policy.h"
#include "owned_fd.h"

ProtectedFiles::~ProtectedFiles() { for (int fd : descriptors_) close(fd); }

void ProtectedFiles::install(int map_fd, const std::vector<std::string> &paths)
{
    if (paths.size() > 256) throw std::runtime_error("Too many protected paths");
    ProtectedFiles candidate;
    candidate.descriptors_.reserve(paths.size());
    OwnedFd policy_map(bpf_map_create(BPF_MAP_TYPE_HASH, "file_policy", sizeof(file_key),
                                     sizeof(unsigned int), 256, nullptr));
    if (policy_map.get() < 0) throw std::runtime_error("Cannot create candidate policy map");
    for (const auto &path : paths) {
        int fd = open(path.c_str(), O_PATH | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0) throw std::runtime_error("Cannot pin " + path + ": " + std::strerror(errno));
        candidate.descriptors_.push_back(fd);
        struct stat st{};
        if (fstat(fd, &st) || !S_ISREG(st.st_mode))
            throw std::runtime_error("Protection requires an existing regular file: " + path);
        file_key key{major(st.st_dev), minor(st.st_dev), st.st_ino};
        unsigned int policy = 1;
        if (bpf_map_update_elem(policy_map.get(), &key, &policy, BPF_ANY))
            throw std::runtime_error("Cannot install policy for " + path + ": " + std::strerror(errno));
        std::cerr << "Prepared policy inode " << key.major << ':' << key.minor << ':' << key.ino
                  << " path=" << path << '\n';
    }
    const unsigned int slot = 0;
    const int candidate_fd = policy_map.get();
    if (bpf_map_update_elem(map_fd, &slot, &candidate_fd, BPF_ANY))
        throw std::runtime_error("Cannot activate candidate policy map");
    descriptors_.swap(candidate.descriptors_);
}
