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

ProtectedFiles::~ProtectedFiles() { for (int fd : descriptors_) close(fd); }

void ProtectedFiles::install(int map_fd, const std::vector<std::string> &paths)
{
    descriptors_.reserve(paths.size());
    for (const auto &path : paths) {
        int fd = open(path.c_str(), O_PATH | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0) throw std::runtime_error("Cannot pin " + path + ": " + std::strerror(errno));
        descriptors_.push_back(fd);
        struct stat st{};
        if (fstat(fd, &st) || !S_ISREG(st.st_mode))
            throw std::runtime_error("Protection requires an existing regular file: " + path);
        file_key key{major(st.st_dev), minor(st.st_dev), st.st_ino};
        unsigned int policy = 1;
        if (bpf_map_update_elem(map_fd, &key, &policy, BPF_ANY))
            throw std::runtime_error("Cannot install policy for " + path + ": " + std::strerror(errno));
        std::cerr << "Protected inode " << key.major << ':' << key.minor << ':' << key.ino
                  << " path=" << path << '\n';
    }
}
