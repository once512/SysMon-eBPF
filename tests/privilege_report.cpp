// SPDX-License-Identifier: MIT
// Read this test process's credentials; compare with BPF without changing them.
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <linux/capability.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

int main()
{
    __user_cap_header_struct header{};
    __user_cap_data_struct data[2]{};
    header.version = _LINUX_CAPABILITY_VERSION_3;
    if (syscall(SYS_capget, &header, data)) { std::perror("capget"); return 1; }
    const auto caps = (static_cast<unsigned long long>(data[1].effective) << 32) | data[0].effective;
    const auto permitted = (static_cast<unsigned long long>(data[1].permitted) << 32) | data[0].permitted;
    const auto inheritable = (static_cast<unsigned long long>(data[1].inheritable) << 32) | data[0].inheritable;
    unsigned uid = 0, euid = 0, suid = 0, fsuid = 0;
    unsigned gid = 0, egid = 0, sgid = 0, fsgid = 0;
    unsigned long long bounding = 0, ambient = 0;
    bool have_uid = false, have_gid = false, have_bnd = false, have_amb = false;
    std::ifstream status("/proc/self/status");
    std::string line;
    while (std::getline(status, line)) {
        std::istringstream values(line);
        std::string field;
        values >> field;
        if (field == "Uid:") have_uid = bool(values >> uid >> euid >> suid >> fsuid);
        else if (field == "Gid:") have_gid = bool(values >> gid >> egid >> sgid >> fsgid);
        else if (field == "CapBnd:") have_bnd = bool(values >> std::hex >> bounding);
        else if (field == "CapAmb:") have_amb = bool(values >> std::hex >> ambient);
    }
    struct stat ns{};
    if (!have_uid || !have_gid || !have_bnd || !have_amb || stat("/proc/self/ns/user", &ns)) {
        std::fprintf(stderr, "Cannot inspect complete test credentials\n");
        return 1;
    }
    std::printf("{\"pid\":%d,\"uid\":%u,\"euid\":%u,\"suid\":%u,\"fsuid\":%u,"
                "\"gid\":%u,\"egid\":%u,\"sgid\":%u,\"fsgid\":%u,\"caps\":%llu,"
                "\"caps_permitted\":%llu,\"caps_inheritable\":%llu,\"caps_bounding\":%llu,"
                "\"caps_ambient\":%llu,\"user_namespace_inode\":%llu}\n",
                getpid(), uid, euid, suid, fsuid, gid, egid, sgid, fsgid, caps,
                permitted, inheritable, bounding, ambient, static_cast<unsigned long long>(ns.st_ino));
    return 0;
}
