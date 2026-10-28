// SPDX-License-Identifier: MIT
#include "decoy/mount_identity.h"
#include "owned_fd.h"
#include <cerrno>
#include <fcntl.h>
#include <iostream>
#include <sstream>
#include <stdexcept>
using decoy::MountState;
const std::string root = "1 99 8:1 / / rw shared:1 - ext4 /dev/test rw\n";
std::string entry(unsigned id, unsigned parent, const std::string &point)
{ return std::to_string(id) + " " + std::to_string(parent) + " 0:42 / " + point + " rw - fuse.secmon-decoy secmon-decoy rw\n"; }
void verify(const std::string &table, unsigned id, const std::string &path, MountState expected)
{
    std::istringstream input(table);
    const auto got = decoy::inspect_mountinfo(input, id, path);
    if (got.state != expected || (expected != MountState::unknown && got.error))
        throw std::runtime_error("Wrong mount topology classification");
}
int main()
{
    try {
        verify(root + entry(2,1,"/view"), 2,"/view",MountState::attached);
        verify(root + entry(2,1,"/view") + entry(3,2,"/view"),2,"/view",MountState::covered);
        verify(root + entry(2,1,"/a/view") + entry(3,1,"/a"),2,"/a/view",MountState::covered);
        verify(root + entry(2,1,"/a/view") + entry(3,1,"/a") + entry(4,3,"/a/view"),4,"/a/view",MountState::attached);
        verify(root + entry(2,1,"/a/view") + entry(3,1,"/a") + entry(4,3,"/a/view"),2,"/a/view",MountState::covered);
        verify(root + entry(2,1,"/view") + entry(3,2,"/view/child"),2,"/view",MountState::attached);
        verify(root + entry(2,1,"/a/view") + entry(3,1,"/ab"),2,"/a/view",MountState::attached);
        verify(root + entry(2,1,"/renamed"),2,"/view",MountState::moved);
        verify(root + entry(3,1,"/view"),2,"/view",MountState::detached);
        verify(root + entry(2,1,"/space\\040name"),2,"/space name",MountState::attached);
        verify(root + entry(2,1,"/line\\012tab\\011slash\\134"),2,"/line\ntab\tslash\\",MountState::attached);
        verify(root + entry(2,1,"/bad\\999"),2,"/view",MountState::unknown);
        verify(root + entry(2,1,"/view") + entry(2,1,"/view"),2,"/view",MountState::unknown);
        verify(root + entry(2,1,"/view") + entry(3,1,"/view"),2,"/view",MountState::unknown);
        verify(root + "malformed\n",2,"/view",MountState::unknown);
        verify(root + entry(2,2,"/view"),2,"/view",MountState::covered);
        verify(std::string(1024*1024+1,'x'),2,"/view",MountState::unknown);
        OwnedFd fd(open("/", O_PATH | O_CLOEXEC));
        if (fd.get() < 0 || !decoy::unique_mount_id(fd.get())) throw std::runtime_error("Missing unique root mount ID");
        if (decoy::inspect_mount(0,"/view").error != ENODATA) throw std::runtime_error("Unattested mount accepted");
        std::cout << "PASS mount topology: original, covered, hidden ancestor, moved, detached, escaped, bounded, malformed\n";
    } catch (const std::exception &e) { std::cerr << e.what() << '\n'; return 1; }
}
