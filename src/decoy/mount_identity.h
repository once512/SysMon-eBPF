// SPDX-License-Identifier: MIT
#pragma once
#include <cstdint>
#include <istream>
#include <string>
namespace decoy {
enum class MountState : std::uint32_t { none, attached, covered, moved, detached, unknown };
struct MountSnapshot { MountState state = MountState::unknown; int error = 0; };
// Linux's non-reusable mount ID; no FUSE getattr is needed for an O_PATH root.
std::uint64_t unique_mount_id(int fd);
// Kernel superblock type, without asking a userspace filesystem for statfs.
bool fuse_mount(int fd);
// Inspect kernel mount topology, never resolve the managed pathname through VFS.
MountSnapshot inspect_mount(std::uint64_t unique_id, const std::string &path) noexcept;
// Pure topology evaluator, shared with tests. The supplied ID is the old ID
// returned by statmount for the exact non-reusable ID, not a cached numeric ID.
MountSnapshot inspect_mountinfo(std::istream &input, std::uint32_t id, const std::string &path);
}
