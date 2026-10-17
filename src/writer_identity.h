// SPDX-License-Identifier: MIT
// 授权对象的用户态固定：只校验被选中的文件对象，路径本身不构成持续身份。
#pragma once
#include "owned_fd.h"
#include "secmon.h"
#include <string>
// FD 维持对象寿命，key 供 Map 匹配；
// 只保存 key 而丢掉 FD 会失去防 inode 回收复用的前提。
struct PinnedPolicyFile {
    OwnedFd fd;
    file_key key;
};
PinnedPolicyFile pin_policy_file(const std::string &path, bool writer);
