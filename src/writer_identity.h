// SPDX-License-Identifier: MIT
// 授权对象的用户态固定：只校验被选中的文件对象，路径本身不构成持续身份。
#pragma once
#include "owned_fd.h"
#include "secmon.h"
#include <string>
struct PinnedPolicyFile {
    OwnedFd fd;
    file_key key;
};
PinnedPolicyFile pin_policy_file(const std::string &path, bool writer);
