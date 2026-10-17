// SPDX-License-Identifier: MIT
// 纯快照测试：不把单次相等误当事务，明确版本/摘要分歧、采样变化和预期版本失败。
#include "management/consistency.h"
#include <iostream>
#include <stdexcept>
using namespace management;
void require(bool value) { if (!value) throw std::runtime_error("Consistency assertion"); }
int main()
{
    Reply b, f;
    b.pid = 123; b.instance_ns = 11; b.flags = configured; b.revision = 7; b.source_digest = content_digest("policy");
    f = b; f.backend = Backend::fanotify; f.pid = 124; f.instance_ns = 12;
    require(check_consistency(b, f, b, f) == Consistency::consistent);
    require(check_consistency(b, f, b, f, 8) == Consistency::unexpected_revision);
    auto changed = f; ++changed.revision;
    require(check_consistency(b, changed, b, changed) == Consistency::revision_mismatch);
    changed = f; changed.source_digest = content_digest("other");
    require(check_consistency(b, changed, b, changed) == Consistency::source_mismatch);
    for (int field = 0; field < 5; ++field) {
        auto after = b;
        if (field == 0) ++after.revision;
        if (field == 1) ++after.reloads;
        if (field == 2) ++after.pid;
        if (field == 3) ++after.instance_ns;
        if (field == 4) after.source_digest = content_digest("new");
        require(check_consistency(b, f, after, f) == Consistency::unstable);
    }
    auto unconfigured = f; unconfigured.flags = 0;
    require(check_consistency(b, unconfigured, b, unconfigured) == Consistency::unconfigured);
    require(check_consistency(b, b, b, b) == Consistency::wrong_backend);
    auto rejected = f; rejected.code = Code::internal_error;
    require(check_consistency(b, rejected, b, rejected) == Consistency::query_failed);
    auto after = b; ++after.rejections; after.last_code = Code::not_newer;
    require(check_consistency(b, f, after, f) == Consistency::consistent);
    require(consistency_json(Consistency::consistent, b, f).find("active_configuration_bytes") != std::string::npos);
    std::cout << "PASS double-collection active-source consistency without transaction claims\n";
}
