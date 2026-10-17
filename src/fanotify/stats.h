// SPDX-License-Identifier: MIT
// 累计裁决统计统一出口；原因计数是 analyzer_error 的拆分，不能与 allowed/denied 再相加。
#pragma once
#include "gate_stats.h"
#include "event_kind.h"
#include <ostream>
void write_gate_stats(std::ostream &output, PermissionEvent event, const GateStats &stats);
