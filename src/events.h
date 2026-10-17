// SPDX-License-Identifier: MIT
// ring buffer 消费和统计输出接口；BPF 事件只是定长二进制记录，在本模块转为 JSON Lines。
#pragma once
#include <cstddef>

// libbpf ring buffer callback; validates the shared ABI before rendering JSONL.
int consume(void *context, void *data, std::size_t size);
void report_stats(int map_fd);
