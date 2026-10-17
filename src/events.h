// SPDX-License-Identifier: MIT
#pragma once
#include <cstddef>

// libbpf ring buffer callback; validates the shared ABI before rendering JSONL.
int consume(void *context, void *data, std::size_t size);
void report_stats(int map_fd);
