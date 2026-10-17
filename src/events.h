// SPDX-License-Identifier: MIT
// ring buffer 消费和统计输出接口；BPF 事件只是定长二进制记录，在本模块转为 JSON Lines。
#pragma once
#include <cstddef>
#include <optional>
#include <string>

// libbpf ring buffer callback; validates the shared ABI before rendering JSONL.
std::optional<std::string> format_event(const void *data, std::size_t size);
int consume(void *context, void *data, std::size_t size) noexcept;
void report_stats(int map_fd);
