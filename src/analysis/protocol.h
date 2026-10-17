// SPDX-License-Identifier: MIT
#pragma once
#include <cstdint>

// Local-only, fixed-width protocol. No pointers, paths, or task authorization.
namespace analysis {
constexpr std::uint32_t magic = 0x53434d41;
constexpr std::uint16_t version = 2;
struct Request {
    std::uint32_t magic_value = magic;
    std::uint16_t abi = version;
    std::uint16_t size = sizeof(Request);
    std::uint64_t id = 0;
};
enum class Result : std::uint32_t { allow = 1, deny = 2, error = 3, ready = 4 };
struct Response {
    std::uint32_t magic_value = magic;
    std::uint16_t abi = version;
    std::uint16_t size = sizeof(Response);
    std::uint64_t id = 0;
    Result result = Result::error;
    std::uint32_t bytes_scanned = 0;
};
static_assert(sizeof(Request) == 16 && sizeof(Response) == 24);
}
