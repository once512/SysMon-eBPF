// SPDX-License-Identifier: MIT
#pragma once
#include <cstdint>
#include <stdexcept>
#include <string>
enum class ReaderFailure : std::uint32_t { none, disconnected, protocol, transport, resource };
inline const char *reader_failure_name(ReaderFailure value)
{
    constexpr const char *names[]={"none","disconnected","protocol","transport","resource"};
    return names[static_cast<unsigned>(value)]; // Validated enums only.
}
class ReaderError : public std::runtime_error {
    ReaderFailure failure_;
public:
    ReaderError(ReaderFailure failure,const std::string &message):std::runtime_error(message),failure_(failure){}
    ReaderFailure failure()const{return failure_;}
};
