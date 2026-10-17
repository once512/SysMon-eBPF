// SPDX-License-Identifier: MIT
// 只在此测试目标包装系统调用/分配：可控地产生 I/O 错误、前后元数据变化和扫描缓冲分配失败。
#include "analysis/scanner.h"
#include "owned_fd.h"
#include <cerrno>
#include <cstdlib>
#include <fcntl.h>
#include <iostream>
#include <new>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>

namespace {
enum class Fault { none, first_stat, last_stat, read, changed };
Fault fault = Fault::none;
int stat_calls = 0;
bool fail_allocation = false;
void require(bool value) { if (!value) throw std::runtime_error("Scan error assertion"); }
}
void *operator new(std::size_t size)
{
    if (fail_allocation) { fail_allocation = false; throw std::bad_alloc(); }
    if (auto *memory = std::malloc(size ? size : 1)) return memory;
    throw std::bad_alloc();
}
void operator delete(void *memory) noexcept { std::free(memory); }
void operator delete(void *memory, std::size_t) noexcept { std::free(memory); }
extern "C" int __real_fstat(int, struct stat *);
extern "C" ssize_t __real_pread(int, void *, size_t, off_t);
extern "C" int __wrap_fstat(int fd, struct stat *st)
{
    ++stat_calls;
    if ((fault == Fault::first_stat && stat_calls == 1) || (fault == Fault::last_stat && stat_calls == 2)) {
        errno = EIO;
        return -1;
    }
    const int result = __real_fstat(fd, st);
    if (!result && fault == Fault::changed && stat_calls == 2) ++st->st_mtim.tv_nsec;
    return result;
}
extern "C" ssize_t __wrap_pread(int fd, void *bytes, size_t size, off_t offset)
{
    if (fault == Fault::read) { errno = EIO; return -1; }
    return __real_pread(fd, bytes, size, offset);
}
int main()
{
    char path[] = "/tmp/secmon-scan-errors-XXXXXX";
    OwnedFd writer(mkstemp(path));
    require(writer.get() >= 0);
    require(write(writer.get(), "clean", 5) == 5);
    OwnedFd reader(open(path, O_RDONLY | O_CLOEXEC));
    unlink(path);
    for (const auto mode : {Fault::first_stat, Fault::last_stat, Fault::read, Fault::changed}) {
        fault = mode;
        stat_calls = 0;
        const auto reply = analysis::scan(reader.get(), 42, "BLOCK", 64);
        require(reply.result == analysis::Result::error && reply.id == 42);
        const auto expected = mode == Fault::read ? analysis::ScanError::read_failed :
            (mode == Fault::changed ? analysis::ScanError::changed : analysis::ScanError::metadata_failed);
        require(reply.error == expected && reply.system_errno == (mode == Fault::changed ? 0 : EIO));
    }
    fault = Fault::none;
    require(ftruncate(writer.get(), 4096) == 0);
    fail_allocation = true;
    const auto resource = analysis::scan(reader.get(), 44, "BLOCK", 8192);
    fail_allocation = false;
    require(resource.result == analysis::Result::error && resource.error == analysis::ScanError::resource_exhausted &&
            resource.system_errno == ENOMEM && resource.id == 44);
    const auto bad = analysis::scan(-1, 45, "BLOCK", 64);
    require(bad.error == analysis::ScanError::bad_descriptor && bad.system_errno == EBADF);
    std::cout << "PASS structured metadata/read/change/resource scan errors without production fault hooks\n";
}
