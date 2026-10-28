// SPDX-License-Identifier: MIT
// Test-only interposer: fail actual FAN_DENY writes, not ordinary application I/O.
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <sys/fanotify.h>
#include <unistd.h>
extern "C" ssize_t write(int fd,const void *data,size_t size)
{
    using Write=ssize_t(*)(int,const void*,size_t);
    static const auto original=reinterpret_cast<Write>(dlsym(RTLD_NEXT,"write"));
    if(size==sizeof(fanotify_response)) {
        fanotify_response response{};std::memcpy(&response,data,sizeof(response));
        if(response.response==FAN_DENY) {
            char path[64],target[64]{};std::snprintf(path,sizeof(path),"/proc/self/fd/%d",fd);
            const auto count=readlink(path,target,sizeof(target));
            constexpr char expected[]="anon_inode:[fanotify]";
            if(count==sizeof(expected)-1 && !std::memcmp(target,expected,sizeof(expected)-1)) {errno=EIO;return -1;}
        }
    }
    if(!original){errno=EIO;return -1;}
    return original(fd,data,size);
}
