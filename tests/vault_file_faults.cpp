// SPDX-License-Identifier: MIT
// Force file fsync and directory fsync failures around the publication boundary.
#include "vault/policy_file.h"
#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <system_error>
#include <sys/stat.h>
#include <unistd.h>
namespace fs=std::filesystem;
namespace { int calls=0, fail_at=0; }
extern "C" int __real_fsync(int);
extern "C" int __wrap_fsync(int fd)
{
    if (++calls==fail_at) { errno=EIO; return -1; }
    return __real_fsync(fd);
}
std::string read(const fs::path &path)
{ std::ifstream input(path); return {std::istreambuf_iterator<char>(input),{}}; }
int main()
{
    if (geteuid()) { std::cerr<<"requires root\n"; return 2; }
    char pattern[]="/tmp/secmon-vault-file-XXXXXX";
    const auto *created=mkdtemp(pattern);
    if (!created) return 1;
    const fs::path root(created),path=root/"policy";
    try {
        const std::string original="revision 1\nvault \"/original\"\n", candidate="revision 2\nvault \"/candidate\"\n";
        { std::ofstream out(path);out<<original; } chmod(path.c_str(),0600);
        {
            vault::PolicyFile file(path,true);
            for (const int phase : {1,2}) {
                calls=0;fail_at=phase;
                bool rejected=false;
                try {file.replace(original,candidate);} catch(const std::system_error &e) {rejected=e.code().value()==EIO;}
                if (!rejected || read(path)!=(phase==1?original:candidate)) throw std::runtime_error("Wrong publication boundary after fsync failure");
                for(const auto &entry:fs::directory_iterator(root))
                    if(entry.path().filename().string().find(".secmon-vault-")==0)throw std::runtime_error("Leaked staging file");
                fail_at=0;
                if(phase==2)file.replace(candidate,original);
            }
            // Existing source changes are never silently overwritten.
            {std::ofstream out(path);out<<"foreign root edit\n";}
            bool conflict=false;try{file.replace(original,candidate);}catch(const std::runtime_error&){conflict=true;}
            if(!conflict || read(path)!="foreign root edit\n")throw std::runtime_error("Clobbered another source");
        }
        fs::remove_all(root);
        std::cout<<"PASS vault file faults: pre-rename fsync, post-rename directory fsync, conditional restore, staging cleanup and source conflict\n";
        return 0;
    } catch(const std::exception &e) {std::cerr<<e.what()<<'\n';fs::remove_all(root);return 1;}
}
