// SPDX-License-Identifier: MIT
#include "service_notify.h"
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdlib>
#include <chrono>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
void require_impl(bool test,int line){if(!test)throw std::runtime_error("Notification assertion failed at line "+std::to_string(line));}
#define require(test) require_impl((test),__LINE__)
void verify(bool abstract)
{
    const std::string name=std::string(abstract?"@":"/tmp/")+"secmon-notify-unit-"+std::to_string(getpid());
    OwnedFd receiver(socket(AF_UNIX,SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0));require(receiver.get()>=0);
    sockaddr_un address{};address.sun_family=AF_UNIX;std::memcpy(address.sun_path,name.data(),name.size());
    if(abstract)address.sun_path[0]='\0';
    const auto size=offsetof(sockaddr_un,sun_path)+name.size()+(abstract?0:1);
    require(!bind(receiver.get(),reinterpret_cast<sockaddr*>(&address),size));
    try {
        require(!setenv("NOTIFY_SOCKET",name.c_str(),1));
        ServiceNotify notify;require(!getenv("NOTIFY_SOCKET"));
        notify.ready();std::array<char,256> data{};
        auto count=recv(receiver.get(),data.data(),data.size(),0);require(count>0);
        require(std::string(data.data(),count)=="READY=1\nSTATUS=SecMon policy and control initialized\n");
        require(notify.stopping());count=recv(receiver.get(),data.data(),data.size(),0);require(count>0);
        require(std::string(data.data(),count).find("STOPPING=1\n")==0);
        // Saturate the receiver without consuming datagrams: notifications must
        // fail immediately rather than wait for a manager to make space.
        unsigned filled=0;
        while(notify.stopping()) require(++filled<65536);
        const auto started=std::chrono::steady_clock::now();
        require(!notify.stopping());
        require(std::chrono::steady_clock::now()-started<std::chrono::milliseconds(100));
        // Closing the manager endpoint cannot block a stopping service.
        receiver=OwnedFd();require(!notify.stopping());
    } catch (...) {if(!abstract)unlink(name.c_str());throw;}
    if(!abstract)unlink(name.c_str());
}
int main()
{
    try {
        unsetenv("NOTIFY_SOCKET");ServiceNotify disabled;disabled.ready();require(disabled.stopping());
        setenv("NOTIFY_SOCKET","",1);ServiceNotify empty;require(!getenv("NOTIFY_SOCKET"));empty.ready();
        for(const auto &invalid:{std::string("relative"),std::string("@"),std::string(200,'x')}) {
            setenv("NOTIFY_SOCKET",invalid.c_str(),1);bool rejected=false;
            try{ServiceNotify wrong;}catch(const std::runtime_error&){rejected=true;}
            require(rejected && !getenv("NOTIFY_SOCKET"));
        }
        verify(false);verify(true);
        std::cout<<"PASS optional notifications: pathname/abstract, environment cleared, exact READY/STOPPING, unavailable manager and no-op\n";
    } catch(const std::exception &e){std::cerr<<e.what()<<'\n';return 1;}
}
