// SPDX-License-Identifier: MIT
#include "vault/policy_edit.h"
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <functional>
using vault::Action;
const std::string boot = "11111111-1111-4111-8111-111111111111";
const std::string original = "# deployment comment\n revision 7\nvault \"/vault one\"\nprotect \"/guard\"\n\n# keep final bytes";
void require(bool test) { if (!test) throw std::runtime_error("Vault editing assertion failed"); }
void reject(const std::function<void()> &action)
{ try { action(); } catch (const std::runtime_error &) { return; } throw std::runtime_error("Unsafe candidate accepted"); }
int main()
{
    try {
        vault::Edit open{Action::open}; open.id=1; open.program="/usr/bin/client"; open.target="/vault one";
        open.mode="read"; open.uid=1000; open.duration_ms=1000;
        const auto first = vault::edit_policy(original,open,boot,1000000000);
        require(first.changed && first.policy.revision==8 && first.session_id==1 && first.deadline==2000000000);
        require(first.text.find("# deployment comment\nrevision 8\n") == 0);
        require(first.text.find("protect \"/guard\"\n\n# keep final bytes\n") != std::string::npos);
        require(first.policy.source_digest == content_digest(first.text));
        reject([&]{vault::edit_policy(first.text,open,boot,1000000001);});
        open.id=2;open.mode="read-write";
        const auto second = vault::edit_policy(first.text,open,boot,1200000000);
        require(second.policy.vault_sessions[0].issued_boot_ns==1000000000 && second.policy.vault_sessions[0].duration_ms==1000);
        require(second.policy.vault_sessions[1].access==3 && second.deadline==2200000000);
        vault::Edit close{Action::close};close.id=1;
        const auto closed=vault::edit_policy(second.text,close,boot,1300000000);
        require(closed.removed==1 && closed.policy.vault_sessions.size()==1 && closed.policy.vault_sessions[0].id==2);
        reject([&]{vault::edit_policy(closed.text,close,boot,1300000001);});
        vault::Edit lock{Action::lock};lock.target="/vault one";
        const auto locked=vault::edit_policy(second.text,lock,boot,1300000000);
        require(locked.removed==2 && locked.policy.vault_sessions.empty() && locked.policy.vaults.size()==1);
        const std::string aliases=second.text+"vault \"/alias\"\nvault \"/separate\"\n";
        auto alias_open=open;alias_open.id=3;alias_open.target="/alias";
        const auto alias_candidate=vault::edit_policy(aliases,alias_open,boot,1300000000);
        alias_open.id=4;alias_open.target="/separate";
        const auto separate=vault::edit_policy(alias_candidate.text,alias_open,boot,1400000000);
        lock.alias_targets={"/alias"};
        const auto alias_locked=vault::edit_policy(separate.text,lock,boot,1500000000);
        require(alias_locked.removed==3 && alias_locked.policy.vault_sessions.size()==1 && alias_locked.policy.vault_sessions[0].target=="/separate");
        lock.alias_targets.clear();
        const auto noop=vault::edit_policy(locked.text,lock,boot,1300000001);
        require(!noop.changed && noop.text==locked.text && noop.policy.revision==locked.policy.revision);
        lock.target="/not-a-vault";reject([&]{vault::edit_policy(second.text,lock,boot,1);});
        open.target="/not-a-vault";reject([&]{vault::edit_policy(second.text,open,boot,1);});open.target="/vault one";
        reject([&]{vault::edit_policy(original,open,"bad-boot",1);});
        reject([&]{vault::edit_policy(original,open,boot,UINT64_MAX);});
        reject([&]{vault::edit_policy("revision 18446744073709551615\nvault \"/vault one\"\n",open,boot,1);});
        const auto maintenance=original+"\nallow-writer \"/usr/bin/maint\" 0 \"/guard\" all\nwriter-lease-ms 1000\n";
        std::istringstream valid_maintenance(maintenance);
        require(parse_policy(valid_maintenance).writer_lease_ms==1000);
        reject([&]{vault::edit_policy(maintenance,open,boot,1);});
        std::cout<<"PASS vault editing: scoped open/close/lock, unchanged deadlines, preserved bytes, no-op, limits and relative-lease refusal\n";
    } catch(const std::exception &e){std::cerr<<e.what()<<'\n';return 1;}
}
