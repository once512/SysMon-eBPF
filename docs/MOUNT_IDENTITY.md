# 虚拟诱饵挂载归属（2026-10-28）

主服务现在把“提供进程最近回答探测”和“原挂载仍在预期路径可见”分开。前者继续使用已有提供进程监督，后者根据内核挂载拓扑采样；不会向FUSE执行getattr，也不读取诱饵内容。

提供程序挂载后以O_PATH固定根，并使用STATX_MNT_ID_UNIQUE取得不复用的64位挂载ID，再在FUSE初始化后的Ready中报告。提供协议升级为同包v2/32字节；probe/progress不得携带挂载ID。主服务以statmount查询这个精确ID，再解析有界的/proc/self/mountinfo。读取后再次核对精确ID，防止旧数字ID在采样期间回收复用。提供程序属于root显式选择的可信组件；这不是对任意提供程序或与特权管理员竞争挂载的认证。

## 状态与就绪

管理协议升级为同包v11/528字节，主服务与管理客户端须一起更新：

| 字段 | 含义 |
| --- | --- |
| decoy_mount_id | Ready报告的不复用ID；未托管为0，缺少归属报告也为0 |
| decoy_mount_state | none、attached、covered、moved、detached或unknown |
| decoy_mount_errno | unknown的正errno；其他状态为0 |
| decoy_mount_sample_age_ms | 最近一次拓扑采样距今毫秒数，不是FUSE响应时间 |

attached表示原挂载仍在配置路径的可见挂载链上；covered包括同路径覆盖和更高层目录被覆盖；moved表示原挂载仍在当前namespace但路径已变；detached表示精确ID已不在当前namespace；unknown表示缺少报告、权限/系统调用失败、格式异常、容量超过预算或拓扑不明确。detach后通过旧引用仍可能存在的对象，不会被当作当前namespace中的挂载。

约每250ms采样一次，提供进程offline后仍继续观察。单次proc内容最多1MiB、8192项；超过预算报告unknown，不无限扩容。采样直接查询内核挂载信息，没有对业务路径的新鲜VFS查询；不能据此声称全部内核系统调用有硬期限，也不提供跨两次内核查询的原子拓扑快照。

`secmon-policyctl --require-ready/--require-decoy`在既有后端进度检查后，额外要求attached且采样年龄小于两秒，否则code=decoy_mount_unavailable。默认不带上述选项的策略检查保持原合同。提供程序无响应、离线和挂载不可用有独立原因；挂载仍attached不代表提供程序健康，也不证明所有发布文件都已配置canary或fanotify。

## 退出和恢复边界

提供程序正常退出前也核对精确ID与拓扑。只对仍在原位的挂载调用原有libfuse卸载；覆盖、移动、脱离或未知时，关闭自己的FUSE设备并留下挂载供管理员核对。不会仅因路径相同就主动卸载替代挂载。

这补齐已存在覆盖/移动的退出检查，不是与并发CAP_SYS_ADMIN挂载操作竞争的原子卸载接口。检查与libfuse的路径卸载之间仍有时间窗口；部署时应由同一管理员串行管理这个挂载位置。内核6.12的umount路径即使用/proc/self/fd/N或切换cwd，也仍可能跟随后来覆盖的挂载；本实现不把这两种写法当作精确FD卸载。

异常死亡、强制停止、被移动/覆盖或归属未知时仍可能残留断开的FUSE挂载。主服务不会自动lazy detach、重启或接管新提供程序，不解除BPF策略，也不把挂载状态直接变成策略授权。显式fanotify重绑定合同继续见[FANOTIFY_REBIND.md](FANOTIFY_REBIND.md)。

下一阶段受控恢复仍需保证新提供程序、新inode与策略引用共同就绪，并维持拒绝门和未交付请求的既有边界。当前归属采样是恢复所需证据，没有完成自动恢复事务。

## 验证入口与实现依据

无特权mount-identity覆盖拓扑、祖先遮蔽、边界分隔、转义、重复/畸形和容量拒绝；virtual-mount-identity在真实FUSE上覆盖直接/上层覆盖、父目录移动、detach后路径复用、暂停及移除覆盖后恢复。停止后核对替代挂载和内容保留。

实现依据：[Linux 6.12 namespace.c](https://raw.githubusercontent.com/torvalds/linux/v6.12/fs/namespace.c)中的statmount/ksys_umount，以及[libfuse 3.16.2 mount.c](https://raw.githubusercontent.com/libfuse/libfuse/fuse-3.16.2/lib/mount.c)的路径卸载行为。本轮开发还以独立临时tmpfs复现了FD路径和cwd并不阻止跟随覆盖挂载；实验脚本只在/tmp验收目录，未修改真实系统挂载配置。


## 挂载路径信任补充（2026-10-28）

特权提供程序现在要求挂载点所有祖先为root所有、不可由组/其他用户写入；root所有的sticky共享祖先（例如/tmp）可用，但下一层仍须归root所有。普通用户独立运行时允许自己的安全祖先目录。符号链接与非规范分量拒绝。仅检查最终目录所有权不足以防止普通用户重命名其上层目录；root模式不再接受位于普通用户可控制祖先下的挂载点。

root模式还通过内核statmount的superblock类型拒绝FUSE祖先，不把用户态文件系统报告的UID/模式当作路径信任证明。检查在realpath及后续分量解析之前逐层进行；已验证暂停FUSE祖先时快速拒绝，不进入它的后续lookup。标准root所有/tmp临时子目录及/run部署继续工作。该约束只影响提供程序的挂载位置，不禁止原有BPF/fanotify监控FUSE目标。

这收敛了非特权祖先替换风险；并发CAP_SYS_ADMIN挂载/卸载的原子性限制仍保留。检查结果与挂载可见性都不能替代同一管理员串行管理的合同。
