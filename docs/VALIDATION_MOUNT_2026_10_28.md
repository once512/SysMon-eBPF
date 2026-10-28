# 挂载归属定向验收（2026-10-28）

开发机内核6.12.0-211.67.1.el10_2.x86_64，普通构建35项CTest通过。新增纯拓扑检查与真实FUSE六种情形通过：直接覆盖、祖先覆盖、父目录移动、detach后同路径复用、提供进程暂停，以及移除覆盖后回到原挂载。替代挂载及内容在旧服务停止后保留，原位正常挂载仍可正常退出。

最后相关特权入口为virtual-mount-identity、virtual-rebind、management-faults、permission-namespace及其pidfd模式，全部通过。既有virtual-managed还单独验证真实视图正常/分析/64文件、错误回退、进度、死亡、启动失败及保留独立BPF策略。未重跑全项目特权名单，没有增加soak。

原始产物在/tmp/secmon-development-20261028：ctest-mount.log、mount-privileged-final.log，以及开发过程的说明文件。首次moved夹具试图直接rename挂载点，内核返回EBUSY，改为rename父目录。首次汇总验收同时发生重链接，管理客户端exec返回EACCES；该轮无效，最终在稳定构建下重跑通过。该失败不能写成内核策略缺陷或忽略不记。

另以独立临时tmpfs确认umount的proc-FD路径及cwd路径仍会跟随覆盖挂载，move_mount实验因源父挂载shared返回EINVAL；这些实验不构成精确FD卸载实现。本项保留root管理员串行管理假设，详见[MOUNT_IDENTITY.md](MOUNT_IDENTITY.md)。

后续路径信任修正：原生38项CTest通过；virtual-mount-identity额外验证root拒绝非root所有/可写祖先，以及暂停FUSE祖先时不进入后续lookup。原有六种挂载情形继续通过，日志mount-trust-native.log。内核唯一ID仍存在而proc采样缺少条目时改报unknown/ESTALE，不把不一致快照直接认定为detach。最终跨构建验收见本轮汇总。
