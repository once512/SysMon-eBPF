# 本轮最终定向验收（2026-10-28）

应用/构建源码冻结点为bc19e33；之后仅补充文档与显式安装验证脚本，没有改动src/include/eBPF/CMake/packaging。内核为6.12.0-211.67.1.el10_2.x86_64。原始产物统一放在/tmp/secmon-development-20261028，下一次清理/tmp或重启后可能不再保留；本页记录结论与边界，不把临时日志当作持久部署。

## 构建与定向范围

| 产物 | 结果 |
| --- | --- |
| 普通build | 38/38 CTest通过 |
| 新建Release | 38/38 CTest通过 |
| 新建Release、关闭FUSE组件 | 37/37 CTest通过 |
| 普通相关特权回归 | 13个专题/模式通过 |
| Release新增能力定向回归 | 9个专题通过 |
| 完整/核心暂存安装 | 6/5个运行程序，全部在/工作目录执行help通过；没有安装测试库或静态库 |
| 暂存完整布局运行 | /工作目录下真实托管FUSE、降权分析、canary响应、独立文件保护、READY/STOPPING、正常停止卸载通过 |
| 暂存核心布局运行 | 真实Vim原地保存、运行中锁定/重新授权及inode不变通过 |

普通相关名单为reader-health、reader-recovery、analysis-faults、virtual-reader、virtual-analysis-reader、vaultctl、vaultctl-faults、fanotify-policy、fanotify-rebind、management-live、management-faults、permission-namespace及其pidfd模式。读取者离线期间关闭vault另有独立普通验证。

Release名单为reader-recovery、virtual-managed、virtual-service-notify、virtual-mount-identity、vaultctl、vault-editor、vaultctl-faults、vault-file-faults、management-faults。reader-recovery当前包含legacy/pidfd十类门/组合场景、拒绝写回EIO和独立vault关闭；不是重复同一条操作累计次数。

没有跑本项目旧完整特权名单，没有增加持续soak、几十万次重复或吞吐基准。此次结果不能替代真实开机、断电、安装升级及全部文件系统/应用兼容验收。

## 辅助检查

Clang分别检查vault三文件、gate/event_reader/monitor、mount_identity、decoy/main及service_notify，最终无诊断。首次读取者分析命令漏了eBPF include路径，未当作通过；补齐路径后结果另存。systemd-analyze verify使用暂存可执行路径核对生成单元语法通过；没有把单元安装到systemd目录、daemon-reload或启用服务。主程序不链接libfuse/libsystemd。

final-metadata.json保存BTF身份、应用源码与三套主要程序SHA-256、普通/Release专题名单及状态；暂存程序与对应Release/Core构建逐一哈希相同。后续文档提交不会据此冒充重新构建了同一应用源码。

主要日志：native-final-ctest.log、release-final-ctest.log、core-final-ctest.log、reader-focused-native.log、release-focused-final.log、install-verification.log、installed-runtime.log、installed-core-vault-editor.log。安装验证脚本为tests/installed_runtime.py，只有显式传入实际安装前缀才运行，不加入默认build目录回归。

## 开发失败与未修复发现

- 最初移动测试直接rename挂载点得到EBUSY，改为移动祖先目录。最初一次定向测试与重链接重叠，客户端exec失败，该轮无效；后续均使用稳定产物。
- 通知夹具尝试读取受保护辅助进程environ得到EACCES，没有放开自保护，改用实际消息凭证及无特权环境移除检查。背压夹具最初填满了另一个发送者的缓冲，修正为同一发送者。
- 旧group释放allow并不保证同一在途syscall成功：新deny group仍可能截获它，已修正新恢复夹具，不修改功能迎合错误假设。
- 静态分析指出锁文件RAII赋值可能遮蔽errno的分析路径，改为局部句柄核对后转交。安装验证脚本首次在错误工作目录创建失败，未启动应用；随后已修正并正常完成。
- 已实际复现UID65534通过系统fusermount3覆盖allow-other视图。这是未修复的挂载干扰缺口，不是通过项。测试只创建和清理自己的额外挂载，未更改系统配置，见[MOUNT_IDENTITY.md](MOUNT_IDENTITY.md)。
- 读取者资源限制故障证明当前自保护没有覆盖外部root的资源限制变更；新离线隔离保留保护，但未修复该干扰入口。

最终检查未遗留本轮secmon/提供进程或测试FUSE挂载。未关机、重启、push、安装系统服务或改变真实系统挂载配置。当前目标与优先级见[状态表](STATUS_2026_10_28.md)，具体合同分别见挂载归属、保险箱管理、服务通知和读取者恢复文档。
