# 保险箱管理员增量验收（2026-10-28）

普通构建37项CTest通过；新增vault-policy-edit和vaultctl-cli，原有检查继续覆盖。最终原生特权四项vaultctl、vault-editor、vaultctl-faults、vault-file-faults通过。原始日志为/tmp/secmon-development-20261028/ctest-vault-final.log、vault-reviewed-native.log；未运行长负载或旧完整特权名单。

真实cat/dd验证完整8192字节读取、指定UID/程序、授权写入、关闭/期限、独立保护、期望版本及锁冲突，包含中文带空格目标名。实际硬链接上的会话随目标锁定被撤销，不同文件的会话保持有效。Vim profile验证原地保存、只读拒绝、保持编辑器运行时锁定及新签发后保存，inode不变，无profile备份/交换/持久撤销文件。该结果不等于所有编辑器或插件环境兼容。

协议故障区分明确拒绝、提交前丢回复、提交后丢回复、服务实例改变及来源被其他编辑器修改。明确拒绝恢复原始字节；未知结果保留候选并能只读查看磁盘/活动差异。来源专题拒绝符号链接、硬链接、0644来源、不可信/可写父目录及不存在的来源；测试对端没有加载BPF，不冒充真实应用路径。

GNU ld的测试专用fsync包装分别在临时文件同步和rename后目录同步注入EIO，核对出版边界、条件恢复、来源冲突及临时文件清理。生产程序未增加故障开关。

Clang静态分析src/vault/main.cpp、policy_file.cpp、policy_edit.cpp最终零诊断，记录vault-analyze-final.log。开发中一次errno告警指出RAII移动赋值可能遮蔽失败原因的分析路径，改为局部句柄验证后转交；此后定向专题通过。另有正常开发编译期的缺失头文件/聚合初始化警告已修正，未作为通过结果。

Release、核心关闭FUSE及安装交付在本轮后续收尾单独记录，不以普通构建结果替代它们。
