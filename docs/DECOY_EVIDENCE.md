# 临时诱饵行为证据实验

`tests/decoy_evidence.py` 使用临时真实文件和四个在策略加载前启动、直到审计排空后才退出的原生进程，验证系统调用结果与两类审计的关系。程序副本分别命名为 indexer、backup、editor、outsider；这些名称是测试声明，不是系统推导的可信角色。indexer/backup 都只执行一次正常读取，本实验尚未实现完整索引或备份工作负载。

运行前在宿主机初始 PID namespace 中构建项目，然后执行：

```sh
sudo python3 -B tests/decoy_evidence.py --build-dir build --report /tmp/decoy-open.json
sudo python3 -B tests/decoy_evidence.py --build-dir build --event access --report /tmp/decoy-access.json
```

脚本检查可见的 PID namespace 与 NSpid。该检查不能独立证明容器中的 `/proc` 展示的是宿主机初始 namespace；从宿主机运行仍是调用前提。不能把这里的 PID 关联直接推广到任意 PID namespace。actor 保持存活且操作串行，限定同一个系统调用时间窗、PID、设备号和 inode；没有使用退出进程的 `/proc` 信息推测身份，也没有实现通用线上关联器。

## 2026-10-18 实测

每种模式验证 11 个操作；open 模式共 3 条 permission 记录、7 条 BPF file_denied，access 模式分别为 2 条和 7 条。

| 操作 | 系统调用 | open permission | access permission | BPF 拒绝 |
|---|---|---|---|---|
| indexer/backup 分别读取 | 成功 | 各一条 allow | 各一条 allow | 无 |
| editor 新打开并写入 | 成功 | 一条 allow | 无 | 无 |
| editor 已打开 FD 写入 | 成功 | 无 | 无 | 无 |
| outsider 写打开 | EACCES | 无 | 无 | open-write |
| outsider 已打开 FD 写入 | EACCES | 无 | 无 | write |
| outsider 已打开 FD 截断 | EACCES | 无 | 无 | truncate |
| outsider 删除/重命名/硬链接 | EACCES | 无 | 无 | 各对应一条 |
| 撤销 editor 授权后原进程、原 FD 写入 | EACCES | 无 | 无 | write |

报告保留每个系统调用的 monotonic 时间窗、返回 errno、actor PID、对应原始事件、文件身份和服务诊断。脚本核对精确事件种类、拒绝操作码、所有相关事件无遗漏及共享审计/内核丢失计数为零。目标文件仍存在，未授权重命名/硬链接没有生成目标路径。输出报告在实验后生成；临时文件、进程与策略均清理。

这些结果说明读取行为本身不能区分正常索引、备份与恶意意图；fanotify 的 allow 只证明权限响应已发送，不证明后续系统调用成功。BPF 拒绝可能在 fanotify 之前结束操作，预先打开的 FD 操作也未必触发 permission 事件。没有事件不等于没有行为。本实验不输出恶意判定、不执行隔离，也不将测试角色作为生产授权依据。

下一步应扩展真实备份/索引负载、inode 别名与路径变化，并单独设计可信进程生命周期身份、跨 namespace 关联及规则误报验证；自动隔离和恢复仍需独立设计。

本轮验证：默认构建成功，23 项 CTest 全部通过；权限 runner 的 writer-scope、writer-matrix、permission-audit、decoy-evidence 四个专题全部通过。策略矩阵包含 40 次提交和 6 次拒绝。access 模式另行通过独立实验。原始报告保存于本机 `/tmp/secmon-decoy-evidence.json` 与 `/tmp/secmon-decoy-access-evidence.json`，它们包含每次运行变化的 PID、inode 和时间戳，不提交到仓库。
