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

## 完整文件读取、备份和路径变化（后续阶段）

`tests/decoy_workloads.py` 增加两个持续存活的 Python 工作进程：索引进程逐块读到 EOF 并计算 SHA-256，备份进程逐块复制到独立目录。每个文件大小与摘要均按独立 fixture 核对，备份副本还逐字节核对。它们是可控的完整文件负载，不代表已覆盖第三方备份软件、增量备份或目录爬取。

```sh
sudo python3 -B tests/decoy_workloads.py --build-dir build --report /tmp/secmon-decoy-workloads.json
```

此命令依次运行 open 和 access 两种模式，已加入权限 runner 的 `decoy-workloads` 专题。namespace 前提与上一实验一致，角色仍是测试声明。

每种模式有四个文件工作负载，包含重命名前后的索引与备份：

- 重命名前，读取原路径、既有硬链接、指向原路径的符号链接，三者均命中同一受保护 inode。
- 原生 editor 仅获 rename 授权，将目标改名；在原路径创建不同 inode 的替代文件。此时硬链接与新名称指向旧 inode，原路径和符号链接指向替代文件。
- 两个工作进程读取这四个路径，核对原内容与替代内容。只有硬链接和新名称触发原 inode 的权限审计；路径字符串相同不会让替代 inode 自动继承策略。
- 重命名前后分别使用 outsider 的预先打开 FD 写入旧 inode，均为 EACCES 且各有一条 BPF write 拒绝。两条事件的 start_ns 相同，actor 全程存活；停止服务后核对旧文件内容未改变。

实测原文件 10040 字节，每个完整读取含三次数据读取和一次 EOF 读取。open 模式共 **10** 条 allow 裁决，access 模式共 **40** 条 allow 裁决；每种模式另有 **2** 条 BPF write 拒绝。报告保留每个工作负载的文件摘要、字节数、PID、时间窗、匹配的原始 permission 事件、原始拒绝和诊断。脚本核对完整请求 ID、实例与对象身份、精确数量、零审计/内核丢失，并在清理前确认 actor 仍存活。

这里的计数属于该脚本使用的普通 read 循环，包括 EOF 读取，不是所有备份程序的固定公式。正常完整读取也会产生多次 access 记录，硬链接会重复访问同一 inode；不能仅据次数阈值判断恶意。权限记录保存的是 inode 身份，没有每次访问的路径；报告里的路径来自受控工作负载声明，不能冒充服务已解析出的可信路径。

后续重点转向线程与进程生命周期的可信身份合同、并发和 namespace 边界，再评估行为规则。现有实验仍未增加恶意判定或自动隔离。
