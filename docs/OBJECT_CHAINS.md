# 进程内多对象观察汇总

`tools/chain_capture.py` 对已核验、可精确重放的采集包，按进程生命周期键汇总对象范围和时间窗口。它独立分析完整原始输入，不从已裁剪的 evidence samples 推断完整历史，不合并不同服务实例或按数字 PID 拼接进程。

```sh
python3 -B tools/chain_capture.py CAPTURE_DIRECTORY \
  --pair-window-ms 1000 --chain-window-ms 10000 --min-objects 3
```

输出分别保留两种观察：

- `multi_object_denials_observed`：同一进程在 chain-window 内，至少 min-objects 个不同设备/inode 对象上发生修改拒绝。
- `multi_object_access_then_denial_observed`：同一范围内至少这么多个对象，各有同进程、同对象、严格早于拒绝且在 pair-window 内的 open/access allow 回复。

窗口边界包含端点；访问回复与拒绝同一时间戳不构成先后。只比较有效进程键；exec、权限 deny、无引用的权限记录不提供访问支持。每个拒绝最多构成一次配对；重复日志不做去重，因此原始次数不代表唯一系统调用数。

每个进程输出两个窗口的最大不同对象数及其起止时间、总拒绝数、配对拒绝数、不同对象数和各对象的操作类型/访问 revision 计数。重复写同一 inode 不增加不同对象数；不同设备的相同 inode 是不同对象。窗口峰值相同时保留按事实时间排序后首次出现的区间，原始流反序不改变结果。访问 revision 只是记录计数，不证明某次拒绝属于该 revision 或发生授权撤销。

这些字段均为事实观察，`classification=undetermined`、`response=none`。open allow 不能证明完成读取，access allow 也不能证明读到了哪些内容；报告明确标记 read_completion_verified=false。正常批量更新和受控批量破坏可能产生相同的对象范围，阈值不是恶意判据。

## 当前原生覆盖限制

早期基线通过 BPF 保护多个对象，但每实例只审计第一个文件。当前已加入[最多 64 个固定文件的订阅](FANOTIFY_MULTITARGET.md)；是否有访问证据取决于实际配置，不能从 protect 声明推断已订阅访问。工具如实输出缺失，不把未记录的读取补成访问。

```sh
sudo python3 -B tests/behavior_chains.py --build-dir build \
  --artifact-dir /tmp/secmon-chains
sudo python3 -B tests/run_privileged.py --build-dir build --only behavior-chains
sudo python3 -B tests/behavior_chains.py --build-dir build --mark-all --objects 64
```

该专题默认每变体保护八个文件、仅标记第一个文件，运行七个独立进程：普通索引、正常批量保存、受控 XOR 覆盖、直接批量截断、重复修改同一文件、分离读取者和写入者。`--mark-all` 订阅全部文件，`--objects` 可选 3..64，`--duration` 可选 0..1200 秒。可写 FD 在保护启用前打开，后续写入必须仍被拒绝；读取另行打开文件。场景仅作用于临时自建文件，角色是测试声明，不是已确认攻击样本。

每个变体 40 次修改拒绝，全部目标 inode 和字节保持不变。pidfd 开启时，正常批量保存和受控批量覆盖各仅第一个文件有配对证据；重复修改该文件八次有八次配对，但不同对象数仍为一。批量截断和分离写入者有八个不同拒绝对象、无访问配对。正常索引和分离读取者无修改拒绝。

## 资源和验证

继承覆盖评估器的 32 MiB 原始输入、50000 条记录、64 MiB evidence、2 MiB manifest 以及最多 128 个声明角色限制；另限制最多 4096 个进程/对象键，超限拒绝，不输出部分成功报告。配对与对象窗口均为 1..3600000 ms，min-objects 为 2..4096。

分析前核验清单摘要、精确重放基线，重新读取的原始流和清单也必须匹配已核验摘要。来源仍是操作者声明，authenticity_verified=false；对象全生命周期、代码身份和全进程历史均未证明。

`offline-object-chains` 使用独立二次复杂度算法核对不同对象窗口及配对，覆盖乱序、窗口边界、设备/进程隔离、重复对象、输入损坏及容量拒绝。真实负载另核对 pidfd、对象、操作、请求 ID、零丢失、控制器 FD 和子进程回收；每包增加 chains.json，可用上述 CLI 重新生成。

多目标订阅已补充目标预算、请求对象身份及重载/失败清理合同；[即时静态 allow 采集模式可受限在线切换目标](FANOTIFY_HANDOVER.md)，拒绝/扫描模式仍需重启。正常批量更新与受控破坏仍可出现相同的多文件访问后拒绝模式，后续需要独立判定依据，不能用范围阈值代替恶意判定。
