# 离线行为观察阶段验证（2026-10-19）

范围为本机 x86_64、`6.12.0-211.61.1.el10_2.x86_64`，不推及其他内核/文件系统或生产误报率。接口及解释边界见 [行为观察规则](BEHAVIOR_OBSERVATION.md)。

## 已完成验证

- 默认构建与 27 项 CTest 通过，包含新增离线归组、时间规则和采集包重放检查。
- 规则检查覆盖时间边界、必须以回复时间先行、exec/deny 不匹配、双路反序投递、进程/文件分离、样本覆盖后仍保留证据对、历史和归组淘汰、重复输入、显式关闭，以及 120 组随机交错流与独立全历史 oracle 的对照。
- 真实负载四变体（open/access × pidfd 关闭/开启）通过，原始产物见 `/tmp/secmon-behavior-tree-20261019`。每个变体包含 258 路径目录的 sha256sum 索引、cp/tar 递归备份及字节核对；另覆盖别名、重命名、替代 inode、在线撤销授权和超时窗对照。
- pidfd 开启时 open/access 分别归组 19/27 条事实，每种模式匹配 2 条：受控未授权写入和良性维护程序授权撤销后的写入。关闭时各归组 5 条 BPF 拒绝，14/22 条权限记录归为 unattributed，匹配为零。测试声明的良性匹配反例说明该模式不能直接当成恶意判定。
- 规模扩展首轮通过：4096 个普通文件加两个别名，受保护文件 4 MiB。access 模式有 1154 条权限记录、5 条 BPF 拒绝，开启 pidfd 时全归组且发生 1018 次有界历史淘汰，观察匹配仍为 2；关闭时 1154 条权限记录均为 unattributed、匹配为 0。open 模式仍为 14 条权限记录和 5 条拒绝。四变体 FD 均回到 4/4，原始包 `/tmp/secmon-behavior-large-first-20261019`。
- 关联回归的 9 个专题/变体通过（含诱饵、线程、namespace、请求方引用、生命周期及 pidfd 扩展），日志 `/tmp/secmon-behavior-regression-20261019.log`。
- 完整权限 runner 的 40 个专题/模式变体通过，日志 `/tmp/secmon-behavior-full-regression-20261019.log`。随后新增的 behavior-identity 单独通过八变体检查；当前 runner 因此共 41 个专题/模式变体。
- behavior-identity 首轮各变体精确归组到一个真实 pidfd 进程键。开启引用时各有 294 条事实、147 次观察匹配（完整时间 oracle 同为 147），关闭时 147 条权限记录均归入 unattributed、147 条 BPF 拒绝仍归组、匹配为 0。原始投递流和对照数据见 `/tmp/secmon-behavior-identity-first-20261019.json`，控制器 FD 为 4/4。
- 采集包重放验证了真实包的摘要及结果一致性，覆盖原始流损坏、结果损坏、清单汇总/来源不符、自洽摘要但错误结果和失败退出码。窗口比较保留 undetermined/none，不把更窄时间窗当作已验证误报修复。
- 流式资源检查：hot/churn 各 100000 条，tracemalloc 峰值分别为 52485/313674 字节，耗时 13.455/14.441 秒。限制为 64 个活动归组、4 个样本、每类历史 8 条；没有累计输入或输出。这不是 RSS、最大配置或内核内存测量。日志 `/tmp/secmon-evidence-streaming-stress-20261019.log`。
- 同时填满允许与未匹配拒绝历史的容量场景通过：默认 1024/32/8 配置保留 65536 条事实，tracemalloc 峰值 44354152 字节、9.426 秒；最大 4096/128/32 配置保留 1048576 条事实，峰值 664111967 字节、178.987 秒。前述三个数字分别为归组数、每类历史条数和样本数；该场景未填满匹配证据对队列，不是所有状态组合的最大内存证明。日志 `/tmp/secmon-evidence-saturated-default-20261019.log` 与 `/tmp/secmon-evidence-saturated-max-20261019.log`。

## 冻结持续验证

代码、Python 测试及二进制冻结在 `build/behavior-checkpoint-20261019`，完整文件摘要见其中 SHA256.json。关键 SHA-256：

| 文件 | SHA-256 |
|---|---|
| tools/evidence.py | `8e0b29c109f57934171eb901c3682fa6fd0e63f575d8fcb739f3c5c18e7bede6` |
| tools/behavior.py | `c028eff1a9f6d24f6ece0727257f2fe6d84e75a71854ffe27ddc8cc028f224a2` |
| tests/behavior_workloads.py | `595cf7fe7ff64c6cb59e2d0dda6d8757c69a2e83248d2ebfc78f8b85f0cd47c0` |
| bin/secmon | `11c416908542e1c92c2bf194042cffa2a9ce0eb46c95942ecf1b6dc1989be2de` |

```sh
sudo python3 -B build/behavior-checkpoint-20261019/tests/behavior_workloads.py \
  --build-dir build/behavior-checkpoint-20261019/bin --duration 3600 \
  --artifact-dir /tmp/secmon-behavior-sustained-20261019
```

日志 `/tmp/secmon-behavior-sustained-20261019.log`，每个实例原始流、CLI 结果和带摘要的来源清单分别保存。完整运行已通过：294 轮、1176 个变体、3605.663 秒，退出码 0、最终 passed=true。持续循环核对控制器 FD 回基线（4/4）、没有未回收子进程，并重新创建服务和 actors。

1176 个包均通过当前最终实现的摘要核对和逐字节重放，累计 21168 条权限记录、5880 条修改拒绝；16464 条归组、10584 条身份不足、49805 条忽略事件，invalid=0。汇总文件 `/tmp/secmon-behavior-capture-replay-summary-20261019.json`。同一数据集窗口 0/1/10/100/1000/10000 ms 分别观察到 0/588/588/1176/1176/1764 次匹配；1000 ms 中有 588 次为受控良性维护反例，10000 ms 还包含超出原窗口的延迟写入对照。这是受控观察计数，不是生产误报率或恶意识别效果。

冻结后增加的目录/文件大小参数、采集包重放工具和归组 API 严格整数校验不在该快照内；合法整数配置的规则与归组输出未改变，旧采集包仍通过当前实现的逐字节重放。直接调用 API 的小数容量原本可能绕过等值淘汰条件，现已拒绝小数、布尔值等非整数限制，并补充负例。扩展规模与新工具使用当前源码单独验收，其摘要保存在对应包的 manifest 中。

## 最终版本补充持续验证

最终源码和四个依赖二进制保存在 `build/behavior-final-v2-checkpoint-20261019`，清单为 SHA256.json，tools/evidence.py 摘要为 `31f259a75e4ba814d897da710da23a0026ce1b4c545600324548958417084300`。并行运行两个独立临时实例专题，各持续约 20 分钟：

```sh
sudo python3 -B build/behavior-final-v2-checkpoint-20261019/tests/behavior_workloads.py \
  --build-dir build/behavior-final-v2-checkpoint-20261019/bin --duration 1200 \
  --corpus-files 4096 --protected-bytes 4194304 \
  --artifact-dir /tmp/secmon-behavior-large-sustained-20261019
sudo python3 -B build/behavior-final-v2-checkpoint-20261019/tests/behavior_identity.py \
  --build-dir build/behavior-final-v2-checkpoint-20261019/bin --duration 1200 \
  --report /tmp/secmon-behavior-identity-sustained-20261019.json
```

日志分别为 `/tmp/secmon-behavior-large-sustained-20261019.log` 与 `/tmp/secmon-behavior-identity-sustained-20261019.log`。较大目录负载已完成：84 轮、336 个变体、1210.625 秒，退出码 0、passed=true，控制器 FD 为 4/4。

较大目录的 336 个包全部通过最终实现的摘要和结果重放：196224 条权限记录、1680 条拒绝，99792 条归组、98112 条身份不足、invalid=0；观察匹配 336 次，有界历史淘汰 85512 次。后者来自正常多次 access，不是审计丢失或威胁标签。汇总 `/tmp/secmon-behavior-large-replay-summary-20261019.json`。

并发身份首轮长测完成 10 轮八变体后，在第 11 轮的 /proc 任务集合采样失败：原本应为 leader 加四个新 worker，却瞬时读到一个额外的旧 worker。失败发生于证据归组前，不能将该次持续验证认定为通过。Python join/ready 同步不使 /proc 目录遍历成为内核退出过程的原子快照；测试现等待最多 3 秒，仍要求最终任务集合精确等于预期，并处理 readdir 后 status 消失的竞态。未忽略额外线程，超时仍失败，BPF 生命周期键检查也保留。

该测试修复及最终实现另存 `build/behavior-identity-v3-checkpoint-20261019`（清单 SHA256.json），以同样 1200 秒重新运行 behavior_identity.py。新日志 `/tmp/secmon-behavior-identity-resumed-20261019.log`，最后完整轮报告 `/tmp/secmon-behavior-identity-resumed-20261019.json`；原失败日志保留。

修复后完整重跑通过：53 轮、424 个变体、1211.137 秒，退出码 0、passed=true，控制器 FD 为 4/4。累计 62328 条权限记录和同量修改拒绝；开启 pidfd 的 212 个变体均观察到 147 次匹配，与全历史时间 oracle 一致，关闭时 212 个变体均为 0。该结果不取消一般情况下的历史裁剪和实际线程归属限制。
