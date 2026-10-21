# 一小时推进与验收（2026-10-21）

基于 `8f4e717`，开发机为 `6.12.0-211.61.1.el10_2.x86_64`、`x86_64`。本轮推进三个原计划缺口，并修正审查中发现的时钟域问题；不把实验观察当作已确认攻击。

## 实现检查点

| 提交 | 变化 |
| --- | --- |
| d019af7 | 订阅代际、闭合离线批次校验、跨代隔离及同进程旧 FD 实验 |
| 8e55db5 | 内核启动时钟上的限时维护写例外、到期拒绝原因、暂停服务与续期/撤销测试 |
| a951bd1 | 扩展 UID/GID、五类 capabilities、user namespace 的观测与单字段偏差测试；BPF ABI 6 |
| 69ce2b8 | 租期 time namespace 偏移归一化；本地 root/全局身份授权对照 |

订阅参考：[代际合同](OFFLINE_EVIDENCE.md)。维护授权参考：[租期合同](POLICY_CONFIG.md)。凭证参考：[字段和实验](CREDENTIAL_LIFECYCLE.md)。

## 已完成的普通及专项检查

- 原生构建及 30/30 CTest 通过；时钟修正后的 Release 构建及 30/30 CTest 通过，后者耗时 2.26 秒。
- 扩展事件编码使用 Clang ASan/UBSan 和泄漏检查通过，包括最大字段及未对齐缓冲。
- 最终 file_policy.cpp 的 Clang 静态分析没有诊断；这是该源文件专题检查，不是完整程序安全审计。
- 解析 libFuzzer/ASan/UBSan 在 `8e55db5` 完成 1,341,944 次输入，121 秒，退出码 0。后续改动未改变该解析器路径；不将这项检查扩大为新内核代码的 sanitizer 验收。
- 同进程、同 inode、旧 FD 的四种真实代际变体通过：每变体三次切换和六次修改拒绝，pidfd 开启时仅三次同代配对，关闭时零配对；七种投递/缺失评估与采集包重放通过。
- 限时写例外覆盖程序/目标隔离、旧 FD、新打开、共享 mmap/mprotect、失败不续期、新版本续期、删除授权、用户态服务暂停仍到期，以及拒绝原因和 FD 清理。
- 凭证专题覆盖 14 个单字段合成偏差及干净对照，不修改真实 task 凭证；普通/setuid/setgid/file-capability/user namespace 的事件与自报值一致。
- 全局 UID/GID 65534 映射为本地 root 的实例仍被宿主 UID 0 写授权拒绝；目标 DAC 有意放行，避免将 DAC 拒绝误认成 BPF 效果。
- 独立初始时钟核对服务启动时钟偏移 +3600/-60 秒下的到期，不修改宿主时钟。无法确定当前 clock namespace 偏移时拒绝候选。

## 离线暂存与内存实验

CLI 对 100000 条合成记录、31800000 字节输入完成闭合批次分析，结果为 100000 条归组事实、50000 次观察配对、零非法记录。耗时 2.355 秒，分析子进程峰值 RSS 为 17820 KiB。这是本机资源观察，不是性能 SLA 或通用上限。

直接 Grouper 的 100000 条 hot/churn 实验也通过，tracemalloc 峰值分别为 58048/314904 字节；它们是 Python 被跟踪分配，不是 RSS，不能互相替代。离线 CLI 暂存有 128 MiB/1000000 条/4096 次切换预算，参考评估器保持更严格的预算。

## 完整特权回归

前两阶段分别完成 47/47 专题（8e55db5，406.744 秒）和 47/47 专题（a951bd1，371.828 秒）。最终 69ce2b8 的 49/49 专题及模式也全部通过，退出码 0，各专题累计耗时 383.934 秒。该最终回归包含两个新增命名空间专题；背压专题有意制造的日志丢弃属于断言中的预期，不应将整套结果描述为所有场景零丢失。持续验证结果见下节。

## 冻结版本持续验证

源提交 `69ce2b8`。本轮共耗时 686.139 秒，代码和二进制在开始/结束时逐项 SHA-256 一致：

- 代际循环 604.726 秒，完成 340 个变体（open/access × pidfd 开关），各实例三次切换；合计 1020 次切换、2040 次独立 BPF 修改拒绝和 510 次同代时间配对。
- 每个实例只支持同代观察：旧 FD 跨保留/移除/重加不能沿用旧访问证据；不将该观察解释为恶意。
- 全部 340 份采集包在结束后逐包精确重放，与各自摘要一致。每个变体还核对七种投递/缺失实验，共 2380 组；这是既有证据上的实验，不是内核丢失注入。
- 十轮租期测试包含 20 个实例场景，覆盖正常/暂停服务、到期、续期、撤销与清理；所有调用断言通过。
- 代际控制器 FD 基线与每次收尾均为 4；源码与产物冻结校验通过。短实例循环不等同于同一守护进程连续运行十分钟，也不证明全部内核对象已同步 RCU 回收。

原始监督日志 `/tmp/secmon-hour-soak-20261021.log`，采集、逐轮日志、summary.json 和 source_sha256.json 位于 `/tmp/secmon-hour-soak-20261021-1792582393`。复现主要入口：

```sh
sudo python3 -B tests/run_privileged.py --build-dir build
sudo python3 -B tests/subscription_live.py --build-dir build --duration 600 --artifact-dir /tmp/secmon-epoch-captures
sudo python3 -B tests/writer_lease.py --build-dir build
python3 -B tools/replay_capture.py CAPTURE_DIRECTORY
```

## 最终冻结生产产物

| 产物 | SHA-256 |
| --- | --- |
| secmon | `7adbf785987ec42d9a1a94567bbb8e1bdf259d248cf3cea1a0a004fe6ec309d8` |
| secmon-analyzer | `c99aad5add45d93d27dc6bd4df24e7a15452f20706b81015bf8913ea08ce361f` |
| secmon-policyctl | `75619831954610a95df6c8935dbd3f5ec2d3f1fd095f5b5f8ce3224371ae9571` |

## 本机记录与边界

原始日志为 `/tmp/secmon-hour-full-20261021.log`、`/tmp/secmon-hour-final-full-20261021.log`、`/tmp/secmon-hour-clock-final-full-20261021.log`、`/tmp/secmon-hour-fuzz-20261021.log` 和对应 Release/专项日志。`/tmp` 不作为永久归档。

当前仍无可信提权来源判定、真实攻击召回/误报结论、在线反勒索自动响应、完整保险箱读会话、虚拟诱饵、加密与恢复。写租期不撤销既有共享可写映射，不取消在途操作；成功新 BPF 策略会显式重新计时。凭证未覆盖附加组、securebits、LSM 标签或全部 cred 结构。租期的 time namespace 归一化不代表非零单调偏移下 fanotify/BPF 联合时间关联已适配。

最终收尾还通过 73 个 Python 文件 AST 检查、全部 Markdown 相对链接检查及 git diff --check；未遗留 secmon 系列测试进程。
