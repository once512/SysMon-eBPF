# 固定多目标订阅验收（2026-10-20）

已实现[一个 group 订阅最多 64 个固定普通文件](FANOTIFY_MULTITARGET.md)。配置可重复 fanotify-file，CLI 可重复 --file；所有目标共享裁决、分析器及 pending 预算。每个请求接收时从事件 FD 核对目标，保存自身设备/inode 快照，所有完成路径使用该快照。

目标列表增删、路径或顺序变化仍返回 restart_required，不在线迁移 mark。裁决参数可在空闲时更新；准备失败、busy 和目标变化保留旧策略。配置来源在读取前排除全部目标，覆盖次要目标的硬链接自我等待风险。管理 ABI 更新为 v4/360 字节，状态报告 fanotify_targets；客户端与服务端需使用同一构建。

## 构建、单元与完整特权回归

- 普通构建成功，29/29 CTest 通过，耗时 2.30 秒。
- 独立 Release 构建成功，29/29 CTest 通过，耗时 2.18 秒。
- 冻结快照 `build/multitarget-v3-checkpoint-20261020` 完整运行 44 项特权专题/模式，全部通过，退出码 0；各专题耗时合计 379.777 秒。此处 v3 是快照修订号，管理协议为 v4。
- 带 ASan/UBSan 的 libFuzzer 配置解析/重编码测试完成 1888707 次执行，121 秒，退出码 0，无 sanitizer 错误或崩溃产物。

完整特权回归包括原有保护/授权/重载、管理异常帧、namespace、审计及诊断背压、真实应用、身份线程和请求方生命周期。新增 fanotify-multiple 专题覆盖四种 open/access × pidfd 组合，各核对 21 条请求审计及 FD 4/4；另外六组分析/超时/容量与停止组合和多对象 exec 放行/拒绝均通过。

启动失败清理验证硬链接重复、符号链接、目录、缺失文件、配置自身及第一个 mark 成功后第二个 mark 失败。CLI 与纯解析测试覆盖重复路径、64/65 目标边界。并发延迟请求、容量回退、超时、分析和停止均检查目标身份，避免不同目标或回复顺序混淆。

八对象全订阅初跑四个变体通过，open/access 各 40/80 条权限允许、40 次修改拒绝；pidfd 开启时单对象时间配对为 24 次，分别为正常批量保存八次、受控覆盖八次、重复修改同一对象八次。

## 64 目标持续负载

完整重复 open/access × pidfd 开关四种模式，55 轮、220 个变体通过，耗时 483.112 秒，退出码 0，控制器 FD 基线/结束均为 4。每个变体保护并订阅 64 个对象，七个独立进程运行索引、正常批量保存及受控破坏对照，核对 320 次修改拒绝、全部原始内容和 inode 不变，以及零审计/内核丢失、零历史淘汰。累计验证 70400 次修改拒绝。

| pidfd | 权限模式 | 每包权限允许 | 每包修改拒绝 | 每包时间配对 |
|---|---|---:|---:|---:|
| 关闭 | open | 320 | 320 | 0 |
| 关闭 | access | 640 | 320 | 0 |
| 开启 | open | 320 | 320 | 192 |
| 开启 | access | 640 | 320 | 192 |

开启 pidfd 后，正常批量保存和受控批量覆盖各有 64 个配对对象，重复修改同一文件有 64 次配对但对象峰值仍为一。直接批量截断及分离写入者各有 64 个拒绝对象、无访问配对。上述结果只表明给定输入的模式覆盖，不认证操作意图。

220 份采集包使用工作区工具全部精确重放，重新生成的多对象结果与各包 chains.json 完全一致，复核耗时 12.44 秒。另核对配对计数、不同对象峰值、角色对照和 classification/response 边界。复核脚本为 `/tmp/secmon-replay-multitarget-20261020.py`，结果及实现摘要为 `/tmp/secmon-multitarget-64-replay-20261020.json`。

## 冻结来源与记录

正式源文件与二进制清单为快照中的 `SOURCE_SHA256.json`，逐项与运行前摘要及工作区核对一致；Python 运行时生成的 __pycache__ 不作为源文件。原始 SHA256.json 含从前次运行复制的缓存条目，不能用缓存变化判断源文件发生变化。

正式命令：

```sh
sudo python3 -B build/multitarget-v3-checkpoint-20261020/tests/run_privileged.py \
  --build-dir build/multitarget-v3-checkpoint-20261020/bin

sudo python3 -B build/multitarget-v3-checkpoint-20261020/tests/behavior_chains.py \
  --build-dir build/multitarget-v3-checkpoint-20261020/bin --mark-all --objects 64 \
  --duration 480 --artifact-dir /tmp/secmon-multitarget-64-soak-20261020
```

本机原始日志与产物（`/tmp` 不是永久归档）：

- 原生构建：`/tmp/secmon-multitarget-build4-20261020.log`。
- CTest：`/tmp/secmon-multitarget-ctest-final-20261020.log`。
- Release 构建及 CTest：`/tmp/secmon-multitarget-release-20261020.log`。
- 完整特权回归：`/tmp/secmon-multitarget-full-v3-20261020.log`。
- 模糊测试：`/tmp/secmon-multitarget-fuzz-20261020.log`，种子与产物目录使用相同日期后缀。
- 64 目标持续负载：`/tmp/secmon-multitarget-64-soak-20261020.log` 及同名无后缀采集目录。

正式 secmon SHA-256：`006ee25c6758b38ae1967107ab40b70026c55614d1a7bd54658057a18034e943`。

## 仍保留的边界

完整多对象访问后拒绝模式也会在正常批量保存中出现；受控 XOR 操作不是已确认恶意软件样本。本轮补齐订阅覆盖，不报告生产误报率或攻击召回率，不自动隔离，classification 保持 undetermined、response 保持 none。动态目标迁移、递归目录订阅及逐目标裁决没有纳入本轮实现。
