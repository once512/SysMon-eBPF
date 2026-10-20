# 受限在线目标切换验收（2026-10-20）

实现[即时静态 allow 模式的在线目标切换](FANOTIFY_HANDOVER.md)：独立准备候选 group，共同路径复制原 O_PATH 引用，新增路径重新固定，成功准备 BPF 后无异常切换资源。旧门使用拒绝、延迟或分析模式时仍需重启；已交付请求未完成时返回 busy。请求号和累计统计跨 group 保留，管理线格式仍为 v4/360 字节。

切换审计事件 fanotify_target_handover 明确标记旧内核未读取事件按先前 allow 语义释放，individual_audit_complete=false。本轮没有实现任意拒绝/扫描策略的无损迁移，没有恶意分类或自动响应。

## 普通、Release 与内存检查

- 普通原生构建成功，29/29 CTest 通过，耗时 2.10 秒。
- Release 构建成功，29/29 CTest 通过，耗时 2.04 秒。
- 请求队列用 Clang ASan/UBSan 和 detect_leaks=1 重新编译运行通过，覆盖共享请求号、耗尽拒绝、截止时间、容量、停止及 FD 所有权。这是队列专题检查，不是完整服务的 sanitizer 验收。
- 冻结版本完整运行 45 项特权专题/模式，全部通过，退出码 0；各专题耗时合计 413.144 秒。新增 fanotify-handover 专题耗时 22.888 秒。

## 新专题的正式结果

open/access × pidfd 开关四个主要变体全部通过。默认 rounds=16 时，每个变体成功切换目标 23 次，产生 56 条权限回复、64 次独立 BPF guard 修改拒绝，最终 revision=27；结束 FD 为 4/4。控制器用稳定进程引用核对主体，按设备/inode、revision、实际裁决逐条核对预期；切换事件核对服务身份、计数、边界标志和连续下一请求号。

验证包含增添/删除目标、共同路径保持旧 inode、原路径替换、新增后重新绑定新 inode、描述符数量恢复，及缺失文件、重复 inode、配置自身、部分 mark 失败和 BPF 准备失败的回滚。拒绝、空闲延迟、忙请求、分析模式分别验证保留旧合同，分析器 PID 未被目标重载悄悄替换。

另有两组最大容量检查：open/access 各在 64 个目标上核对 511 条权限回复，并验证第 65 项、重复路径、部分 mark 和 BPF 失败，随后完成三次成功的 64/63 目标切换。FD 数按当前目标数精确恢复，guard 写入仍被拒绝。

## 内核积压请求边界

fanotify-only 临时实例暂停后，八个旧访问进程均被观察到等待 fanotify，再将 reload 命令排入管理 socket 后恢复服务。该实验不暂停联合自保护实例。

- 旧即时 allow：目标切换成功，八个旧访问均允许；本机正式运行只记录一条旧权限回复，另有一条新目标 deny 回复和一个切换事件。没有把其余旧内核请求补造为审计记录。
- 旧 deny：目标切换返回 restart_required，旧八个访问及后续旧目标访问全部拒绝，九条权限回复均保留旧 revision。
- 候选准备失败：旧 group 保留，八个旧访问及后续旧目标访问全部有实际 allow 回复，共九条旧 revision 记录。

请求号连续只表示已交付、已回复的记录没有重置或复用，不证明所有系统调用均已采集。关闭 group 的语义依据及并发限制见[实现合同](FANOTIFY_HANDOVER.md)。

## 持续负载口径

持续模式使用 rounds=128，每个主要变体执行 135 次成功目标切换、224 条权限回复、288 次独立 BPF guard 修改拒绝，最终 revision=139。每次成功或失败尝试均查询活动状态、检查旧保护和 FD 数量；每个完整变体结束后控制器必须恢复 FD 基线且没有遗留子进程。预检另包括最大容量、内核积压和模式限制场景，不混入主要变体的切换次数。

逐包复核先验证摘要并精确重放 evidence，再用测试动作独立核对所有切换事件的旧/新/保留目标数、revision、下一请求号及时间顺序。最终汇总还重新核对全部原始流、结果和清单摘要，避免把仍在写入的目录当作已完成包。辅助复核脚本只选择已在日志中输出 passed 的变体。

正式持续运行 1323.074 秒（22 分 3 秒），完成 34 个完整循环、136 个主要变体，全部通过，进程退出码为 0。主要变体累计成功切换 18360 次，记录 30464 条权限回复，并验证 39168 次独立 BPF guard 修改拒绝；这些数字不包含一次性预检。控制器起止 FD 均为 4。

全部 136 个采集包均通过独立精确重放及切换字段核对，最后重新验证原始流、evidence 和清单摘要完整；最终复核结果为 passed=true、final_artifacts_intact=true。辅助脚本多次增量复核累计耗时 4.466 秒。生产源文件、测试、工具及正式二进制在持续运行期间保持冻结。

## 冻结版本与原始记录

代码、全部测试、工具、BPF 源码及二进制冻结于 `build/handover-checkpoint-20261020`，SHA256.json 对全部文件记录摘要。正式运行设置 PYTHONDONTWRITEBYTECODE=1，避免缓存写入混淆源文件冻结检查；工作区生产源文件与快照逐项核对一致。

```sh
sudo env PYTHONDONTWRITEBYTECODE=1 python3 -B \
  build/handover-checkpoint-20261020/tests/run_privileged.py \
  --build-dir build/handover-checkpoint-20261020/bin

sudo env PYTHONDONTWRITEBYTECODE=1 python3 -B \
  build/handover-checkpoint-20261020/tests/fanotify_handover.py \
  --build-dir build/handover-checkpoint-20261020/bin --rounds 128 --duration 1320 \
  --artifact-dir /tmp/secmon-handover-soak-20261020
```

本机产物（`/tmp` 内容不是永久归档）：

- 构建：`/tmp/secmon-handover-build5-20261020.log`。
- CTest：`/tmp/secmon-handover-ctest-final-20261020.log`。
- Release 构建及 CTest：`/tmp/secmon-handover-release-20261020.log`。
- 队列 sanitizer：`/tmp/secmon-handover-sanitizer-build-20261020.log` 和 `/tmp/secmon-handover-sanitizer-20261020.log`。
- 完整特权回归：`/tmp/secmon-handover-full-20261020.log`。
- 持续负载：`/tmp/secmon-handover-soak-20261020.log` 及同名无后缀采集目录。
- 回放与切换字段复核：`/tmp/secmon-check-handover-20261020.py`，汇总为 `/tmp/secmon-handover-replay-20261020.json`。

正式 secmon SHA-256：`8f493ef0d517f77638ce7f617ed0df72f7e42eff4f149bfc5474453428769d5d`。
