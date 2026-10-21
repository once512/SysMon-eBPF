# 凭证基线与线程生命周期实验

凭证基线用于比较已观测的状态，不是授权结论。合法 root 执行、setuid、文件 capabilities、主动降权和真正的攻击都需要区分；仅凭一次 `commit_creds` 不能证明变化合法。

## 直接观察 Map

```bash
sudo python3 tests/baseline_lifecycle.py --build-dir build --rounds 20
```

测试仅查询自己临时启动的宿主所持有的 `cred_map`。先从 `/proc/PID/fdinfo` 取得该宿主的 Map ID，再用 bpftool 核对名称、类型与 key/value 大小，通过系统 libbpf 读取。不会遍历其他实例并任意选取同名 Map，也不写入 Map。

| 文件 | 职责 |
| --- | --- |
| `tests/lifecycle_scenario.cpp` | 保持线程存活、等待测试指令、join、主动降权和非主线程 exec |
| `tests/baseline_lifecycle.py` | 按阶段验证 task key、凭证值、exec 事件与最终删除 |
| `tests/credential_map.py` | 找到指定宿主的凭证 Map，并以对应布局读取 |
| `tests/monitor_harness.py` | 临时宿主的启动、日志、停止和释放 |

测试流程：

1. 主线程创建四个等待中的线程，检查五个 task key 均存在，UID/EUID 与 capabilities 一致。
2. 释放并 join 四个线程，检查只剩主线程 key。
3. 交替保持 root 或在测试进程内降权到 UID/GID 65534，后者检查 Map 中 UID/EUID=65534、有效 capabilities=0。
4. 从非主线程执行同一个临时测试程序。检查 exec 后 TID 回到线程组 PID，只剩一个当前 key；检查成功事件的 `old_tid` 等于原执行线程 TID。
5. 退出子进程，检查该线程组已无条目，宿主失败计数为 0。

key 使用 `(TGID/TID, start_boottime)`，不能只按裸 PID 比较。测试在受控阶段保持目标线程不退出，降低观察竞争；其他系统线程仍可更新 Map，所以遍历有时间预算并对重复观察去重。这不是全系统原子快照，也不证明所有任务、PID 复用和命名空间场景均已覆盖。

测试会把场景程序复制到 root 所有、可遍历的临时目录，使 UID 65534 能执行它；不会修改用户主目录权限。stdin 指令采用逐字节有界读取，避免 exec 丢失用户态预读的后续指令。辅助程序的基础交互流程也由无特权 CTest 验证。

2026-10-17 当前开发机上，20 轮交替 root/降权场景全部通过；此前已通过的事件输出验证由此补充了对实际 Map key 和值的观察。测试不制造真实内核提权，也不证明基线具备可信授权属性。


## 合法 setuid 与文件 capabilities

```bash
sudo python3 tests/credential_transitions.py --build-dir build
```

需要 libcap 工具中的 `setcap`，并要求临时文件所在挂载允许 setuid 和文件 capabilities。测试复制普通、setuid、setgid、file-capability 和 user-namespace 五个临时报告程序。前三类权限转换及 file capabilities 从 UID/GID 65534 与空补充组启动；user namespace 通过 unshare 在临时子进程中映射 root，不改变宿主 namespace。报告程序读取自身 /proc 状态与 capget，不执行特权操作。临时目录退出后自动删除，不修改系统程序或账户。

当前开发机已通过：普通执行保持 UID/EUID=65534、caps=0；setuid 执行得到真实 UID 65534、有效 UID 0；文件 capability 执行仍为 UID/EUID=65534，但有效 capabilities 含指定的 CAP_NET_BIND_SERVICE。检查/完成事件与实际报告相符，未出现基线不一致标记或统计失败。

这个实验修正了一个重要的字段解释：`exec_check.target_euid` 只是该检查点的 `bprm->cred` 候选 EUID，尚未必计算 setuid，不能预测最终权限。`exec_success.target_euid` 则读取当前任务已提交的 EUID，与成功事件的 `euid` 相同。

Linux 6.12 在 `search_binary_handler` 中先调用安全检查，随后格式处理器进入 `begin_new_exec` 计算最终文件凭证；提交后 `bprm->cred` 被清空。因此完成事件不能继续从该指针取 EUID。可对照 [Linux v6.12 fs/exec.c](https://github.com/torvalds/linux/blob/v6.12/fs/exec.c) 中这些步骤阅读。


## 合成基线不一致

```bash
sudo python3 tests/baseline_mismatch.py --build-dir build
```

此测试先运行不修改 Map 的对照进程，再对测试宿主自己的凭证 Map 中、仍在等待指令的测试主线程条目，逐次把 UID、EUID、五类 capability、保存/文件系统 UID、各类 GID 或 user namespace 字段中的一个改为不同值。使用精确 task key 和 BPF_EXIST，拒绝凭空创建条目。真实任务仍为 UID/EUID 0，随后由主线程 exec，同一次检查输出 flags=1；干净对照的检查 flags=0。exec 提交后，Map 再次与实际凭证一致，进程退出后条目清理。

当前开发机验证通过。它证明已观测基线不一致到事件输出的链路，不证明能够检测真实内核攻击。`exec_success.flags=0` 仍然不表示在完成点重新做过异常检查。这里的 Map 写入仅存在于测试脚本，生产程序没有注入接口。


## 完整凭证观察（2026-10-21）

cred_map 的 value 当前为 80 字节：UID/EUID、有效 capabilities，以及 SUID/FSUID、GID/EGID/SGID/FSGID、permitted/inheritable/bounding/ambient capability 集合和 user namespace inode。每次提交/创建/执行建立完整观测值，执行检查比较所有有意义字段，忽略保留填充。key 的线程生命周期合同不变。

公共 BPF 事件 ABI 升至 6，执行检查和成功事件输出新增字段。UID/GID 使用内核全局 kuid/kgid 坐标，不能把 namespace 内 root 数字直接当作宿主 root；namespace inode 是观测上下文，不是可信判定。file_denied/self_denied 仍按自己的字段合同输出，不把未采集的额外字段解释为零凭证。

合成偏差专题逐个覆盖 14 个字段（一个干净对照加 14 次单字段注入），只改当前测试 Map，不改真实 task->cred；每次 exec 后完整基线恢复并在退出后删除。真实普通、setuid、setgid、file-capability 和子 user namespace 执行的成功事件逐字段与进程自身报告对照。该 namespace fixture 使用宿主 root 到子 root 的对应映射，不构成任意 UID 映射或完整容器验收。

这补齐观察覆盖，不认证提权路径，也不新增自动阻断。正常调用 commit_creds 的攻击仍可能更新基线；特定合法操作、历史缺失和内核失陷边界仍需独立分析。
