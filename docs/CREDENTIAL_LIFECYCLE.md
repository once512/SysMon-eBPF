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

需要 libcap 工具中的 `setcap`，并要求临时文件所在挂载允许 setuid 和文件 capabilities。测试仅复制三个临时报告程序：普通文件、root 所有的 4755 文件，以及附加 `cap_net_bind_service=ep` 的文件。子进程先以 UID/GID 65534 和空补充组执行它们；报告程序只输出自身 UID/EUID 与有效 capabilities，不执行特权操作。临时目录退出后自动删除，不修改系统程序或账户。

当前开发机已通过：普通执行保持 UID/EUID=65534、caps=0；setuid 执行得到真实 UID 65534、有效 UID 0；文件 capability 执行仍为 UID/EUID=65534，但有效 capabilities 含指定的 CAP_NET_BIND_SERVICE。检查/完成事件与实际报告相符，未出现基线不一致标记或统计失败。

这个实验修正了一个重要的字段解释：`exec_check.target_euid` 只是该检查点的 `bprm->cred` 候选 EUID，尚未必计算 setuid，不能预测最终权限。`exec_success.target_euid` 则读取当前任务已提交的 EUID，与成功事件的 `euid` 相同。

Linux 6.12 在 `search_binary_handler` 中先调用安全检查，随后格式处理器进入 `begin_new_exec` 计算最终文件凭证；提交后 `bprm->cred` 被清空。因此完成事件不能继续从该指针取 EUID。可对照 [Linux v6.12 fs/exec.c](https://github.com/torvalds/linux/blob/v6.12/fs/exec.c) 中这些步骤阅读。
