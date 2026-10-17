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
