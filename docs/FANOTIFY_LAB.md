# fanotify 单文件权限裁决实验

fanotify 已作为对象编入统一 secmon 主服务。本文使用 `secmon --fanotify-only` 诊断模式单独研究权限门，不加载本次进程的 BPF；正常部署直接使用 secmon 加共用配置即可同时启用两个模块。实验范围为本机内核与文件系统上的同步权限裁决、对象身份、有界等待队列及退出行为。

## 运行

先创建仅用于实验的文件，在一个终端启动裁决程序：

```bash
printf 'demo\n' > /tmp/secmon-fanotify-demo
sudo ./build/secmon --fanotify-only --file /tmp/secmon-fanotify-demo --decision deny --run-for 20
```

看到 `Fanotify active` 后，在另一个终端运行：

```bash
cat /tmp/secmon-fanotify-demo
```

`deny` 时打开返回 EPERM；改用 `--decision allow` 则允许打开。默认立即回复，可通过下述参数模拟延迟分析。需要 CAP_SYS_ADMIN、内核 fanotify 权限事件支持及支持该标记的文件系统。程序会报告初始化或标记失败，不静默切换成纯观察模式。

必须显式提供文件、裁决和 1..3600 秒运行时长。Ctrl+C/SIGTERM 或内部期限使程序关闭组并退出；正常退出输出 JSON 统计，如 `{"allowed":0,"denied":1,"overflow":0}`。输出还包含 `timed_out`、`overloaded`、`shutdown_denied` 和 `peak_pending`。前三项是回复原因的子集计数，不应再加到 allowed/denied 总量中；`peak_pending` 表示用户态待裁决队列峰值，不包含内核尚未投递的事件。统计表示已成功写入的权限回复数量，不表示系统调用最终成功次数。其他安全模块仍可能拒绝已被本程序允许的操作。

## 按代码研究

| 文件 | 阅读内容 |
| --- | --- |
| `src/service.cpp` / `src/fanotify/monitor.cpp` | 共用信号/运行期限/管理和主循环；权限门对象管理与结束统计 |
| `src/fanotify/options.h/.cpp` | 参数及边界校验 |
| `src/fanotify/event_kind.h/.cpp` | 打开、读取、执行打开事件的显式选择 |
| `src/fanotify/decisions.h/.cpp` | 截止时间、容量回退、队列与事件 FD 所有权 |
| `src/fanotify/gate.h` | 文件句柄与组的所有权、最小处理接口 |
| `src/fanotify/gate.cpp` | 固定 inode、创建权限组、标记、poll/read、回复与事件 FD 释放 |
| `tests/decisions.cpp` | 可控时钟下的截止时间与资源所有权测试 |
| `tests/fanotify.py` | 临时文件、外部打开进程、并发请求、服务崩溃和恢复实验 |
| `tests/fanotify_events.py` | 读取与直接执行的覆盖边界 |
| `tests/fanotify_deferred.py` | 真实权限等待、超时、容量和带待裁决请求的退出 |
| `tests/fanotify_soak.py` | 持续并发负载、进程 FD 上限与回复计数对账 |
| `tests/fanotify_harness.py` | 共享的进程启动、就绪等待和清理 |

`O_PATH | O_NOFOLLOW` 固定一个普通文件，拒绝末尾符号链接、目录和不存在的文件。通过 `/proc/self/fd/N` 对固定的对象设置 inode mark，避免重新解析原始路径。硬链接共享策略，文件重命名后策略跟随对象，原路径替换成新 inode 则不受该标记约束；文件描述符固定期间不会出现目标 inode 被回收复用。

组采用 `FAN_CLASS_CONTENT | FAN_NONBLOCK | FAN_CLOEXEC`，默认请求 `FAN_OPEN_PERM`，也可通过 `--event` 单独选择读取或执行打开事件。不使用 `FAN_REPORT_*`，按固定大小的 metadata 一次读取一个事件，每个事件 FD 通过 RAII 关闭。校验 ABI 后把 FD 所有权转交 `PendingDecisions`，立即或到期写入 `FAN_ALLOW`/`FAN_DENY`，成功回复才增加计数并释放 FD。静态/模拟延迟模式不读取文件内容。也可启用 [独立内容分析组件](ANALYSIS_WORKER.md)，由子进程扫描传递的事件 FD，接收端不重新打开目标。

## 三种权限入口

`--event open|access|exec` 每次选择一种事件，默认 `open`：

| 选择 | 内核事件 | 已验证的边界 |
| --- | --- | --- |
| open | `FAN_OPEN_PERM` | 新增打开受控；已打开 FD 的读写不重新裁决 |
| access | `FAN_ACCESS_PERM` | 普通 read 受控，包括服务启动前已打开 FD；仅 open、写入、mmap 访问不受此事件控制 |
| exec | `FAN_OPEN_EXEC_PERM` | ELF 或脚本直接执行受控；普通读取及 `/bin/sh script.sh` 解释读取不触发脚本的执行打开裁决 |

执行打开权限事件不能代表脚本内容的完整执行控制；读取权限事件也不覆盖所有数据访问方式。三种事件的结果均受原有文件权限与其他安全模块约束，不能当作完整保险箱。

```bash
sudo ./build/secmon --fanotify-only --file /absolute/path/test-file --event access --decision deny --run-for 20
sudo python3 tests/fanotify_events.py --build-dir build
```

正常统计通过 `permission_event` 字段标明本次选择，便于区分打开回复与读取回复。

## 延迟、截止时间和容量

```bash
sudo ./build/secmon --fanotify-only --file /absolute/path/test-file --decision allow --run-for 20 \
  --decision-delay-ms 1000 --request-timeout-ms 100 \
  --timeout-decision deny --max-pending 4 --overload-decision deny
```

这个示例模拟需要 1000 ms 才能给出的 allow 策略，但已接收事件在 100 ms 后超时，因此回复 deny。延迟只是受控实验值，此模拟模式不调用分析进程；真实内容分析需显式选择 analyzer 模式，两者不能同时启用。

| 参数 | 默认值 | 范围/含义 |
| --- | --- | --- |
| `--decision-delay-ms` | 0 | 0..60000，模拟策略结果就绪时间 |
| `--request-timeout-ms` | 250 | 1..60000，从用户态收到事件起计算 |
| `--max-pending` | 64 | 1..4096，用户态已接收且未回复的事件数量 |
| `--timeout-decision` | deny | 截止时间到达后的 allow/deny |
| `--overload-decision` | deny | 用户态队列满后的立即 allow/deny |

每次循环先回复到期请求，poll 等待时间取主循环预算和最近截止时间的较小值。新事件到来前也先处理已到期的队列条目，腾出容量。唤醒时若请求已经超时，超时优先于原策略，包括恰好同时到期和调度迟到跨过两个时间点的情况。

这是事件接收后的用户态期限，不涵盖此前在内核队列中等待的时间。它依赖进程得到调度，不是实时保证。所有请求共享实验参数，因此接收 FIFO 也就是到期顺序；以后引入每请求不同的分析时间时，必须重新选择调度结构。

## 覆盖与故障语义

- 每次仅覆盖选择的权限入口，不裁决每次 write，不撤销 FD 或已有映射，也不提供删除、重命名、属性修改保护。默认 open 模式下已有 FD 读写继续成功；access 模式则会裁决已打开 FD 的普通读取。
- 一次接收一个事件，用户态队列显式有界，队列满则立即执行容量回退；内核另有独立有界队列，使用系统默认上限，不请求无限队列。
- 检测到 `FAN_Q_OVERFLOW` 时增加计数并以失败退出；ABI、读取或回复异常也报告失败并关闭组。这是可观察的退出策略，不能保证队列满时继续拒绝全部访问。
- 正常 SIGINT/SIGTERM 或内部期限退出时，先对已投递到用户态队列的请求回复 deny，再关闭组。关闭或崩溃会移除标记，内核尚未投递或故障时尚未回复的请求会放行；不能把正常退出的用户态队列排空理解成全局原子拒绝。故障后没有持久拒绝承诺。
- 每次 poll 最多等待 100 ms，并受最近请求截止时间约束，循环检查内部期限与退出信号；持续到达事件时也会检查。没有独立 watchdog 或调度暂停期间的截止保证，SIGSTOP 会暂停裁决。
- 当前没有进程身份授权、真实恶意内容检测、权限缓存、递归目录保护，也未接入 BPF、自保护和管理 socket。

权限事件与关闭组的语义参考 [Linux fanotify(7)](https://man7.org/linux/man-pages/man7/fanotify.7.html)，标记接口参考 [fanotify_mark(2)](https://man7.org/linux/man-pages/man2/fanotify_mark.2.html)。

## 验证结果

```bash
sudo python3 tests/fanotify.py --build-dir build
sudo python3 tests/fanotify_deferred.py --build-dir build
sudo python3 tests/fanotify_soak.py --build-dir build --duration 30 --mode policy
sudo python3 tests/fanotify_soak.py --build-dir build --duration 30 --mode timeout
```

2026-10-17 在当前开发机运行通过：允许/拒绝、硬链接、未标记文件、已有 FD 读写、两种模式各 24 个并发打开请求、精确回复计数、正常停止解除策略、重命名与原路径替换、内部期限、拒绝非法目标。

崩溃测试先 SIGSTOP 监听者，启动一个打开请求并确认它尚未退出，再 SIGKILL 监听者，确认打开请求被释放且后续打开成功。此测试验证服务故障放行，不代表生产故障隔离能力。

本轮未触发真实队列溢出、未验证跨文件系统/挂载命名空间及与其他 fanotify 监听者的组合，也未验证真实攻击检测。已新增确定性截止时间和 FD 所有权测试、真实延迟/超时回退与容量回退测试；持续负载结果单独记录在 DESIGN 中。后续仍需在隔离环境验证真实内核队列溢出，并设计独立分析组件与调度暂停后的故障策略。
