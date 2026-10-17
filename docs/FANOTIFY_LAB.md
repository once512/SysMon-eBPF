# fanotify 单文件权限裁决实验

这是独立的 `secmon-fanotify` 可执行程序，不会加载 BPF，也不会修改 `secmon` 的现有策略。目标是先验证本机内核与文件系统上的同步权限裁决、对象身份及退出行为，作为后续裁决队列的实验基础。

## 运行

先创建仅用于实验的文件，在一个终端启动裁决程序：

```bash
printf 'demo\n' > /tmp/secmon-fanotify-demo
sudo ./build/secmon-fanotify --file /tmp/secmon-fanotify-demo --decision deny --run-for 20
```

看到 `Fanotify active` 后，在另一个终端运行：

```bash
cat /tmp/secmon-fanotify-demo
```

`deny` 时打开返回 EPERM；改用 `--decision allow` 则允许打开。需要 CAP_SYS_ADMIN、内核 fanotify 权限事件支持及支持该标记的文件系统。程序会报告初始化或标记失败，不静默切换成纯观察模式。

必须显式提供文件、裁决和 1..3600 秒运行时长。Ctrl+C/SIGTERM 或内部期限使程序关闭组并退出；正常退出输出 JSON 统计，如 `{"allowed":0,"denied":1,"overflow":0}`。统计表示已成功写入的权限回复数量，不表示系统调用最终成功次数。其他安全模块仍可能拒绝已被本程序允许的操作。

## 按代码研究

| 文件 | 阅读内容 |
| --- | --- |
| `src/fanotify/main.cpp` | 参数、信号、运行期限、关闭组后输出统计 |
| `src/fanotify/gate.h` | 文件句柄与组的所有权、最小处理接口 |
| `src/fanotify/gate.cpp` | 固定 inode、创建权限组、标记、poll/read、回复与事件 FD 释放 |
| `tests/fanotify.py` | 临时文件、外部打开进程、并发请求、服务崩溃和恢复实验 |

`O_PATH | O_NOFOLLOW` 固定一个普通文件，拒绝末尾符号链接、目录和不存在的文件。通过 `/proc/self/fd/N` 对固定的对象设置 inode mark，避免重新解析原始路径。硬链接共享策略，文件重命名后策略跟随对象，原路径替换成新 inode 则不受该标记约束；文件描述符固定期间不会出现目标 inode 被回收复用。

组采用 `FAN_CLASS_CONTENT | FAN_NONBLOCK | FAN_CLOEXEC`，仅请求 `FAN_OPEN_PERM`。不使用 `FAN_REPORT_*`，按固定大小的 metadata 一次读取一个事件，每个事件 FD 通过 RAII 关闭。校验 ABI 后写入 `FAN_ALLOW` 或 `FAN_DENY`，成功回复才增加计数。期间不读取文件内容、不再次打开目标，不调用外部分析程序。

## 覆盖与故障语义

- 只裁决新增打开，不裁决每次 write，不撤销已打开的 FD 或已有映射，也不提供删除、重命名、属性修改保护。已有 FD 读写继续成功是预期边界。
- 一次立即回复一个事件，用户态没有分析等待队列；内核仍有有界队列，使用系统默认上限，不请求无限队列。
- 检测到 `FAN_Q_OVERFLOW` 时增加计数并以失败退出；ABI、读取或回复异常也报告失败并关闭组。这是可观察的退出策略，不能保证队列满时继续拒绝全部访问。
- 关闭或崩溃会移除组的标记，并放行该组尚未回复的权限请求。故障后没有持久拒绝承诺。
- 每次 poll 最多等待 100 ms，循环检查内部期限与退出信号；持续到达事件时也会检查。这里没有单请求超时、独立 watchdog 或调度暂停期间的截止保证；SIGSTOP 会暂停裁决。后续引入分析必须另行设计超时和并发预算。
- 当前没有进程身份授权、内容检测、权限缓存、递归目录保护或执行打开专用策略，也未接入 BPF、自保护和管理 socket。

权限事件与关闭组的语义参考 [Linux fanotify(7)](https://man7.org/linux/man-pages/man7/fanotify.7.html)，标记接口参考 [fanotify_mark(2)](https://man7.org/linux/man-pages/man2/fanotify_mark.2.html)。

## 验证结果

```bash
sudo python3 tests/fanotify.py --build-dir build
```

2026-10-17 在当前开发机运行通过：允许/拒绝、硬链接、未标记文件、已有 FD 读写、两种模式各 24 个并发打开请求、精确回复计数、正常停止解除策略、重命名与原路径替换、内部期限、拒绝非法目标。

崩溃测试先 SIGSTOP 监听者，启动一个打开请求并确认它尚未退出，再 SIGKILL 监听者，确认打开请求被释放且后续打开成功。此测试验证服务故障放行，不代表生产故障隔离能力。

本轮未触发真实队列溢出、未验证跨文件系统/挂载命名空间及与其他 fanotify 监听者的组合，也未验证真实攻击检测。后续应在隔离环境中设计可复现的队列压力与单请求超时实验，再接入耗时分析。
