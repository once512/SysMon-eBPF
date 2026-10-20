# 请求方 pidfd 与进程生命周期身份

`--requester-pidfd` 是启动时显式开启的审计能力，要求 `--audit-permissions` 和实际启用 fanotify。默认关闭；不是策略文件字段，在线重载不会修改组格式。内核不支持 `FAN_REPORT_PIDFD` 时启动失败，不静默改成按数字 PID 查询。

```sh
sudo ./build/secmon --policy /absolute/policy.conf --audit-permissions --requester-pidfd
```

管理 JSON 的 `requester_pidfd` 表示启用了该模式，不保证每次请求都能取得引用。flag 位 32 表示启用引用；当前管理协议为多目标订阅引入的 v4/360 字节布局，客户端和服务端使用同一构建。

## 引用从哪里来

fanotify 组开启 FAN_REPORT_PIDFD，内核在事件 metadata 后附加一个 pidfd 记录。服务不调用 `pidfd_open(metadata.pid)`，也不查询 `/proc/<requester_pid>` 来重建身份。解码器只接受本组启用的固定布局：24 字节 metadata，或 metadata 加 8 字节 PIDFD 附件；每次读取最多一个事件。内核事件 FD 和 pidfd 分别由 RAII 对象持有，验证失败时回收已接管句柄并关闭服务，不跳过未知附件继续裁决。

接收时检查 pidfd 的 fstat/fstatfs，只有确认 PID_FS_MAGIC 且 inode 非零时才记录进程 inode。只使用 FD 本身，不解析路径。pidfd 随对应的 pending 请求保存，静态答复、分析结果、超时、容量回退、分析错误、正常停止和析构均关闭它。分析器只接收目标文件 FD，不接收请求方 pidfd。容量仍以请求数计；每个启用引用的请求最多多持有一个 FD，另有正在接管事件的瞬时预算。

新增权限审计字段仅在开启本模式时出现：

| 字段 | 含义 |
|---|---|
| requester_reference | present / unavailable / error，描述接收时的内核引用，不表示回复时仍存活 |
| requester_process_inode | 经过 pidfs 验证的进程 inode；无法建立身份时为 0 |
| requester_identity_errno | 本地 fstat/fstatfs 的错误或不支持 pidfs 的 EOPNOTSUPP；不是内容扫描 errno |

`unavailable` 对应 FAN_NOPIDFD，包含监听器不可见的外层请求等情况；`error` 对应 FAN_EPIDFD，内核没有提供细分 errno，因此不伪造具体错误。两者 inode/identity_errno 都为 0。`present` 表示收到句柄，若本地验证失败则 inode=0、identity_errno 非零。0 不能用作身份关联键。

本模式用于审计，不把引用缺失改成新的授权或拒绝条件；仍执行原来的静态/扫描及超时/容量回退策略。身份错误和分析器错误分别编码。

## 与 BPF 的关联范围

BPF 事件 ABI 更新为 5，exec_check、exec_success、file_denied、self_denied 都增加 `process_inode`：读取当前任务 signal->pids[PIDTYPE_TGID] 的 pidfs inode，而不是实际 worker 的线程 PID。CO-RE 检查字段存在性，不可用时输出 0；旧事件布局不混用解码。

在已验证的 x86_64 开发内核 `6.12.0-211.61.1.el10_2.x86_64`，同一进程的 pidfd fstat inode、fanotify requester_process_inode 和 BPF process_inode 一致，并覆盖宿主/子 PID namespace、线程重建、主线程 exec、非主线程 exec、主线程单独退出。其他内核、架构、pidfs 版本不能仅凭头文件存在就认定已验证。

同一机器、同一次 boot、已验证 pidfs 环境中，两个非零值相等可将记录关联到同一进程生命周期。采集端必须保留机器和 boot 上下文。该键不区分实际操作线程，也不认证代码、凭证或恶意意图；进程 exec 后身份可能保持，而执行内容已改变。BPF 的 tid/start_ns 仍用于任务生命周期。两类记录没有共同操作 ID，因此同进程关联不等于同一次系统调用。

pidfd 只保留到本次请求结束。JSON 中的 inode 是历史身份说明，不是仍持有的可操作句柄；不能根据它重新打开数字 PID 并声称等价。当前没有启用自动发信号、隔离或身份授权。

## 实验与复现

```sh
ctest --test-dir build --output-on-failure
sudo python3 -B tests/requester_pidfd.py --build-dir build
sudo python3 -B tests/requester_lifecycle.py --build-dir build --report /tmp/requester-lifecycle.json
sudo python3 -B tests/identity_threads.py --build-dir build --requester-pidfd
sudo python3 -B tests/permission_namespace.py --build-dir build --requester-pidfd
sudo python3 -B tests/management_soak.py --build-dir build --duration 30 --combined \
  --audit-permissions --requester-pidfd --verify-audit-output --backend analysis --event access
```

无特权 ownership 测试使用自身 pidfd 和可控 FD，核对未对齐数据、畸形附件、两种 sentinel、非 pidfs 句柄不产生身份、各完成/异常路径的关闭。真实权限专题覆盖请求方中途退出、容量、停止、超时、分析成功/错误、直接执行；还临时收紧本次监听器 FD soft limit，实际触发 FAN_EPIDFD，恢复后验证回到基线。

生命周期专题保持进程引用穿过 exec 和 leader 退出；整个线程组退出前引用不可读，全部退出后可读，向旧引用发信号 0 返回 ESRCH。它不强制复用真实宿主 PID 数字。反向 namespace 专题确认外层请求仍为 PID=0/unavailable，不做猜测性补全。默认 runner 同时覆盖关闭和开启 pidfd 的线程、namespace 及背压变体。

接口参考：[Linux fanotify 实现](https://github.com/torvalds/linux/blob/v6.12/fs/notify/fanotify/fanotify_user.c)、[上游 pidfs 实现](https://github.com/torvalds/linux/blob/master/fs/pidfs.c)。上游设计参考不能替代本机内核及发行版回移的实际验收。
