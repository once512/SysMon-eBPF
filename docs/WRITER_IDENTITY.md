# 按执行对象授权文件修改

这是 BPF 文件只读策略的受限授权原型。配置 v3 可以为固定的程序 inode 和有效 UID 授予修改 `protect` 对象的例外。它提供可验证的对象匹配、在线撤销与程序对象保护；完整可信应用识别还需要内容认证、加载链与运行上下文约束。

```text
version 3
revision 1
protect "/srv/secmon-demo/data"
allow-writer "/opt/secmon-demo/writer" 65534
```

继续使用 `secmon --policy FILE --self-protect SOCKET` 启动，用 `--reload SOCKET` 更新。没有 `allow-writer` 时保留原来的全任务只读行为。最多 256 条 `protect` 和 64 条 `allow-writer`；同一程序只能配置一个有效 UID。此阶段所有 writer 都可修改本份策略的所有普通 protect 对象，没有按目标或操作划分权限。

`allow-writer` 要求双引号绝对路径，UID 是 0..4294967294 的十进制数。程序必须是 root 所有、组/其他用户不可写、至少有一个执行位的普通文件；末尾符号链接拒绝。不同路径若指向同一个 inode，可重复指定相同 UID，冲突 UID 拒绝整个候选。该检查不要求 ELF：脚本路径可以被选择，但普通 shebang 执行后的实际执行对象是解释器，因此脚本 inode 本身不会使它获得授权。

## 从内核模块思路理解

宿主以 `O_PATH` 打开路径，使用 `fstat` 得到设备主次号和 inode，并保存 FD。路径只负责首次选择，FD 固定对象以避免 inode 回收复用；不读取程序内容，不获取 SHA-256。已有配置来源 SHA-256 仍只代表配置原始字节。

`src/writer_identity.h/.cpp` 负责固定和检查；`src/file_policy.cpp` 将两类对象合入同一个 HASH Map。value 包含只读、writer、身份保护三个标志和 writer EUID。最多 320 个不同 inode，宿主按路径分别持有最多 320 个 FD；保护路径和 writer 路径重合时合并标志。

`eBPF/writer_identity.bpf.c` 在敏感操作发生时，通过 CO-RE 读取当前 `task->mm->exe_file->f_inode`，查询同一份策略中的 writer，再比较 `task->cred->euid.val`。这里的 UID 是内核全局 kuid 坐标，不能直接当作容器内显示的 UID。没有使用 `comm`、argv、PID 缓存或 `/proc/PID/exe` 路径字符串。

| 情况 | 结果 |
| --- | --- |
| 同一程序经已有硬链接或改名后的路径执行，EUID 匹配 | 普通 protect 对象允许通过本层检查 |
| 普通 fork 后仍执行同一程序 | 持续按当前对象和 EUID 检查 |
| exec 成另一个未授权程序 | 下次操作拒绝，不永久继承父进程授权 |
| 未授权程序 exec 成授权程序 | 下次操作可以匹配授权 |
| 程序相同，EUID 不同 | 拒绝；root 没有隐式例外 |
| 原路径指向新 inode，即使新文件字节完全相同 | 不自动继承授权；需管理员发布并应用新策略 |
| 修改、删除、重命名或新建硬链接指向授权程序 inode | 拒绝，包括授权程序自身发出的请求 |
| 其他 LSM、DAC 或挂载规则已拒绝 | 本策略的例外不能覆盖其拒绝 |

授权程序 inode 自动受到现有文件保护钩子的只读限制，即使它没有出现在 `protect` 中。保护程序代码的检查优先于 writer 例外，因此 writer 不能经已覆盖入口修改自己的授权 inode。程序升级应通过管理策略撤销/重新选择对象；父目录不递归保护，不能把路径一直存在当作保证。

## 更新与撤销

候选包含目标和 writer 全部 inode，完整准备后一次替换外层 Map 引用。路径缺失、程序权限不合格、冲突 UID、Map 准备失败都会保留旧版本的保护、授权及固定 FD。重载成功后新进入检查的操作使用新策略，在途 BPF 检查可能继续用旧快照；这不是系统调用屏障。

移除 writer 后，它的自动身份保护一起解除；若同一 inode 还在 `protect` 中，则继续按普通只读对象保护。已有打开的写 FD 仍经过普通 `file_permission` 检查。授权期间已建立的共享可写映射无法靠撤销这条规则追回，已覆盖钩子以外的异步/文件系统专用写路径也未完整验证。

管理 v2 的 `protected_paths` 只计算显式 `protect` 路径，不包含 writer 自动保护的对象；活动版本与配置摘要能核对配置来源，尚不能列出当前内核对象授权表。

## 可信边界

把通用 shell、Python、动态链接器或可以执行任意输入的程序列为 writer，会使该程序承载的代码具有同样例外。动态库、插件、环境变量、代码注入、打开的句柄传递和运行时数据都没有被这项对象匹配认证。此阶段没有受信的子进程策略，只按每次操作时的实际 exe 与 EUID 重新判断。

程序启动前已有的共享可写映射、权限检查到首次 attach 之间的竞态、文件系统自身可信度、解释器链、内容签名和跨重启连续保护尚未解决。高权限管理员还可以改变进程执行文件标识或卸载 BPF；这不是对宿主 root/内核失陷的隔离边界。fanotify 不消费 writer 授权，即使 BPF 放行，独立 fanotify 层仍可拒绝。

## 验证与阅读

```bash
ctest --test-dir build --output-on-failure
sudo python3 tests/run_privileged.py --build-dir build --only writer-identity policy-reload policy-layers
```

`tests/writer_scenario.cpp` 是专用原生程序，避免将系统解释器加入授权。`tests/writer_identity.py` 在临时目录中验证对象/EUID、fork/exec、硬链接、同名替换、程序只读、错误候选回滚、FD 回收和撤销。所有授权在临时 BPF 宿主退出后解除，不安装持久策略。
