# 独立 FUSE 虚拟诱饵视图

`secmon-decoyfs` 提供一个没有真实业务文件后端的合成目录。固定的 1..64 个普通文件各有 4096 字节确定内容，只存在于进程内存和内核缓存中，不创建磁盘诱饵文件。它是视图提供组件；文件选择、进程身份、拒绝、限时响应及解除仍使用现有 secmon 策略，没有新增安全控制协议、BPF Map 或事件 ABI。

这交付最初规划中的第一版虚拟诱饵，不代表通用勒索分类器、业务目录透明注入或生产诱饵管理。文件名可配置，内容是明确的合成文本，没有伪装成真实 Office/PDF 文档；攻击者可以识别或跳过本视图。

## 构建和运行合同

当前开发机使用 libfuse3 3.16.2；安装 `fuse3-devel` 后按原方式构建，会额外生成 `secmon-decoyfs`。关闭视图可使用 `-DSECMON_BUILD_DECOYFS=OFF`，核心服务仍可独立构建。普通 CTest 只检查不挂载的参数拒绝，真实 FUSE 测试单独执行。

```bash
sudo dnf install fuse3-devel
cmake -S . -B build
cmake --build build -j
```

视图始终前台运行，接受一个绝对、规范化、已有、空的挂载目录。目录必须属于启动者，不能有组/其他用户写权限，不接受末尾或父路径符号链接、已有挂载、重复文件名、超过 64 个名字或不在 ASCII 字母/数字/点/下划线/横线集合中的名字。文件名最长 255 字节，排除 `.` 和 `..`。不要在正在被其他主体修改的路径命名空间部署；准备检查与系统 mount 之间不是全局原子操作。

root 为普通用户提供可见的测试视图示例：

```bash
sudo install -d -m 0755 /run/secmon-decoy-view
sudo ./build/secmon-decoyfs --mountpoint /run/secmon-decoy-view \
  --file accounts.csv --file notes.txt --allow-other
```

保持该进程运行，在另一终端完成可用性检查，再启用安全策略：

```bash
stat /run/secmon-decoy-view/accounts.csv
sha256sum /run/secmon-decoy-view/accounts.csv
```

将以下内容存为 root 独占修改、权限 0600 的现有策略文件。需要安全管理 socket 时，父目录仍须满足现有 root 私有目录合同。

```text
revision 1
canary "/run/secmon-decoy-view/accounts.csv"
canary "/run/secmon-decoy-view/notes.txt"
canary-response 1 30000
```

```bash
sudo ./build/secmon --policy /absolute/root-owned-policy --control /absolute/root-private-directory/control
```

`--allow-other` 只能由 root 显式开启，未开启时按 FUSE 默认限制访问者。挂载固定使用 `default_permissions,nodev,nosuid,noexec`。普通用户也可以挂载自己的私有视图，用于不含 root 安全服务的文件系统验证；不能据此假定 root 会自动绕过 FUSE 的挂载访问限制。

## 内容、权限与判定

目录元数据的模式是 0777，文件是 0666，目的是让普通用户的修改意图进入 LSM 检查点，避免先在 DAC 阶段被拒绝而无法触发诱饵规则。**实际没有可写文件能力**：写打开、内容写入、截断、权限/属主变化、删除、改名、硬链接、扩展属性、创建目录/新文件等回调都拒绝，未知 ioctl 返回 ENOTTY。这个视图不会代写任何业务对象，也不提供透传后端。

- 安全服务未启动：视图本身仍拒绝修改，但不会限制请求者对其他文件的操作。
- 对象作为 `canary` 激活：现有 BPF 钩子按实际设备号/inode 拒绝修改并发布限时 TGID 响应；FUSE 不向安全服务发送 PID，也不参与身份授权。
- 读取、查询、普通索引及备份不触发响应；未被选中的同目录文件仅受视图的不可修改合同约束，不自动成为 canary。
- 未知 ioctl 的 BPF 拒绝仍不作为修改证据。已分类修改 ioctl、xattr/ACL 等继续遵循[元数据合同](FILE_METADATA.md)。
- 视图 bytes 和 inode 编号在同一挂载内固定，不复用 inode。查找/属性回复不建立长期属性缓存；内容缓存可保留，因为没有修改路径。没有每请求同步日志，输出消费者不能拖住 FUSE 回调。
- 这不是加密保险箱：没有敏感文件后端，但也不保证堆内存、交换空间或读取副本的机密性。

## fanotify 联合运行

当前开发内核已验证虚拟 inode 可用于现有 `fanotify-event open` 与 `access` 的权限等待、延迟 allow、deny、逐请求审计和 requester pidfd。它不需要额外的 FUSE 专用安全通道。一次命令可能产生多个权限事件：例如 `cat` 的最终 EOF 读取也可经过 access gate，不能把事件数量当作恶意或命令数量。

同一视图里的事件来自原始访问者，而不是把视图提供进程当作实际修改者。受测场景分别核对实际 inode、BPF TGID inode 和权限请求引用；这不扩大原有 namespace、线程身份与时间坐标合同。fanotify 当前仍执行配置判定，不会仅因另一个进程触发诱饵就自动改变一个已等待读取的结论。

## 卸载、重挂载和故障

建议顺序：授权停止安全服务，退出测试访问者，再终止视图提供进程或 `fusermount3 -u MOUNTPOINT`。没有后台 daemon；正常信号处理会退出循环并卸载。持有 O_PATH/文件 FD 时，普通卸载可能返回 EBUSY。管理者执行 lazy detach 是异常操作，不作为正常部署的自动恢复方式。

**同一路径重挂载不是同一文件对象。** 活动策略仍固定旧挂载的 inode，新视图在显式更高 revision 重载成功前没有 BPF canary 响应；不可修改的 FUSE 回调不能掩盖这个保护空档。更高 response epoch 可同时显式解除旧进程的限制。禁止把新旧挂载只按路径拼接。

已验证提供进程被杀后，新路径访问报错；已经发布的 BPF 响应不因提供进程死亡或 lazy detach 解除。提供进程死亡时准备新策略失败，保留原策略及 epoch。缓存/持有引用不保证一律立即报错；其内容也不会落到目录下的另一份真实文件。

当前没有把提供进程纳入安全服务自保护，没有自动启动、死亡监控、挂载健康状态、自动重建或策略重新绑定。提供进程暂停可能让访问、路径准备或取属性等待于 FUSE；已在本机实测暂停约501ms时，重载及随后status都等待，恢复后完成。该问题尚未修复。主循环同步准备策略时不能同时推进其他管理请求；fanotify超时也不能为所有这些VFS阶段提供期限。需要监督与健康检查后才能部署为生产能力。root/挂载命名空间管理者仍可改变可见性。

已有共享映射、在途 I/O、预先存在的其他进程、服务重启以及响应期限的边界，继续遵循[现有 canary 合同](CANARY_RESPONSE.md)。只验证了本合成视图，不据此声明任意 FUSE 文件系统、overlay 或 NFS 已完整覆盖。

## 验证入口

```bash
ctest --test-dir build --output-on-failure
# 不需要 BPF/root，但需要 /dev/fuse 与 fusermount3 可用
python3 -B tests/decoy_view.py --build-dir build
# 顺序加载临时 BPF/fanotify；只在开发机执行
sudo python3 -B tests/run_privileged.py --only \
  virtual-view virtual-response virtual-lifecycle virtual-fanotify
sudo python3 -B tests/virtual_decoy_soak.py --build-dir build \
  --duration 1800 --artifact-dir /absolute/new-artifact-directory
```

持续验证使用单视图 64 个虚拟文件、单联合服务和 8 个原生访问者，交替 root/普通 UID，循环九类修改、未知 ioctl 反例、权限读取、失败重载、显式解除及自动到期。保存原始审计、逐轮日志、身份、代码/构建摘要与 FD 计数；正式结果及已知失败以日期验收文档为准。

持续工具还为监控服务设置运行时长加120秒的内部期限，并在SIGTERM/SIGHUP时走上下文清理，拒绝覆盖已有证据目录。这些措施依赖主循环和清理路径能够推进，不是强制取消任意FUSE/VFS等待的保证。


2026-10-23后续增量已隔离重载的候选对象准备，BPF-only及健康本地权限目标场景中status/stop可推进，约2秒失败保留旧策略。但暂停FUSE本身的fanotify事件路径仍可阻塞，监督与自动重绑定尚未完成，见[准备合同](BOUNDED_PREPARATION.md)。前面的“未修复”描述对应首版阶段，不据此扩大后续增量范围。


随后静态fanotify事件读取/真实事件FD关闭也已隔离，暂停FUSE期间管理与已交付旧请求期限可推进；内容分析模式仍未迁移，读取者队首阻塞、未交付审计及不可中断内核等待见[静态事件读取合同](STATIC_EVENT_READER.md)。
