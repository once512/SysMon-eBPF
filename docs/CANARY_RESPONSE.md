# 显式诱饵修改响应

本功能适用于管理员明确保证“这个文件不应被修改”的真实诱饵。修改尝试被 LSM 拒绝后，同一线程组在有限期限内受到普通文件修改、创建任务和 exec 限制。读取诱饵不触发，普通 protect/vault 拒绝不触发。它提供一个可解释的在线响应闭环，不是通用勒索软件分类器；已有[独立 FUSE 虚拟诱饵最小版](VIRTUAL_DECOYS.md)，生产诱饵管理仍待实现。

## 配置与解除

```text
revision 1
canary "/absolute/path/trap.docx"
canary-response 1 30000
```

`canary` 选中一个已存在的普通文件，使用现有 O_PATH 固定及设备/inode 匹配。protect、vault、canary 共用最多 256 路径预算。硬链接和 bind 别名指向同一对象；路径替换不会自动迁移策略。canary 不能与 vault 指向同一 inode，也不能成为 allow-writer 的目标，别名同样检查。

`canary-response EPOCH DURATION_MS` 为策略级响应配置；正整数 EPOCH 是本服务实例内的解除代际，时长为 100..3600000 毫秒。首次命中从内核全局 CLOCK_BOOTTIME 计时，包含系统挂起时间。并发命中或持续拒绝不延长当前期限；到期后再次修改诱饵会开启新期限。各进程分别计时。

普通更高 revision 重载、字段重排、失败候选均不会解除或续期。保持 EPOCH 时不能改变时长。需要立即解除旧限制时，提交更高 EPOCH：

```text
revision 2
canary "/absolute/path/trap.docx"
canary-response 2 30000
```

更高 EPOCH 使旧代际失效，保留诱饵便能对下一次修改重新响应。仅移除 canary 行而保留响应配置不会解除已触发的限制；移除响应配置且移除全部 canary 可解除。在同一实例重新启用时必须使用更高 EPOCH，已退休的编号不能复用。候选失败不消耗编号。EPOCH 最大值激活后，需重启服务才能再次推进编号。

通过现有 `--policy`、`--control` 和 `--reload` 部署，无第二个服务或新增控制命令。fanotify-only 模式拒绝该配置；联合模式仍复用既有协调器，fanotify 不承担本规则的判定。已有延迟/分析 permission gate 的语义不变。

## 内核执行范围

- 同次钩子先发布该线程组的响应状态，再以 EACCES 拒绝触发操作；动作不等待用户态消费审计，ring buffer 满也不会放行该操作。
- 扩展属性、ACL 和已分类修改 ioctl 同样触发；活动响应期间普通文件的全部 ioctl 拒绝，未触发时未知 ioctl 仅保守拒绝选中对象、不判为攻击。具体授权和已测 I/O 见[补充范围](FILE_METADATA.md)。
- 普通文件的已有写 FD、新可写打开、普通写权限检查、截断、删除、重命名、硬链接、setattr、新共享可写映射及共享映射增加写权限纳入限制。未列入保护集合的普通文件也受限制；已有 writer/vault 授权不能绕过响应。
- 已存在的其他线程共享状态；其余进程和触发之前已有的子进程不继承状态。fork/clone（包括创建新线程）和 exec 在后续检查点拒绝。已通过检查的在途操作不能被追溯撤销。
- 保留普通读取、私有映射及管道/socket I/O；不向进程发送 SIGSTOP、SIGKILL，也不把用户态 PID 数字用于响应。
- 身份使用当前内核 pidfs 的 TGID inode，跨线程、PID namespace 保持同一坐标；取得不到身份时显式报告响应失败，不猜测数字 PID。最后一个线程退出后删除状态，主线程提前退出时继续保留。

发布响应与拒绝触发操作属于同次钩子执行，但跨 CPU/线程没有“同时停止所有系统调用”的屏障；另一线程可能已完成权限检查。新 epoch 切换后，持有旧策略快照的在途钩子仍可按旧快照返回拒绝。旧代际不能覆盖已创建的新代际状态。

## 容量、审计与状态

响应为独立的有界 HASH，最多 4096 个线程组条目，不使用 LRU 淘汰；活动或已过期但仍存活的进程会占用条目，退出才回收。表满或身份缺失时，诱饵修改仍拒绝，但不得声称其他文件已经受到响应限制：`response_failed` 增加，审计带失败标志。此失败策略目前为显式降级，尚无系统级紧急响应或自动容量回收。

BPF 事件 ABI 为 8；主程序与 skeleton 同包升级。`file_denied` 新增：

- `canary_hit`、`response_started`、`response_blocked`、`response_failed`；
- `response_epoch`、`response_deadline_boot_ns`。

创建任务和 exec 被拒绝时输出 `process_response_denied`，操作号分别为 14、15，包含 pid/tid、start_ns、process_inode、代际、期限及 errno=13。审计丢失仍可发生，不能将缺少事件解释为未触发。

管理布局为同包 v9/472 字节。BPF 状态增加 `canary_paths`、`response_epoch`、`response_duration_ms`，以及累计 `response_started`、`response_failed`、`response_denied`。这些是累计内核计数采样，不是当前受限进程数；采样跨 CPU 不是原子快照。配置关闭后累计值保留。stderr 定期输出同名计数。

策略内层为 337 项、408 字节 value：保留原有最多 336 个目标/主体 inode，额外一项使用不可能的设备主号作为响应配置。目标和响应配置通过同一个不可变 Map 引用切换，失败候选保留旧策略和解除编号。

## 已知边界

该限制不撤销既有共享可写映射，受限进程仍可通过先前映射修改数据。测试明确验证了这一点。扩展属性/ACL、部分文件系统 ioctl、传统 AIO 和本合成 FUSE 视图已有专项验证，见对应合同；所有异步 I/O、已提交 I/O、块设备、内核内修改、目录/挂载命名空间以及其他 FUSE/overlay/NFS 等不在完整覆盖声明内；不能把它称作完整沙箱或冻结。

状态随未固定的 BPF Map/链接释放，服务退出、崩溃或重启会解除。没有跨重启持久防护、隔离恢复快照、最终用户身份认证或真实攻击意图判定。具备足够宿主权限的攻击者也不在本阶段自保护保证内。

管理员需把真实不应修改的诱饵与业务文件区分开，不能用正常保存行为去证明恶意。已有备份/索引、合法保存和目录扫描反例仍保留。生产虚拟诱饵、可信判定、fanotify 等待期间协同决策、撤销映射与更完整恢复分别作为后续工作。

## 验证入口

```bash
cmake --build build -j
ctest --test-dir build --output-on-failure
sudo python3 -B tests/run_privileged.py --only \
  canary-response canary-capacity canary-backpressure canary-namespace canary-layers
```

专题覆盖既有 FD、两线程、主线程先退出、普通拒绝反例、代际解除、自动到期、失败回滚、别名冲突、容量满显式失败、真实生命周期清理、暂停消费者后的 ring buffer 耗尽、PID=1 隔离及双向时间偏移。完整回归与持续负载结果以本轮验收文档为准。

联合验收补充：正常 sha256sum、cp、tar 读取/备份不触发响应；响应优先于现有 writer/vault 写授权。已验证 fanotify 等待中的打开不会被事后撤销，但打开结束后的普通写入仍被 BPF 拒绝。vault 与 permission 订阅的同 inode 冲突在准备阶段拒绝，避免监听器取读 FD 失败后退出；不隐式授予保险箱读权限。
