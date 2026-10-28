# 指定文件保险箱的最小会话

保险箱复用 inode 固定、单份候选 Map、root 管理和原子替换，提供指定普通文件的在线内容访问控制。目前授权者是 root 管理员；最终用户认证、加密和恢复仍待实现。

## 配置与操作

先以锁定配置启动。策略来源须为 root 所有、不可被其他用户写入的普通文件，管理目录须为 root 所有且模式 0700。

```text
revision 1
vault "/srv/private/document"
```

```bash
sudo ./build/secmon --policy /etc/secmon/policy.conf --control /run/secmon/control.sock
```

用工具生成限时会话配置行：

```bash
./build/secmon-vault-session --id 101 \
  --program /opt/company/document-client --uid 1000 \
  --target /srv/private/document --mode read-write --duration-ms 30000
```

工具输出一行声明。将完整输出加入 root 策略文件、递增 revision，再执行 `sudo ./build/secmon --reload /run/secmon/control.sock` 激活。生成声明时即开始计时，粘贴或重载不会重新开始计时。超过期限再激活也保持锁定。

格式为：

```text
vault-session ID "PROGRAM" EUID "TARGET" MODE DURATION_MS BOOT_UUID ISSUED_BOOT_NS
```

ID 为正 uint64，MODE 为 read 或 read-write，DURATION_MS 为 100..3600000，BOOT_UUID 为生成时的系统启动标识，ISSUED_BOOT_NS 为全局启动时钟上的签发时间。工具处理时钟命名空间偏移、路径引号和字段校验。签发时间在未来或截止时间溢出会拒绝候选。

程序须为 root 所有、有执行位且组/其他用户不可写的普通文件，使用当前 `mm->exe_file` inode 匹配。EUID 使用内核全局坐标。TARGET 须与显式 vault 路径文本一致，安装后按固定 inode 匹配。访问还必须通过 DAC 和其他 LSM。

删除对应 vault-session 行、保留 vault 行并提交更高 revision，即关闭该会话。移除 vault 行本身则解除对象的保险箱保护，属于 root 策略管理操作。

## 会话合同

- vault 默认拒绝经过已覆盖入口的内容读取和修改，包括 root、服务和分析器。O_PATH 与普通元数据查询不取得内容读取权限。
- read 允许内容读取及私有映射；read-write 额外允许写打开、普通写入、截断和新共享可写映射。写会话仍不能删除、改名、新建硬链接或任意改变属性，依赖替换 inode 的编辑器保存方式尚不支持。
- 截断还经过 setattr；仅纯大小及其内核附属属性按截断处理，不将 chmod/chown/显式时间设置整体放开。
- 截止时间为 ISSUED_BOOT_NS + DURATION_MS，BPF 使用全局启动时钟执行，包含休眠；用户态服务暂停也不会延长。无关 revision、行重排、失败候选和同一启动内的服务重启均不续期。
- 当前实例内，同一 ID 的程序、UID、目标、权限、签发时间、期限或对象身份改变会拒绝候选；关闭后保留墓碑，不能用同一 ID 重开。开启新会话须用新 ID。
- 历史属于当前服务实例，重启后不会继承墓碑；绝对截止时间仍由配置保留。关闭结果应通过移除会话行保留在配置中。
- 启动标识不匹配的会话不参与授权，也不固定可能已经不存在的旧程序，vault 目标继续锁定。状态单独报告这类配置。该测试使用模拟旧标识，没有重启开发机。
- 多个会话独立到期；匹配主体、目标、UID 且包含所需权限的任一未过期会话可授权。不同槽的 UID、权限和期限不会合并。
- 普通已有 FD 的后续读写会重新检查，PROT_NONE 映射增加权限时也会检查。不取消在途 I/O、不收回已读取内容、不撤销现有映射。已有共享可写映射到期后仍可写入，已用实际字节修改验证此限制。

程序 inode/EUID 没有认证动态库、插件、解释器代码和运行时完整性；会话适用于所有匹配的程序实例。程序对象自动加写保护；同一启动内的已过期配置也继续固定程序，部署删除/替换程序前应先移除对应会话。停止或崩溃会释放当前未固定的 BPF 链接，服务重启间隙及停止后的持久锁定尚未实现。

## 组合、容量与状态

protect/vault 合计最多 256 条目标路径，另有最多 64 条 allow-writer、16 条 vault-session。候选 Map 为337项（含一项响应配置），最多336个不同 inode、value为408字节。相同 inode 的 protect/vault 别名合并为更严格的 vault；allow-writer 不能直接或经别名指向 vault。

当前实例最多保留 4096 个历史会话 ID，不静默淘汰墓碑；达到上限后拒绝新 ID，仍允许关闭会话。候选失败保留原 Map、期限、历史和对象引用。

fanotify-only 拒绝包含 vault 的配置。组合模式独立执行 fanotify 裁决，会话不会绕过它；分析器没有隐式内容读取权限。

管理协议为同包 v10/496 字节，BPF 状态包括：

| 字段 | 含义 |
| --- | --- |
| vault_paths | 已配置 vault 路径数，包含在 protected_paths 中 |
| vault_sessions | 已配置会话数，含过期及其他启动的配置 |
| vault_stale_sessions | 启动标识不匹配、未授权的会话数 |
| vault_live_sessions | 查询时采样的当前有效会话数 |
| vault_session_history | 当前实例已记住的当前启动会话 ID 数 |
| vault_clock_valid | 本次查询能否解析全局启动时钟 |
| vault_next_deadline_boot_ns | 最早的当前启动配置期限，可能已经过期；无此类配置时为 0 |

live 是采样值，不是授权令牌。clock_valid=false 时零 live 数表示未知；内核仍执行原截止时间。

file_denied 新增 vault_session_expired，只有主体、目标、UID、权限匹配但会话过期时才设置。读操作编号 11=open-read、12=read、13=mmap-read，原 1..8 修改编号不变。离线修改行为工具明确忽略读拒绝，避免误计为勒索修改。

扩展属性/ACL及部分ioctl现已补齐，读写会话不授予这些修改权限，见[具体范围](FILE_METADATA.md)。目录递归、全部异步I/O、其他文件系统专用操作、底层设备和overlay/NFS/FUSE覆盖仍待验证或实现。加密、密钥、备份恢复及虚拟诱饵是独立未完成项。

## 验证入口

```bash
ctest --test-dir build --output-on-failure
sudo python3 -B tests/run_privileged.py --build-dir build \
  --only vault-sessions vault-capacity vault-restart vault-history vault-applications vault-time-namespace
```

覆盖默认拒绝、root/UID/程序/目标隔离、别名、普通旧 FD、映射入口、到期、暂停服务、重排、关闭、ID 复用拒绝及回滚；336 项联合容量、4096 个历史 ID；跨服务重启及模拟旧启动标识；真实 cat/dd 的完整 8192 字节读取、修改与锁定；签发者和服务分别处于 +3600/-60 秒偏移命名空间。

首个相对期限检查点 57dcedb 的 30/30 CTest 与 51/51 特权回归已通过，原始日志 `/tmp/secmon-vault-regression.log`。本文描述后续绝对期限合同，其最终回归和产物范围见 [本轮验收](VALIDATION_VAULT_2026_10_21.md)。

与 fanotify 联合部署时，vault inode 目前不能同时成为本服务的 permission 目标（包括硬链接别名）。监听器交付事件需要读 FD，默认锁读会阻止交付；启动、重载和目标切换在策略准备阶段检查实际固定对象并拒绝冲突，失败保留旧策略。此限制不自动给服务增加保险箱读会话；可信监听器/分析器的独立读权限尚待设计。BPF-only 模式忽略未启用的 fanotify 字段。
