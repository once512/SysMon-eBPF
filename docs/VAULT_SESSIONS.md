# 指定文件保险箱的最小会话

保险箱复用现有 inode 固定、单份候选 Map、root 管理和原子替换。它是指定普通文件的在线访问控制，尚非加密存储或完整桌面保险箱。

## 配置与操作

先以锁定配置启动；策略来源和管理目录仍遵循原有 root 所有、不可被其他用户写入的约束。

```text
revision 1
vault "/srv/private/document"
```

```bash
sudo ./build/secmon --policy /etc/secmon/policy.conf --control /run/secmon/control.sock
```

在同一配置中增加会话并递增 revision，然后 `sudo ./build/secmon --reload /run/secmon/control.sock`。例如：

```text
revision 2
vault "/srv/private/document"
vault-session 101 "/opt/company/document-client" 1000 "/srv/private/document" read-write 30000
```

字段依次为正整数会话 ID、程序绝对路径、内核全局有效 UID、显式 vault 目标路径、`read` 或 `read-write`、100..3600000 毫秒期限。路径语法与 protect 一致，必须加双引号。程序按当前 `mm->exe_file` inode 匹配，不按名字或提交请求的路径匹配；目标按固定 inode 匹配。文件还必须通过 DAC 和其他 LSM 检查。

删除对应 vault-session 行并提交更高 revision，关闭该会话；保留 vault 行以继续锁定目标。移除 vault 行本身则解除该对象的保险箱保护，属于 root 策略管理操作。

## 会话合同

- vault 默认拒绝所有主体的读取和修改，包括 root、服务和分析器；O_PATH 本身不提供内容访问。没有隐式的管理员内容读取例外。
- read 允许被覆盖检查点的内容读取、私有映射；read-write 额外允许写打开、普通写入、截断和新共享可写映射。写会话仍不能删除、改名、新建硬链接或任意改变属性，因此依赖替换 inode 的编辑器保存方式尚不支持。
- 截断还经过 setattr；仅纯大小及其内核附属属性按截断处理，不将 chmod/chown/显式时间设置整体放开。
- 同一运行实例中，无关 revision、会话行重排、失败候选和旧版本不续期。已有 ID 的程序、UID、目标、权限、期限或对象身份改变都会拒绝候选；开启另一会话必须用新 ID。
- 关闭 ID 后保留有界墓碑，当前实例不能用同一 ID 重开。最多 16 个配置会话，最多保留 4096 个会话历史 ID；达到历史上限后拒绝新 ID，但仍允许关闭现有会话。
- 多个会话独立到期；匹配主体和目标上的任一未过期、包含所需权限的会话即可授权。期限由 BPF 全局启动时钟执行，包含休眠，用户态服务暂停也不会延长。
- 普通已有 FD 的后续读写会重新检查；不取消正在执行的 I/O，不收回已读取内容，不撤销现有映射。对 PROT_NONE 映射后增加权限的入口再次检查。
- 会话 ID、历史及相对期限目前属于一个服务实例。重启加载带会话的配置会重新计时，不能据此承诺跨重启的绝对到期。停止或崩溃释放当前未固定的 BPF 链接，也不提供持久锁定。

程序文件自动加写保护，防止经已覆盖入口修改授权代码。程序 inode/EUID 仍不认证动态库、插件、解释器代码和运行时完整性；会话面向所有匹配的程序实例，并非单个 PID 的令牌。当前授权者是 root 管理员，尚无最终用户口令、用户会话认证或授权代理。

## 与现有能力组合

protect 与 vault 共用最多 256 条目标路径；另有最多 64 条 allow-writer 和 16 条 vault-session。候选 Map 最多 336 个不同 inode，value 为 352 字节。相同 inode 的 protect/vault 别名合并为更严格的 vault。allow-writer 不能直接或经别名指向 vault，避免普通维护写例外绕过会话锁定。

fanotify-only 拒绝包含 vault 的配置；组合模式仍独立执行 fanotify 裁决，不能靠会话绕过它。分析器没有隐式读权限，给通用解释器或扫描器添加会话须按其全部承载代码评估信任范围。

管理协议为同包 v5/392 字节。BPF 状态包含 vault_paths、vault_sessions（含过期项）、vault_live_sessions、vault_session_history、vault_clock_valid、vault_next_deadline_boot_ns。live 是查询时采样，不是授权令牌；clock_valid=false 时不把零计数解读为已确认到期，内核仍执行原截止时间。next_deadline 为最早配置截止时间，可能已过期。

file_denied 新增 vault_session_expired；只有主体、目标、UID、所需权限匹配但会话过期时才设置，不把所有拒绝都标为过期。读操作编号 11=open-read、12=read、13=mmap-read，原 1..8 的修改编号不变。离线修改行为工具明确忽略读拒绝，避免把锁定读取误计为勒索修改。

不承诺目录递归、所有异步 I/O、扩展属性/ACL、文件系统专用操作、底层设备访问或 overlay/NFS/FUSE 覆盖。加密、密钥、备份恢复和虚拟诱饵仍是独立未完成项。

## 验证入口

```bash
ctest --test-dir build --output-on-failure
sudo python3 -B tests/run_privileged.py --build-dir build --only vault-sessions vault-capacity
```

会话专题覆盖默认拒绝、root/错误 UID/程序/目标隔离、别名、旧 FD、读写与私有/共享映射、到期、暂停服务、重排、失败候选、关闭与 ID 复用拒绝。容量专题同时装入 256 目标、64 writer、16 会话，检查第 15 位、336 项 Map、准备末尾失败回滚及 FD/旧 Map 回收。通过范围和最终回归以验收记录为准。

首个相对期限检查点：原生构建及 30/30 CTest 通过；包含新增两专题的完整特权回归 51/51 通过，原始日志 `/tmp/secmon-vault-regression.log`。此记录仅对应本节的单实例合同，后续绝对期限变更需单独重验。
