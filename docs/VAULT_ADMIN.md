# 保险箱管理员操作流程（2026-10-28）

`secmon-vaultctl`把签发、递增revision、原子替换策略和核对重载串成一个管理员操作。继续复用既有vault/session和单份策略Map，没有增加内核授权通道。授权者仍为通过sudo/root控制入口的管理员，不是最终用户登录认证，也没有加密磁盘内容。

## 首次部署

文件保险箱必须先显式配置并启动，工具不会把任意路径自动变成vault。配置文件须root所有、0600、单硬链接普通文件；目录须root所有且组/其他用户不可写，祖先禁止符号链接和非root所有目录，允许root所有的sticky共享祖先（例如/tmp）但不允许最终策略目录可写。

```text
revision 1
vault "/srv/private/document.txt"
```

```bash
sudo install -d -m 0700 /etc/secmon /run/secmon/management
sudo chmod 0600 /etc/secmon/policy.conf
sudo secmon --policy /etc/secmon/policy.conf --control /run/secmon/management/control.sock
```

工具对配置文件的要求比主服务读取合同更严格；例如主服务可接受的0644来源须先调整为0600。`--policy`须指向该服务实际读取的文件，工具通过活动revision和原始字节SHA-256核对，不能仅因语法相同就认为来源一致。BPF-only和组合服务均可使用，fanotify-only拒绝。

## 开启、查看、关闭及锁定

为已有的root所有、不可被组/其他用户写入的可信程序授予明确UID的会话：

```bash
sudo secmon-vaultctl open \
  --policy /etc/secmon/policy.conf --socket /run/secmon/management/control.sock \
  --expect-revision 1 --program /usr/bin/cat --uid 1000 \
  --target /srv/private/document.txt --mode read --duration-ms 30000
```

成功输出`code=applied`、新revision、随机正uint64的session_id和全局启动时钟上的deadline_boot_ns；然后用户以对应程序和UID读取。工具本身没有内容读取例外，root也不能绕过vault读取。DAC和其他LSM仍适用。

```bash
sudo secmon-vaultctl status --policy /etc/secmon/policy.conf --socket /run/secmon/management/control.sock
sudo secmon-vaultctl close --policy /etc/secmon/policy.conf --socket /run/secmon/management/control.sock --id SESSION_ID
sudo secmon-vaultctl lock --policy /etc/secmon/policy.conf --socket /run/secmon/management/control.sock --target /srv/private/document.txt
```

- open增加一个独立声明，不修改旧会话签发时间；期限从签发开始，准备和粘贴延迟均不会续期。随机ID仍受服务的历史墓碑/4096容量约束，失败明确拒绝。
- close仅关闭指定ID；ID不存在时报错，不静默当作成功。
- lock解析全部已配置vault的固定对象身份，关闭目标及同inode别名上的全部会话，保留不同对象的会话。O_PATH引用保留到操作结束；对象无法核对则失败，不猜测别名。它不移除vault条目。
- 已无相关会话时lock输出unchanged，不写文件、不重载、不消耗revision。工具也不能清除已复制到程序内存、文件或已有映射中的内容。
- status不创建锁/暂存文件；列出配置会话、期限、启动标识/时间有效性及活动快照。live只表示来源匹配且时间有效的声明采样，不是授权令牌。磁盘与活动状态不一致时输出policy_mismatch、source_matches=false和两侧状态，退出1；不会将尚未激活的候选显示为live。
- 可给变更传入--expect-revision，防止调用方依据旧状态操作；没有该选项也必须通过操作前的活动revision/摘要/实例核对。

程序身份和EUID适用于所有匹配实例，不是某一个PID的专属授权；解释器、插件、动态库和应用输出不会因此受到完整代码认证或防泄漏限制。默认写会话仍不允许原文件删除/改名/创建硬链接；依赖替换inode的编辑器保存没有自动放开。详见[会话合同](VAULT_SESSIONS.md)。

## 发布、拒绝和不确定结果

变更持有同目录`.文件名.secmon-vault.lock`的非阻塞独占锁。其他vaultctl实例遇锁失败，不等待任意时长。原始字节先比较，再以0600临时文件写入、保留SELinux标签、fsync文件、rename和fsync目录发布；无关行保留，全部候选再经共享配置解析器校验。

工具确认同一服务实例返回候选revision和摘要才报告applied。服务明确拒绝时，核对活动实例仍是旧策略、磁盘仍是自身候选后恢复原始字节；保留服务拒绝原因。不会覆盖其他来源变更。文件同步失败也核对出版阶段并尝试恢复。

回复丢失时先查询：若确认同一实例已激活候选，可报告applied及response_recovered=true；否则输出activation_unknown，退出3，保留候选，不依据“没收到回复”回写旧策略。管理员可用vaultctl status与secmon --status查看候选/活动版本，再选择显式reload或恢复来源。不要在未核对时重复open。

| 退出码 | 合同 |
| --- | --- |
| 0 | 已确认applied、unchanged或匹配的status |
| 1 | 失败、明确拒绝并恢复，或status发现来源/预期版本不匹配；查看code与rolled_back |
| 2 | 命令行错误 |
| 3 | 发布/激活/回滚结果无法确认，需核对；不是“没有生效” |

文件发布与内核策略更新不是跨系统原子事务。崩溃或断电可留下已发布但尚未激活的候选；后续启动可能读取它，绝对启动期限仍有效。仅vaultctl遵守相邻锁，其他root编辑器、服务重启和手工reload须由管理员串行管理；校验与rename之间没有防御不合作root的文件CAS接口。配置路径与同步操作也不保证全局VFS硬期限。

包含writer-lease-ms的策略拒绝通过该工具变更，因为普通成功重载会续期无关的相对维护授权；只读status仍可查看。canary响应代际、fanotify重绑定代际和旧vault期限都不会被工具主动提高/重签。普通重载既有的对象固定/重新准备规则继续适用；对象被移走、替换或无法解析时不能承诺修复所有旧引用，失败不会据此报告锁定成功。

## 验证入口

CTest的vault-policy-edit与vaultctl-cli，加上特权vaultctl、vaultctl-faults、vault-file-faults。真实cat/dd覆盖开启、完整读取、指定UID/程序、写入、独立关闭、期限、别名锁定及保留不同文件的授权；协议对端注入明确拒绝、提交前/后丢回复、实例变化及其他来源变更。fsync故障分别发生在rename前和目录同步后，核对当前字节与临时文件清理；这些故障注入不冒充真实内核安全策略验收。

## 已验证的真实编辑器配置

本机Vim已通过原地保存专题，包括编辑器保持运行时关闭会话导致保存拒绝、重新签发新会话后同一编辑器保存成功，以及inode不变。示例[配置](../examples/vault-vim.vim)关闭交换文件、备份和持久撤销，关闭modeline，并指定backupcopy=yes；这些是应用配置，不是新的内核权限。

先用open给实际Vim程序、用户UID及目标授予read-write，再在该用户终端运行：

```bash
sudo install -d -m 0755 /etc/secmon-editor
sudo install -m 0644 /usr/local/share/doc/SecMon/examples/vault-vim.vim /etc/secmon-editor/vault-vim.vim
vim -u NONE -i NONE -n --noplugin \
  --cmd 'source /etc/secmon-editor/vault-vim.vim' /srv/private/document.txt
```

管理员应先把示例放到root所有、不可被其他用户写入但目标用户可读取/遍历的位置。它不应放进0700的私有策略目录；上例的编辑器配置目录与管理/策略目录分别设置权限。不要直接使用任意用户可写的启动脚本或插件作为可信授权依据。授权仍匹配所有相同程序inode/EUID实例；该命令行配置不会让内核认证Vim插件、脚本或所有运行时代码。用户已读进编辑缓冲的内容在锁定后仍存在；关闭会话阻止新的受检I/O，不是抹除缓冲区。

此专题只证明本机Vim这个明确配置及其普通文件原地保存路径。未验证所有交互命令、GUI编辑器、外部工具、崩溃恢复和真实用户插件环境；不将其表述为透明兼容任意编辑器。保存失败时不要使用替换文件或解除vault保护作为自动回退。
