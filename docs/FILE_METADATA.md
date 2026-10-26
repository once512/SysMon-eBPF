# 扩展属性、ACL 与文件 ioctl 保护

本轮沿用现有 inode 策略、程序身份与重载事务，补齐普通写入以外的修改入口。当前开发内核为 6.12 x86_64；没有另建文件底座。

## 修改检查点

| 配置名 | 审计操作号 | LSM 入口 |
| --- | --- | --- |
| setxattr | 16 | inode_setxattr |
| removexattr | 17 | inode_removexattr |
| setacl | 18 | inode_set_acl |
| removeacl | 19 | inode_remove_acl |
| ioctl-write | 20 | file_ioctl、file_ioctl_compat 的已分类修改命令 |

`system.posix_acl_access` 通过本内核的独立 ACL 钩子处理，不能只依赖普通 xattr 钩子。保护普通文件、授权程序对象、vault 和 canary 共用这些检查；已有 FD 和硬链接别名也按同一个 inode 匹配。前序 LSM 拒绝保持不变。

已分类 ioctl 为 SETFLAGS、SETVERSION（原生及 32 位 long 命令）、FSSETXATTR、FICLONE 和 FICLONERANGE。修改被拒绝时，`file_denied.ioctl_command` 给出实际命令值；其他文件事件该字段为 0。SETVERSION 在当前文件系统上没有成功基线，仅按命令保守分类，不列为已实测功能。

未知 ioctl 在选中对象上以 EACCES 保守拒绝，操作号为 21；不创建 canary 响应，不作为离线修改证据。已验证的只读 GETFLAGS（原生/compat）、FSGETXATTR，以及普通文件上返回 ENOTTY 的 TCGETS 探测可在没有活动响应时按原语义查询。即使 writer 配置 `all` 也不会放开未知命令。对未选中对象，未触发响应的进程保持原有 ioctl 行为。这项收紧可能影响 FIEMAP 等尚未列入查询白名单的应用，需要按实际部署验证后再显式分类。

FIDEDUPERANGE 的目标 FD 位于参数向量内，不能把源文件当成修改目标。本轮验证其目标经过普通写权限检查：受保护目标拒绝，canary 目标触发响应；不在 BPF 中追踪用户态 FD 向量。其他文件系统专用多 FD 命令仍待验证，不能从接收 ioctl 的主 FD 推断所有附加对象都已检查。

## 授权与响应

原有八个检查点及授权位保持不变；新增五项占后五位，`all` 现在明确表示全部十三项。原先只授予 `setattr` 的配置不会获得 xattr、ACL 或 ioctl 权限。升级时使用 `all` 的管理员应核对这一语义；未知 ioctl 仍不能通过该授权。

一个调用可能经过多个检查点：reflink 在本机既需要 `ioctl-write`，也需要目的文件的 `write`；仅授予其中一项仍拒绝。vault 的 `read-write` 会话仅授权既有内容操作，不授权上述元数据修改、reflink 或未知 ioctl。

canary 的上述已分类修改尝试会创建与普通写入相同的限时响应。响应优先于 writer 和 vault 会话；同一线程组后续对普通文件的 xattr/ACL 及全部 ioctl 都拒绝，包括平时允许的查询命令。普通 read/pread 和私有映射的既有语义不变。未知命令被拒绝本身不会启动响应。

## 布局与边界

BPF 事件 ABI 为 8，新增 ioctl_command；管理协议保持同包 v8/448 字节。策略 value 为 408 字节，含十三个 uint64 授权槽，Map 容量仍为 337（336 个实际 inode 加一项响应配置）。所有主程序、BPF 对象和测试布局须同包构建。

`tests/file_metadata.py` 使用保护启用前打开 FD 的原生请求者，验证四个 xattr/ACL 入口、SETFLAGS、FSSETXATTR、两种 reflink、逐项授权、错误程序、租期、vault 会话、独立 canary 触发及响应。另有不依赖 32 位 libc 的真实 i386 进程验证 compat SETFLAGS；不是将一个 32 位常量传给 64 位进程来代替 compat 验证。

另有 `tests/metadata_identity.py`：以实际匹配执行 inode 的进程持有自身只读 FD，验证用户属性、ACL、文件 capabilities 和 SETFLAGS 修改；显式授予自身 all 仍不能绕过身份对象只读。测试使用私有 root 所有的解释器副本，作为可控身份夹具，不构成生产信任通用解释器的建议。

同机还验证 pwritev、fallocate 打洞、copy_file_range、FIDEDUPERANGE、传统 Linux AIO 的 O_DIRECT 写、splice 和 sendfile 的保护与响应。覆盖只代表这些实际调用路径；不取消已通过检查的在途 I/O，不撤销已有映射，不覆盖底层块设备写入或所有文件系统。当前 `kernel.io_uring_disabled=2`，未改变系统设置，io_uring 未验证。FUSE/overlay/NFS 及生产兼容性仍需后续验证。

## 验证命令

```sh
sudo python3 tests/run_privileged.py --only file-metadata metadata-identity
sudo python3 tests/metadata_soak.py --duration 1800 --artifact-dir /tmp/secmon-metadata-run
python3 -B tools/verify_metadata_soak.py /tmp/secmon-metadata-run
```

持续验证期间保持运行代码和构建产物不变。独立核对器检查原始审计、逐轮公式、代际/期限关联、FD、计数器以及当前源码/二进制摘要；详见[本轮验收](VALIDATION_METADATA_2026_10_22.md)。
