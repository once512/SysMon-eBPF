# 2026-10-17：程序对象授权阶段验证

> 历史阶段记录：以下结果对应所列提交/固定快照。当前代码已移除历史配置和管理协议兼容；现行格式见 [策略配置](POLICY_CONFIG.md) 与 [管理接口](MANAGEMENT.md)。

本记录对应本轮约半小时推进。基础实现提交 335a136，管理 v3 提交 a960800，扩充边界测试/中文导读提交 e73af2d。配置格式 v3、管理协议 v3、分析协议 v3 与 BPF 事件 ABI v4 各自独立。

## 最终普通构建

- 20 项 CTest 通过，四个正式程序的 BUILD_TESTING=OFF 构建通过。
- 22 个权限专题与八项可选 10 秒负载共 **30 项通过**，汇总 JSON passed=true。新增 writer-identity、writer-capacity、writer-layers；writer-soak 包含常驻进程的并发轮换、撤销与错误候选回滚。
- 本轮较早管理 v2 阶段先完成 27 项回归；管理 v3 定向五专题及随后最终 30 项分别完成，不把早期结果归到后续源码。

```bash
sudo python3 tests/run_privileged.py --build-dir build \
    --soak-duration 10 --analysis-soak-duration 10 \
    --management-soak-duration 10 --writer-soak-duration 10
```

新增验证覆盖程序 inode/全局 EUID、fork/exec、硬链接和同名替换、argv[0] 与 shebang、程序对象的属性/删除/重命名/覆盖目标保护、无执行位及非 root 所有对象拒绝。常驻进程用已有 FD 测试写入、截断、共享 mmap/mprotect 和私有映射。

满容量专题核对 256+64 个不同 inode 的真实 HASH 键值与 value 布局；最后一个候选失败时完整回滚。同一对象兼具多种标志时 identity 保护优先；显式检查 FD 固定的旧表在替换后保持完整，关闭最后检查引用后旧 Map ID 消失。自保护拒绝外部 proc fdinfo 属于预期，专题通过启动前后唯一外层 ID 差集定位实例，歧义即失败，不任意选择或修改其他实例 Map。

两层组合使用同一 v3 配置，验证 BPF writer 例外不能覆盖 fanotify deny，fanotify allow 不能覆盖撤销后的 BPF 拒绝；open 权限门不撤销已有写 FD。停止 BPF 后 fanotify 的新打开拒绝仍存在，最终两层退出后临时对象恢复普通访问。

## 固定二进制：15 分钟并发轮换

主程序 secmon 对应 a960800。测试场景程序为当时支持 serve/UID 参数的固定二进制，使用预先打开的 O_WRONLY FD；后续源码又扩充了 O_RDWR/mmap 等场景，未改动本快照。执行文件保存在忽略目录 build/writer-checkpoint，运行时不受后续编译替换影响。摘要为：

```text
2e63e9686a37d786c649a208d9135ceae372886697b70f6843d8d2a079f899fe  build/writer-checkpoint/secmon
8ff4a9621961f1499ce4d99502c2cf7b7c4dce5d6b4b286ff589694989bd3156  build/writer-checkpoint/secmon-writer-scenario
```

```bash
sudo python3 tests/writer_soak.py --build-dir build/writer-checkpoint --duration 900
```

| 指标 | 结果 |
| --- | --- |
| 指定持续时间 | 900 秒 |
| 实际含收尾耗时 | 901.888 秒 |
| 成功更新 | 3181 |
| 错误候选拒绝 | 454 |
| 宿主闲置 FD 基线/峰值 | 50 / 51 |
| 背景请求合计 | 133330 |

| 常驻进程 | 允许 | EACCES |
| --- | --- | --- |
| root 执行对象 | 14805 | 29637 |
| UID 65534 执行对象 | 14710 | 29731 |
| 未授权执行对象 | 0 | 44447 |

背景线程在既有 FD 写入和新 open 之间交替；两个授权执行对象分别保持 root 与 65534 的实际 EUID，规则轮换 root/65534/无授权。未授权对象持续拒绝。每次确认更新后还同步检查六次新操作，确认后的操作不接受“在途旧版本”作为理由；这部分不计入上表背景数量。

每次失败候选保持旧 revision，修正后可重试同一候选版本；成功回复及后续 status 的来源 SHA-256、实例、版本和计数相符。每次提交后 FD 都精确回到基线加当前 writer 路径数。上表峰值是**提交完成后的闲置采样**，不代表准备候选期间的瞬时峰值，也不证明 RSS 或所有内核资源均无增长。

## libstdc++ 调试构建

-D_GLIBCXX_DEBUG 构建 20 项 CTest 通过。writer-identity、writer-capacity、writer-layers、management-faults、policy-consistency 五专题和 120 秒 writer-soak 共六项通过；持续负载成功更新 423 次、拒绝错误候选 60 次，宿主闲置 FD 基线/峰值 50/51。此结果属于当前扩充测试工具，与较早固定快照分别记录。

## 范围

对象授权不是内容签名或加载链认证。动态库、解释器/插件、进程注入、共享映射追回、首次挂载竞态、完整文件系统/容器支持及对宿主 root 的隔离仍未实现。授权覆盖当前策略所有普通 protect 对象，尚无按目标/操作细分或期限授权。长测并行进行构建和其他专题，不用作吞吐或时延 SLA；完整可信应用、真实威胁检测与自动处置仍待后续建设。

原始日志位于本机 /tmp/secmon-writer-final-root.log、/tmp/secmon-writer-soak-long.log、/tmp/secmon-writer-debug-root.log；收尾已确认无残留监控、分析、管理客户端或本轮临时 writer 进程。学习入口见 [程序对象授权](WRITER_IDENTITY.md)。
