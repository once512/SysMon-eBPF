# 请求方 pidfd 生命周期阶段验证（2026-10-18）

## 2026-10-19 强制关机后的恢复核查

冻结产物的三个 SHA-256 与下表一致。保留日志显示 requester-pidfd 的 15 个场景和 requester-lifecycle 的 4 个变体通过，随后身份持续循环完成 49 轮四变体及第 50 轮的宿主 open，共 197 个通过记录，未见失败记录。日志缺少持续循环结束报告，也未开始后三组 pidfd 持续负载，不能将这些部分认定为完成。

用户提供 sudo 凭据后已重新启动下方完整持续验证命令，新日志为 `/tmp/secmon-requester-sustained-validation-resumed.log`，原日志保留。中断的长测不按剩余秒数续算。本次仍须以 runner 最终 passed/results 报告为完成依据；启动不代表验收通过。

本次重跑已完成：进程退出码 0，runner 最终 `passed: true`，六个阶段全部通过，累计 5754.499 秒（约 96 分钟）。身份持续循环完成 97 轮四变体，共 388 个通过记录。三组持续负载结果如下：

| 后端/入口 | 请求数 | 管理查询 | 成功更新 | FD 基线/峰值 |
|---|---:|---:|---:|---:|
| static/open | 1,134,666 | 14,789 | 704 | 56/66 |
| analysis/open | 2,225,207 | 14,623 | 730 | 58/66 |
| analysis/access | 2,222,291 | 14,619 | 729 | 58/67 |

三组均通过权限记录/身份对账、管理更新与旧版本拒绝、空闲 FD 恢复和输出健康检查。本次覆盖范围仍受本记录的内核/架构和受控负载限制。

实现提交为 `6f59a3b`。本阶段在 `6.12.0-211.61.1.el10_2.x86_64`、x86_64 开发机验证可选内核请求方引用及 pidfs 进程键；不据此认定其他内核/架构或完整容器环境已覆盖。接口和失败合同见 [请求方 pidfd](REQUESTER_PIDFD.md)。

## 构建与专题回归

默认与 Release 构建的 24 项 CTest 均通过；Clang ASan/UBSan（包含泄漏检测）的 metadata/FD 所有权、权限 JSON 编码和 BPF JSON 编码三组检查通过。BPF 二进制事件 ABI 为 5，管理协议布局仍为 v3/360 字节，启用引用由 flag 32 表示。

默认构建全量 39 个专题/模式变体全部通过，累计专题耗时 227.709 秒，原始日志为 `/tmp/secmon-requester-full-validation.log`。包括原有授权、回滚、故障、审计/诊断背压和生命周期，以及新增/扩展：

- open/access 的并发线程、线程重建、宿主/子 PID namespace，核对 BPF process_inode 与真实 pidfd、可选权限审计 cookie 一致。
- 主线程 exec、非主线程 exec、主线程单独退出后 worker 继续运行，覆盖宿主和子 namespace。进程键保持一致，任务 tid/start_ns 独立处理；整个线程组退出后旧 pidfd 可读，信号 0 返回 ESRCH。
- 请求取消、容量、正常停止、超时、分析成功/错误、FD 压力，以及直接 exec。FD 压力通过仅限本次服务的 soft limit 实际触发 FAN_EPIDFD，并在恢复后核对句柄回到基线。
- 子 namespace 监听器对不可见外层任务输出 PID=0 / unavailable / cookie=0，不查询数字 PID 补身份。
- 开启 pidfd 后，联合和 fanotify-only 下的恢复、堵塞退出、断开与持续 stdout 洪流仍能裁决/重载/停止，并正确报告预期丢弃。

短时静态 open 联合负载 10 秒核对 7639 条权限记录，100 次查询、4 次成功更新及同量旧版本拒绝；FD 基线/峰值为 56/64。请求 ID、回复数、进程 inode、revision 与审计健康全部对账，原始日志为 `/tmp/secmon-pidfd-management-smoke.log`。

## 冻结产物

后续持续验证使用 `build/requester-checkpoint`，执行期间不重新链接；SHA-256：

| 产物 | SHA-256 |
|---|---|
| secmon | `11c416908542e1c92c2bf194042cffa2a9ce0eb46c95942ecf1b6dc1989be2de` |
| secmon-analyzer | `c99aad5add45d93d27dc6bd4df24e7a15452f20706b81015bf8913ea08ce361f` |
| secmon-policyctl | `ec248c2bb9c28bc51fca3a0c25d087f82b7f1bf3a5209b12bb5abf209f8b5477` |

持续验证命令：

```sh
sudo python3 -B tests/run_privileged.py --build-dir build/requester-checkpoint \
  --only requester-pidfd requester-lifecycle \
  --requester-identity-soak-duration 1200 --requester-pidfd-soak-duration 1500
```

命令先重跑引用及 exec/leader 专题，再运行约 20 分钟的四变体完整创建/并发/退出循环，之后依次运行静态 open、分析 open、分析 access，每组请求负载 25 分钟。管理负载在线逐轮更新与拒绝旧版本，停止后逐条核对完整权限日志和进程 cookie。原始中断日志为 `/tmp/secmon-requester-sustained-validation.log`；完成的重跑日志及结果见本页恢复核查。
