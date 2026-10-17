# BPF 与 fanotify 策略组合实验

正常部署的 BPF 与 fanotify 属于同一 secmon 进程的两个对象，共用启动/停止与策略提交。这里的机制实验刻意分别启动 `secmon --bpf-only` 和 `secmon --fanotify-only` 诊断实例，以研究两层的独立裁决与资源解除；这不是产品部署方式，也不提供新的完整保险箱接口。同进程联合行为另由 unified-service 专题验证，见 [单服务结构](UNIFIED_SERVICE.md)。

```bash
sudo python3 tests/policy_composition.py --build-dir build
```

| 实验状态 | 新读打开 | 新写打开 | 启动前已有 FD 写入 |
| --- | --- | --- | --- |
| BPF 只读 + fanotify allow | 允许 | BPF 拒绝，EACCES | BPF 拒绝，EACCES |
| BPF 只读，fanotify 已退出 | 允许 | BPF 拒绝，EACCES | BPF 拒绝，EACCES |
| BPF 只读 + fanotify deny | fanotify 拒绝，EPERM | BPF 拒绝，EACCES | BPF 拒绝，EACCES |
| BPF 已退出，fanotify deny | fanotify 拒绝，EPERM | fanotify 拒绝，EPERM | 允许 |
| 两层均退出 | 允许 | 允许 | 允许 |

测试在当前开发机通过。BPF 拒绝写打开时，fanotify 没有收到该打开的裁决请求；允许回复不覆盖已有安全模块的拒绝。精确 errno 与先后关系是当前内核上的观测结果，不应假设所有内核和所有入口都以相同顺序运行。

组合测试还检查删除被 BPF 拒绝、拒绝事件的设备号/inode、零事件丢失和零基线更新失败，以及两层独立解除。所有文件和日志都位于临时目录，不部署持久策略。

停止 BPF 后，fanotify 仍能拒绝新打开，但不能撤销已存在的写 FD；因此两层一起运行也不等于完整的数据访问撤销、路径命名锁定或崩溃后的持久防护。mmap、异步 I/O 及其他文件系统入口仍需各自验证。

阅读顺序：先看 `tests/policy_composition.py` 的状态转换，再看 `tests/monitor_harness.py` 和 `tests/fanotify_harness.py` 如何拥有、停止与清理各自的服务进程。此实验与 [fanotify 学习实验](FANOTIFY_LAB.md) 配套。
