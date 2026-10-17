# 一个主服务、两个监控对象

`src/main.cpp` 是唯一监控服务入口。分析器和命令行管理工具仍有各自的 main，但不会作为第二个常驻监控服务运行。

```mermaid
flowchart TD
    Main[main：参数与管理动作] --> Service[MonitorService：一个事件循环]
    Service --> Runtime[一份 PolicyRuntime]
    Service --> Control[一个 ControlServer]
    Service --> BPF[BpfMonitor]
    Service --> Fan[FanotifyMonitor]
    BPF --> Skel[skeleton / Map / ring buffer / inode FD]
    Fan --> Gate[PermissionGate / mark / 队列]
    Gate --> Worker[独立降权分析器]
```

| 文件 | 负责什么 |
| --- | --- |
| [main.cpp](../src/main.cpp) | 解析动作；管理请求不加载模块；运行时创建服务对象 |
| [service.h](../src/service.h) / [service.cpp](../src/service.cpp) | 初始配置、信号、两个对象的寿命、联合重载、统一快照和退出 |
| [bpf/monitor.h](../src/bpf/monitor.h) / [monitor.cpp](../src/bpf/monitor.cpp) | 本机检查、skeleton open/load/attach、策略 Map、事件消费和卸载 |
| [fanotify/monitor.h](../src/fanotify/monitor.h) / [monitor.cpp](../src/fanotify/monitor.cpp) | 权限门资源、候选检查、无异常提交和状态/统计适配 |

BpfMonitor 用私有 State 隐藏 libbpf 生成类型，外部不持有 skeleton 或裸 Map FD。State 中先声明固定 inode 集合，再声明 skeleton 和 ring buffer；逆序析构确保钩子释放后才释放 inode 引用。FanotifyMonitor 组合 PermissionGate，后者继续拥有事件队列、group、目标 inode 和分析器监督对象；没有引入继承或虚接口。

## 启动与事件处理

```bash
sudo ./build/secmon --policy /run/secmon/policy.conf --control /run/secmon/control.sock
sudo ./build/secmon --status /run/secmon/control.sock
sudo ./build/secmon --reload /run/secmon/control.sock
sudo ./build/secmon --stop /run/secmon/control.sock
```

默认启动 BPF；配置中有 fanotify 字段时同时创建权限门。任一对象构造失败，整个启动失败，已创建的对象逆序回收；只有 stderr 的 `Service active;` 才表示所有请求模块均已就绪。各内核钩子/mark 首次启用有先后，不承诺瞬时联合启用。

同一线程串行处理管理命令、BPF 事件和 fanotify 裁决。联合模式中 BPF 以零等待、每轮最多 128 条消费，fanotify 每轮最多等待 10ms，并受请求截止时间进一步限制。该数值是 poll 等待上限，不是端到端时延承诺。没有第二个监控进程或独立重载线程。AuditSink 另用专门 I/O 线程消费有界 JSONL 队列，避免 stdout 管道堵塞主循环；该线程不修改策略。

审计事件仍写 stdout JSONL。BPF 周期统计和联合模式 fanotify 结束统计写 stderr，避免将统计混入事件消费者。`--fanotify-only` 诊断模式的结束统计仍写 stdout，方便机制测试读取。

## 联合重载的失败边界

1. 读取启动时指定的配置源，排除 fanotify mark 的 inode，完整解析并校验递增 revision。
2. FanotifyMonitor::prepare 检查模块仍启用、目标/事件/扫描参数不变，且已交付队列与分析器空闲。候选值复制和转换均在此阶段完成，尚未改变活动裁决。
3. BpfMonitor::install 准备完整候选 Map 和 inode FD，再一次替换外层 Map slot。失败保持活动 Map 与旧固定引用。
4. FanotifyMonitor::commit 执行已验证的 noexcept 值赋值；随后 PolicyRuntime 移动新配置并记录共用 revision。两阶段之间不处理新事件，提交后不再进行可失败的资源准备。

因此拒绝不会留下“BPF 新 revision、fanotify 旧 revision”的服务状态。已经进入内核的操作、不同 LSM 钩子和仍在内核队列中的事件可能跨越提交时刻；这里不承诺跨内核入口的全局原子切换。尚未读出的 fanotify 事件按读取后的当前规则处理。

fanotify 启用/禁用、目标、事件和分析器固定配置变更需重启。忙队列拒绝不修改旧请求合同，排空后可重试同一候选 revision。默认模式不再存在分别重载两个服务的管理流程。

## 退出与分析隔离

授权 stop 只设置本事件循环的退出状态，回复当前完整快照后，统一拒绝已交付的 fanotify 请求、关闭监听组、停止分析器、卸载 BPF 并报告统计；客户端收到确认不代表析构已全部完成。关闭 group 仍会释放未读请求，进程崩溃不提供持久拒绝保证。

分析器是唯一必要的独立工作进程，继续按既有规则降权和清空 capabilities。它接收借出的只读事件 FD，其故障按 fanotify 回退策略处理，不负责 BPF 管理或整个主服务的策略版本。

`--bpf-only` / `--fanotify-only` 只用于诊断和机制实验，仍进入同一个 main 与 MonitorService。旧 secmon-fanotify 可执行文件不再构建；更新已有构建目录时应删除遗留旧产物，避免误运行。

## 验证

```bash
ctest --test-dir build --output-on-failure
sudo python3 tests/run_privileged.py --build-dir build --only unified-service policy-consistency
```

联合专题验证共享 PID/快照、两侧准备失败与忙队列回滚、确认后的读写行为、配置自身 inode 排除、固定后端变更拒绝、协调停止、分析器崩溃回退和第二模块启动失败后的清理。原机制专题继续用诊断模式研究分层效果。

审计队列、输出错误和诊断边界见 [有界审计出口](AUDIT_OUTPUT.md)。
