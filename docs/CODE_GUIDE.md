# 代码导读

建议先阅读 README 的运行边界，再按下面的顺序研究代码。当前代码围绕三个能力组织：执行与凭证审计、指定文件只读保护、进程自保护。

## 宿主程序：从参数到事件

| 文件 | 职责 | 阅读重点 |
| --- | --- | --- |
| `src/options.h` / `src/options.cpp` | 参数解析和互斥校验 | `Options` 保存配置；`CliAction` 区分运行、帮助和停止；解析过程不访问 BPF 或 socket |
| `src/main.cpp` | 环境检查、BPF 生命周期、轮询与退出 | 按 open → load → 写入策略 → attach 顺序启动；声明顺序决定资源释放顺序 |
| `src/events.h` / `src/events.cpp` | ABI 校验、JSONL 输出、统计汇总 | 先校验记录长度和版本，再按事件类型输出；每 CPU 统计需要逐 CPU 求和 |
| `src/owned_fd.h` | 文件描述符 RAII | 禁止复制，析构时关闭 FD，避免重复关闭 |
| `src/file_policy.h` / `src/file_policy.cpp` | 固定文件对象并安装 Map 策略 | `O_PATH` 持有 inode；设备号和 inode 组成身份；文件句柄必须比 BPF 链接活得更久 |
| `src/control.h` / `src/control.cpp` | root 管理 socket | 私有目录 FD 固定创建与清理位置；`SO_PEERCRED` 验证身份；完整 `stop` 消息触发退出 |

头文件暴露接口与资源所有权，系统调用和协议细节放在对应 `.cpp`。`main.cpp` 通过这些接口协调运行，避免再次把各个功能实现堆回入口。

正常退出时先 detach，再消费剩余事件并报告统计。异常退出依赖 RAII：ring buffer、skeleton、固定文件句柄、控制 socket 依次释放。调整局部变量声明位置时，必须检查这一顺序，尤其不能在 BPF 链接仍存在时提前释放固定 inode 的句柄。

## 内核侧：跟踪一次执行

1. 阅读 `eBPF/secmon.h`：这是用户态与内核态共同使用的事件 ABI 和常量定义。
2. 阅读 `eBPF/secmon.bpf.c`：共享 ring buffer、统计 Map，以及执行检查和执行完成事件。
3. 阅读 `eBPF/upchk.bpf.c`：凭证基线、fork/exec/exit 生命周期和异常标记。基线只是观测记录，不代表凭证变化得到授权。
4. 阅读 `eBPF/fileguard.bpf.c`：文件身份匹配、各个 LSM 钩子与拒绝事件。
5. 阅读 `eBPF/selfguard.bpf.c`：任务本地存储、线程组目标身份、信号与 ptrace 拒绝。

这些 `.bpf.c` 模块由 `secmon.bpf.c` 包含，编译成一个 BPF 对象，以共享 Map 和辅助函数。它们不是单独链接的用户态源文件。修改模块后，CMake 的依赖规则会重新编译对象并生成 skeleton。

一次普通 exec 通常会产生检查和完成事件。脚本可能经过多次检查，失败的执行也可能只有检查事件。非主线程 exec 可能改变 TID，需结合 `old_tid`、任务身份及事件顺序理解，不能仅按检查事件数量统计成功次数。

## 构建产物与验证

`CMakeLists.txt` 描述两条构建链：本机 BTF → `build/vmlinux.h` → BPF 对象 → skeleton，以及 `src/*.cpp` → 宿主可执行文件。生成文件留在构建目录，不应手动修改或提交。

```bash
cmake -S . -B build
cmake --build build -j
ctest --test-dir build --output-on-failure
./build/secmon --check
```

CTest 的 `cli-validation` 检查非法参数的退出码为 2，覆盖缺失值、时长格式/范围、选项冲突与 257 个文件；这些路径在加载 BPF 前退出。其余用例验证帮助输出和执行场景工具，不验证防护是否实际生效。

完整内核行为需要管理员权限：

```bash
sudo python3 tests/integration.py --build-dir build
sudo python3 tests/self_protection.py --build-dir build
```

阅读测试时，先看 `tests/scenarios.cpp` 如何制造执行和线程场景，再看两个 Python 脚本如何启动服务、验证事件和清理。测试操作范围及防护边界以 README 为准。

## 后续研究方向

现已提供独立的单文件 fanotify 原型，源码位于 `src/fanotify/`，详见 [fanotify 学习实验](FANOTIFY_LAB.md)。已加入接收后的请求超时、用户态并发预算和对应实验；后续可研究真实内核队列溢出，再考虑接入现有策略。fanotify 不能作为所有写入操作的通用阻断入口；详细设计和已验证范围见 `DESIGN.md`。

同时研究两个策略模块时，可参照 [策略组合实验](POLICY_LAYERS.md) 的状态矩阵，区分单层退出与所有防护退出。

研究凭证基线时，可参照 [凭证生命周期实验](CREDENTIAL_LIFECYCLE.md)，在受控阶段直接观察 Map 中的线程身份与凭证值。
