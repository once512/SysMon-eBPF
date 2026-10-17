<p align="center">
  <a href="./README_en.md">English</a>
  &middot;
  <a href="./README.md">简体中文</a>
</p>

# SecMon

在所有的Linux系统监控方法中，唯有基于eBPF方法没有做过了，故创建此开源仓库

也欢迎和我一样有兴趣的人一起加入并迭代这个项目

## 当前实现

总体方案见 [DESIGN.md](DESIGN.md)。目前实现第一阶段的执行与凭证审计链路，尚未实现文件保护、自保护、fanotify 裁决、诱饵或保险箱。

- GNU++17 宿主使用 libbpf skeleton 加载、挂载和消费事件。
- 在执行安全检查点输出 JSON Lines；这些事件表示执行检查，不表示执行最终成功。
- 新增 `exec_success` 完成事件及 `old_tid` 字段，区分检查与成功，并关联非主线程 exec 前后的 TID；该事件的 `flags=0` 不代表执行后重新做过异常检查。
- 同一次执行可能多次经过检查点（例如脚本与解释器处理），不按检查事件数量统计成功执行次数。`comm` 是检查时的当前任务名，可能仍为调用者名称；`filename` 是本次执行请求路径。
- 在 `commit_creds` 返回后、fork 和 exec 完成时记录已观测凭证，按线程生命周期清理。
- 凭证与基线不一致时设置事件 `flags` 的位 0，仅审计，不阻断。合法提交也可能来自攻击，基线不等同于可信授权。
- 每 10 秒及退出时向标准错误输出丢失事件和基线更新失败计数。

## 构建与运行

当前目标为开发机的 x86_64 Linux 6.12，要求活动 LSM 列表包含 `bpf`，并具有本机 BTF、对应跟踪点和足够的 BPF 加载权限。直接针对本机能力构建，不提供旧内核兼容层。

在当前 RPM 系统安装开发依赖：

```bash
sudo dnf install clang llvm libbpf-devel elfutils-libelf-devel zlib-devel cmake gcc-c++ pkgconf-pkg-config
cmake -S . -B build
cmake --build build -j
./build/secmon --check
sudo ./build/secmon > events.jsonl
```

构建使用系统 libbpf，不要求初始化子模块。`vmlinux.h` 从 `/sys/kernel/btf/vmlinux` 生成，skeleton 从新编译的对象生成，均输出到构建目录；不使用仓库里旧的生成文件。切换运行内核后重新配置构建。

`--check` 仅检查内核标识、可读 BTF 和活动 BPF LSM，不保证所有钩子和加载权限可用。实际挂载失败会报告错误并退出。Ctrl+C 或 SIGTERM 退出时解除挂载，资源通过 RAII 清理。

事件输出的非 ASCII 字节采用 `\u00XX` 编码，按字节保留文件名，不保证显示为原始 Unicode。文件名字段最多 255 字节。程序启动前已有线程在首次检查时建立观测基线；启动和分步挂载期间不提供无缝覆盖保证。

`uid`、`euid`、`caps` 和 `comm` 反映事件发生时的当前任务状态：检查事件发生在凭证提交前，成功事件发生在执行完成阶段。`old_tid` 在成功事件中标识执行前的线程 ID，配合 PID、事件顺序与生命周期信息关联；它不是全局唯一的执行请求 ID。脚本仍可能产生多个检查事件。

当前已在开发机完成 BPF 对象编译、skeleton 生成和 GNU++17 宿主构建，`--check` 与 `--help` 验证通过。用户以管理员权限完成加载、挂载、超时退出及执行事件采集验证，输出包含 `/usr/bin/id` 和 `/usr/bin/true`，提供的样本中 `flags` 均为 0，丢失事件和基线更新失败计数均为 0。凭证切换、线程生命周期、异常检测及压力场景仍待验证。

## 验证工具

```bash
ctest --test-dir build --output-on-failure
sudo python3 tests/integration.py --build-dir build
```

第一条只验证帮助命令及测试工具的普通执行、线程创建退出、非主线程 exec，不加载 BPF。

第二条会临时启动审计程序，自动触发上述场景及测试子进程降权到 UID/GID 65534 后执行，检查检查事件、完成事件、TID 关联、凭证字段和失败计数，最后停止审计程序。不部署持久策略，不修改账户；测试程序所在路径需允许降权后的进程遍历。运行前停止手工启动的旧版 secmon，避免额外挂载干扰。

当前开发机上该特权集成测试已全部通过，包括新增钩子的实际加载、普通执行、线程创建退出、非主线程 exec 的 TID 关联、合法降权后的执行及正常退出；两个失败计数均为 0。该测试不验证真实提权攻击检测，也不直接检查 Map 中的所有生命周期条目是否均已清理。
