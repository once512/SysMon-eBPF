# 配置解析的模糊测试

这是开发期的内存语法测试，不启动监控服务、不读取真实配置文件、不需要 sudo。目标是让编译器插桩检查输入边界和内存行为，同时验证“已接受的配置值可以稳定重编码/重解析”的属性。它不能证明内核策略、来源读取权限或用户态运行资源没有错误。

## 单独构建和运行

```bash
cmake -S . -B build/fuzz -DCMAKE_CXX_COMPILER=clang++ \
    -DBUILD_TESTING=OFF -DSECMON_BUILD_FUZZERS=ON
cmake --build build/fuzz --target secmon-policy-fuzzer -j
python3 tests/prepare_fuzz_corpus.py --output build/fuzz-corpus
mkdir -p build/fuzz-artifacts
./build/fuzz/secmon-policy-fuzzer -max_total_time=60 -max_len=65537 \
    -dict=tests/policy_fuzzer.dict -artifact_prefix=build/fuzz-artifacts/ \
    -print_final_stats=1 build/fuzz-corpus
```

该选项默认关闭，要求 Clang。目标直接编译被测解析源，并启用 libFuzzer、AddressSanitizer 和 UndefinedBehaviorSanitizer；没有链接未插桩的普通策略库。普通 secmon/分析器/管理工具不携带此测试入口或 sanitizer 故障注入。

max_total_time 限制本次运行秒数；max_len 比配置预算多一个字节，以同时触达合法 64 KiB 和超限拒绝。语料只写 build 下的本地目录；源码中的三个小种子便于阅读，生成工具另补 256/64 满容量、4095 字节路径和 65536/65537 字节边界，避免提交大段重复填充。操作字典帮助变异触达字段名、引号、NUL 和数值边界。

## harness 检查什么

[tests/fuzz_policy.cpp](../tests/fuzz_policy.cpp) 把输入作为内存流交给 parse_policy。预期的语法 runtime_error 表示拒绝，继续下个输入。接受后用完整值模型编码 revision、protect、所有 writer 规则及 fanotify 的模式/参数，再次解析并检查编码稳定；这一步的异常和不一致不会被“正常拒绝”分支吞掉。

编码会显式展开默认值和操作名，可能比原文本长；若编码超过同一文本预算，跳过重解析属性，但原输入依然经过被测解析和 sanitizer。编码器只存在于测试，不是第二套生产配置格式或版本兼容层。

非 ASCII 字节、空白、转义、重复/未知字段、越界数字、错误操作列表、模式互斥和引用关系都由变异输入探索。来源读取使用 O_PATH 的权限/身份检查、运行提交失败回滚和实际 Map 行为仍由权限专题验证。

## 发现异常后如何复现

保留输出中给出的最小输入路径和 sanitizer 堆栈，用同一 fuzzer 直接传入该文件：

```bash
./build/fuzz/secmon-policy-fuzzer build/fuzz-artifacts/crash-具体文件名
```

先确认异常来自生产解析逻辑还是测试属性本身，再修复并添加小型确定性回归。一次指定时长内未发现异常，只说明这批输入和插桩检查未触发报告，不是无漏洞证明。ASan 的隔离区、插桩和 fuzzer 语料会占用额外内存，不能把该进程 RSS 当作生产服务资源量。
