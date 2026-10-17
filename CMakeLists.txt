# 构建包含两条链：本机 BTF → vmlinux.h → BPF ELF → skeleton，以及普通 C++ 宿主/分析器。
# BPF 程序使用 clang 的 bpf target，宿主使用系统 C++ 编译器；生成文件写 build，不手改生成头。
cmake_minimum_required(VERSION 3.20)
project(SecMon LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)
find_program(CLANG_EXE NAMES clang REQUIRED)
find_program(BPFTOOL_EXE NAMES bpftool REQUIRED)
find_package(PkgConfig REQUIRED)
find_package(OpenSSL REQUIRED COMPONENTS Crypto)
pkg_check_modules(LIBBPF REQUIRED IMPORTED_TARGET libbpf)
if(NOT CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64)$")
    message(FATAL_ERROR "Current implementation targets the development x86_64 kernel")
endif()
# 同一工程用两类编译目标：BPF 指令进入内核，普通 C++ 代码通过 libbpf 系统调用接口管理它。
set(BPF_OBJ "${CMAKE_CURRENT_BINARY_DIR}/secmon.bpf.o")
set(BPF_SKEL "${CMAKE_CURRENT_BINARY_DIR}/secmon.skel.h")
set(VMLINUX "${CMAKE_CURRENT_BINARY_DIR}/vmlinux.h")
# sysfs timestamps may be in the future. Track BTF content, not its mtime.
# Reconfigure after switching kernels to refresh this identity.
# 内核切换后重新配置工程，以 BTF 内容身份触发类型头更新，而非依赖可能异常的 sysfs 时间戳。
file(SHA256 /sys/kernel/btf/vmlinux KERNEL_BTF_HASH)
file(CONFIGURE OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/kernel-btf.identity"
    CONTENT "@KERNEL_BTF_HASH@\n" @ONLY)
add_custom_command(OUTPUT "${VMLINUX}"
    COMMAND ${CMAKE_COMMAND} -DTOOL=${BPFTOOL_EXE} -DMODE=btf
        -DINPUT=/sys/kernel/btf/vmlinux -DOUTPUT=${VMLINUX}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/Bpftool.cmake
    DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/kernel-btf.identity" cmake/Bpftool.cmake VERBATIM)
# -target bpf 生成 BPF 指令；-g 保留 BTF/重定位所需信息，-O2 也有利于消除 verifier 难处理的冗余代码。
add_custom_command(OUTPUT "${BPF_OBJ}"
    COMMAND ${CLANG_EXE} -g -O2 -target bpf -D__TARGET_ARCH_x86
        -Wall -Werror -I${CMAKE_CURRENT_BINARY_DIR}
        -I${CMAKE_CURRENT_SOURCE_DIR}/eBPF ${LIBBPF_CFLAGS}
        -c ${CMAKE_CURRENT_SOURCE_DIR}/eBPF/secmon.bpf.c -o ${BPF_OBJ}
    DEPENDS eBPF/secmon.bpf.c eBPF/fileguard.bpf.c eBPF/selfguard.bpf.c eBPF/upchk.bpf.c eBPF/secmon.h "${VMLINUX}"
    VERBATIM)
# skeleton 从当前 ELF 生成并嵌入对象；src/main.cpp 调用生成的 open/load/attach/destroy 接口。
add_custom_command(OUTPUT "${BPF_SKEL}"
    COMMAND ${CMAKE_COMMAND} -DTOOL=${BPFTOOL_EXE} -DMODE=skeleton
        -DINPUT=${BPF_OBJ} -DOUTPUT=${BPF_SKEL}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/Bpftool.cmake
    DEPENDS "${BPF_OBJ}" cmake/Bpftool.cmake VERBATIM)
# 纯用户态公共库：配置读取/摘要、运行版本和 root 管理协议；没有 BPF/fanotify 挂载动作。
add_library(secmon-policy STATIC src/policy_config.cpp src/policy_runtime.cpp src/control.cpp
    src/management/protocol.cpp src/content_digest.cpp)
target_include_directories(secmon-policy PUBLIC src)
target_compile_options(secmon-policy PRIVATE -Wall -Wextra -Werror)
target_link_libraries(secmon-policy PUBLIC OpenSSL::Crypto)
add_executable(secmon
    src/main.cpp
    src/options.cpp
    src/events.cpp
    src/file_policy.cpp
    "${BPF_SKEL}")
# build 放在 eBPF 前面，确保使用新生成的 skeleton；仓库里的旧生成快照不是本次构建输入。
target_include_directories(secmon PRIVATE "${CMAKE_CURRENT_BINARY_DIR}" eBPF src)
target_compile_options(secmon PRIVATE -Wall -Wextra -Werror)
target_link_libraries(secmon PRIVATE PkgConfig::LIBBPF secmon-policy)

add_executable(secmon-fanotify src/fanotify/main.cpp src/fanotify/gate.cpp
    src/fanotify/decisions.cpp src/fanotify/options.cpp src/fanotify/event_kind.cpp
    src/fanotify/policy.cpp src/fanotify/status.cpp src/fanotify/stats.cpp
    src/analysis/client.cpp src/analysis/transport.cpp)
target_include_directories(secmon-fanotify PRIVATE src)
target_compile_options(secmon-fanotify PRIVATE -Wall -Wextra -Werror)
target_link_libraries(secmon-fanotify PRIVATE secmon-policy)

add_executable(secmon-analyzer src/analysis/worker_main.cpp src/analysis/scanner.cpp
    src/analysis/transport.cpp)
target_include_directories(secmon-analyzer PRIVATE src)
target_compile_options(secmon-analyzer PRIVATE -Wall -Wextra -Werror)

# CTest 运行无特权检查；真实加载 BPF、fanotify 权限事件和权限转换由 tests/run_privileged.py 另行组织。
include(CTest)
if(BUILD_TESTING)
    add_executable(secmon-policy-tests tests/policy_config.cpp)
    target_link_libraries(secmon-policy-tests PRIVATE secmon-policy)
    target_include_directories(secmon-policy-tests PRIVATE src)
    target_compile_options(secmon-policy-tests PRIVATE -Wall -Wextra -Werror)
    add_test(NAME policy-config COMMAND secmon-policy-tests)
    add_executable(secmon-management-tests tests/management.cpp)
    target_link_libraries(secmon-management-tests PRIVATE secmon-policy)
    target_include_directories(secmon-management-tests PRIVATE src)
    target_compile_options(secmon-management-tests PRIVATE -Wall -Wextra -Werror)
    add_test(NAME management-protocol COMMAND secmon-management-tests)
    add_executable(secmon-control-loop-tests tests/control_nonblocking.cpp)
    target_link_libraries(secmon-control-loop-tests PRIVATE secmon-policy)
    target_compile_options(secmon-control-loop-tests PRIVATE -Wall -Wextra -Werror)
    find_package(Threads REQUIRED)
    find_package(Python3 COMPONENTS Interpreter REQUIRED)
    add_executable(secmon-analysis-fault-worker tests/analysis_fault_worker.cpp src/analysis/transport.cpp)
    target_include_directories(secmon-analysis-fault-worker PRIVATE src)
    target_compile_options(secmon-analysis-fault-worker PRIVATE -Wall -Wextra -Werror)
    add_test(NAME analysis-protocol COMMAND ${Python3_EXECUTABLE} -B
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/analysis_protocol.py --build-dir $<TARGET_FILE_DIR:secmon-analyzer>)
    add_executable(secmon-analysis-allocation-tests tests/analysis_allocation.cpp src/analysis/transport.cpp)
    target_include_directories(secmon-analysis-allocation-tests PRIVATE src)
    target_compile_options(secmon-analysis-allocation-tests PRIVATE -Wall -Wextra -Werror)
    add_test(NAME analysis-allocation-failure COMMAND secmon-analysis-allocation-tests)
    add_executable(secmon-analysis-tests tests/analysis.cpp src/analysis/scanner.cpp src/analysis/transport.cpp)
    target_include_directories(secmon-analysis-tests PRIVATE src)
    target_compile_options(secmon-analysis-tests PRIVATE -Wall -Wextra -Werror)
    add_test(NAME analysis-content-transport COMMAND secmon-analysis-tests)
    add_executable(secmon-scan-fault-tests tests/analysis_scan_faults.cpp src/analysis/scanner.cpp)
    target_include_directories(secmon-scan-fault-tests PRIVATE src)
    target_compile_options(secmon-scan-fault-tests PRIVATE -Wall -Wextra -Werror)
    target_link_options(secmon-scan-fault-tests PRIVATE -Wl,--wrap=fstat -Wl,--wrap=pread)
    add_test(NAME analysis-scan-errors COMMAND secmon-scan-fault-tests)
    add_test(NAME analyzer-help COMMAND secmon-analyzer --help)
    add_executable(secmon-decision-tests tests/decisions.cpp src/fanotify/decisions.cpp)
    target_include_directories(secmon-decision-tests PRIVATE src)
    target_compile_options(secmon-decision-tests PRIVATE -Wall -Wextra -Werror)
    add_test(NAME fanotify-decisions COMMAND secmon-decision-tests)
    add_executable(secmon-privilege-report tests/privilege_report.cpp)
    target_compile_options(secmon-privilege-report PRIVATE -Wall -Wextra -Werror)
    add_test(NAME scenario-privilege-report COMMAND secmon-privilege-report)
    add_executable(secmon-lifecycle-scenario tests/lifecycle_scenario.cpp)
    add_test(NAME scenario-lifecycle COMMAND ${CMAKE_COMMAND}
        -DSCENARIO=$<TARGET_FILE:secmon-lifecycle-scenario>
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/lifecycle_smoke.cmake)
    target_link_libraries(secmon-lifecycle-scenario PRIVATE Threads::Threads)
    target_compile_options(secmon-lifecycle-scenario PRIVATE -Wall -Wextra -Werror)
    add_executable(secmon-scenarios tests/scenarios.cpp)
    target_link_libraries(secmon-scenarios PRIVATE Threads::Threads)
    target_compile_options(secmon-scenarios PRIVATE -Wall -Wextra -Werror)
    add_test(NAME fanotify-cli COMMAND ${CMAKE_COMMAND}
        -DSECMON=$<TARGET_FILE:secmon-fanotify> -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/fanotify_cli.cmake)
    add_test(NAME fanotify-help COMMAND secmon-fanotify --help)
    add_test(NAME cli-help COMMAND secmon --help)
    add_test(NAME cli-validation COMMAND ${CMAKE_COMMAND}
        -DSECMON=$<TARGET_FILE:secmon> -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/cli.cmake)
    add_test(NAME scenario-exec COMMAND secmon-scenarios exec)
    add_test(NAME scenario-thread-exec COMMAND secmon-scenarios thread-exec)
    add_test(NAME scenario-threads COMMAND secmon-scenarios threads)
endif()
