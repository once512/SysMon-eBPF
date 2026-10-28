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
find_package(Threads REQUIRED)
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
        -I${CMAKE_CURRENT_SOURCE_DIR}/eBPF -I${CMAKE_CURRENT_SOURCE_DIR}/include ${LIBBPF_CFLAGS}
        -c ${CMAKE_CURRENT_SOURCE_DIR}/eBPF/secmon.bpf.c -o ${BPF_OBJ}
    DEPENDS eBPF/response.bpf.c eBPF/secmon.bpf.c eBPF/writer_identity.bpf.c eBPF/fileguard.bpf.c eBPF/selfguard.bpf.c eBPF/upchk.bpf.c eBPF/secmon.h include/secmon/policy_limits.h include/secmon/file_operations.h "${VMLINUX}"
    VERBATIM)
# skeleton 从当前 ELF 生成并嵌入对象；BpfMonitor 调用生成的 open/load/attach/destroy 接口。
add_custom_command(OUTPUT "${BPF_SKEL}"
    COMMAND ${CMAKE_COMMAND} -DTOOL=${BPFTOOL_EXE} -DMODE=skeleton
        -DINPUT=${BPF_OBJ} -DOUTPUT=${BPF_SKEL}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/Bpftool.cmake
    DEPENDS "${BPF_OBJ}" cmake/Bpftool.cmake VERBATIM)
# 纯用户态公共库：配置读取/摘要、运行版本和 root 管理协议；没有 BPF/fanotify 挂载动作。
add_library(secmon-policy STATIC src/policy_config.cpp src/policy/source.cpp src/policy/fanotify_fields.cpp src/policy/writer_fields.cpp src/policy_runtime.cpp src/control.cpp src/control_client.cpp
    src/management/protocol.cpp src/management/channel.cpp src/content_digest.cpp src/boot_clock.cpp)
target_include_directories(secmon-policy PUBLIC src include)
target_compile_options(secmon-policy PRIVATE -Wall -Wextra -Werror)
target_link_libraries(secmon-policy PUBLIC OpenSSL::Crypto)
add_executable(secmon
    src/main.cpp
    src/service.cpp
    src/service_notify.cpp
    src/bpf/monitor.cpp
    src/options.cpp
    src/events.cpp
    src/event_format.cpp
    src/audit_sink.cpp
    src/diagnostic_output.cpp
    src/file_policy.cpp
    src/writer_identity.cpp
    src/policy_pins.cpp
    "${BPF_SKEL}")
# build 放在 eBPF 前面，确保使用新生成的 skeleton；仓库里的旧生成快照不是本次构建输入。
target_include_directories(secmon PRIVATE "${CMAKE_CURRENT_BINARY_DIR}" eBPF src)
target_compile_options(secmon PRIVATE -Wall -Wextra -Werror)
target_link_libraries(secmon PRIVATE PkgConfig::LIBBPF secmon-policy Threads::Threads)

# fanotify 与 BPF 链接进同一个服务；分析器仍是独立降权进程。
target_sources(secmon PRIVATE src/decoy/mount_identity.cpp src/decoy/provider.cpp src/fanotify/event_reader.cpp src/fanotify/monitor.cpp src/fanotify/gate.cpp
    src/fanotify/decisions.cpp src/fanotify/options.cpp src/fanotify/event_kind.cpp
    src/fanotify/policy.cpp src/fanotify/requester.cpp src/fanotify/metadata.cpp src/fanotify/audit.cpp src/fanotify/status.cpp src/fanotify/stats.cpp
    src/analysis/client.cpp src/analysis/transport.cpp)

add_executable(secmon-policyctl src/management/main.cpp)
target_link_libraries(secmon-policyctl PRIVATE secmon-policy)
target_compile_options(secmon-policyctl PRIVATE -Wall -Wextra -Werror)

# Optional view provider; the core security service does not depend on FUSE.
option(SECMON_BUILD_DECOYFS "Build immutable FUSE virtual decoy view" ON)
if(SECMON_BUILD_DECOYFS)
    pkg_check_modules(FUSE3 REQUIRED IMPORTED_TARGET fuse3)
    add_executable(secmon-decoyfs src/decoy/main.cpp src/decoy/mount_identity.cpp)
    target_include_directories(secmon-decoyfs PRIVATE src)
    target_compile_definitions(secmon-decoyfs PRIVATE _FILE_OFFSET_BITS=64)
    target_compile_options(secmon-decoyfs PRIVATE -Wall -Wextra -Werror)
    target_link_libraries(secmon-decoyfs PRIVATE PkgConfig::FUSE3)
endif()

add_executable(secmon-vaultctl src/vault/main.cpp src/vault/policy_edit.cpp src/vault/policy_file.cpp)
target_link_libraries(secmon-vaultctl PRIVATE secmon-policy)
target_compile_options(secmon-vaultctl PRIVATE -Wall -Wextra -Werror)

add_executable(secmon-vault-session src/vault_session_main.cpp)
target_link_libraries(secmon-vault-session PRIVATE secmon-policy)
target_compile_options(secmon-vault-session PRIVATE -Wall -Wextra -Werror)

add_executable(secmon-analyzer src/analysis/worker_main.cpp src/analysis/scanner.cpp
    src/analysis/transport.cpp)
target_include_directories(secmon-analyzer PRIVATE src)
target_compile_options(secmon-analyzer PRIVATE -Wall -Wextra -Werror)

# CTest 运行无特权检查；真实加载 BPF、fanotify 权限事件和权限转换由 tests/run_privileged.py 另行组织。
include(CTest)
if(BUILD_TESTING)
    if(SECMON_BUILD_DECOYFS)
        add_executable(secmon-virtual-decoy-scenario tests/virtual_decoy_scenario.cpp)
        target_compile_options(secmon-virtual-decoy-scenario PRIVATE -Wall -Wextra -Werror)
    endif()
    add_executable(secmon-metadata-compat tests/metadata_compat.cpp)
    target_compile_options(secmon-metadata-compat PRIVATE -m32 -fno-pie -fno-stack-protector
        -fno-exceptions -fno-rtti -Wall -Wextra -Werror)
    target_link_options(secmon-metadata-compat PRIVATE -m32 -nostdlib -static -no-pie -Wl,--build-id=none)
    add_executable(secmon-metadata-scenario tests/metadata_scenario.cpp)
    target_compile_options(secmon-metadata-scenario PRIVATE -Wall -Wextra -Werror)
    add_executable(secmon-response-scenario tests/response_scenario.cpp)
    target_link_libraries(secmon-response-scenario PRIVATE Threads::Threads)
    target_compile_options(secmon-response-scenario PRIVATE -Wall -Wextra -Werror)
    add_executable(secmon-writer-scenario tests/writer_scenario.cpp)
    target_compile_options(secmon-writer-scenario PRIVATE -Wall -Wextra -Werror)
    add_executable(secmon-audit-tests tests/audit_sink.cpp src/audit_sink.cpp)
    target_include_directories(secmon-audit-tests PRIVATE src include)
    target_link_libraries(secmon-audit-tests PRIVATE Threads::Threads)
    target_compile_options(secmon-audit-tests PRIVATE -Wall -Wextra -Werror)
    add_test(NAME audit-output-queue COMMAND secmon-audit-tests)
    add_executable(secmon-diagnostic-tests tests/diagnostic_output.cpp src/diagnostic_output.cpp src/audit_sink.cpp)
    target_include_directories(secmon-diagnostic-tests PRIVATE src include)
    target_link_libraries(secmon-diagnostic-tests PRIVATE Threads::Threads)
    target_compile_options(secmon-diagnostic-tests PRIVATE -Wall -Wextra -Werror)
    add_test(NAME diagnostic-output-queue COMMAND secmon-diagnostic-tests)
    add_executable(secmon-event-format-tests tests/event_format.cpp src/event_format.cpp)
    target_include_directories(secmon-event-format-tests PRIVATE src eBPF include)
    target_compile_options(secmon-event-format-tests PRIVATE -Wall -Wextra -Werror)
    add_test(NAME audit-event-format COMMAND secmon-event-format-tests)
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
    add_test(NAME vault-session-help COMMAND secmon-vault-session --help)
    add_test(NAME policyctl-help COMMAND secmon-policyctl --help)
    add_test(NAME policyctl-cli COMMAND ${CMAKE_COMMAND} -DPOLICYCTL=$<TARGET_FILE:secmon-policyctl>
        -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/policyctl_cli.cmake)
    find_package(Python3 COMPONENTS Interpreter REQUIRED)
    if(SECMON_BUILD_DECOYFS)
        add_test(NAME decoyfs-cli COMMAND ${Python3_EXECUTABLE} -B
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/decoy_cli.py --binary $<TARGET_FILE:secmon-decoyfs>)
    endif()
    add_test(NAME vault-session-declaration COMMAND ${Python3_EXECUTABLE} -B
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/vault_declaration.py --binary $<TARGET_FILE:secmon-vault-session>)
    add_test(NAME subscription-generations COMMAND ${Python3_EXECUTABLE} -B ${CMAKE_CURRENT_SOURCE_DIR}/tests/subscription_generations.py)
    add_test(NAME offline-evidence-grouping COMMAND ${Python3_EXECUTABLE} -B ${CMAKE_CURRENT_SOURCE_DIR}/tests/offline_evidence.py)
    add_test(NAME offline-behavior-rule COMMAND ${Python3_EXECUTABLE} -B ${CMAKE_CURRENT_SOURCE_DIR}/tests/offline_behavior.py)
    add_test(NAME offline-capture-replay COMMAND ${Python3_EXECUTABLE} -B ${CMAKE_CURRENT_SOURCE_DIR}/tests/capture_replay.py)
    add_test(NAME offline-capture-evaluation COMMAND ${Python3_EXECUTABLE} -B ${CMAKE_CURRENT_SOURCE_DIR}/tests/capture_evaluation.py)
    add_test(NAME offline-object-chains COMMAND ${Python3_EXECUTABLE} -B ${CMAKE_CURRENT_SOURCE_DIR}/tests/offline_chains.py)
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
    add_executable(secmon-requester-lifecycle tests/requester_lifecycle.cpp)
    target_link_libraries(secmon-requester-lifecycle PRIVATE Threads::Threads)
    target_compile_options(secmon-requester-lifecycle PRIVATE -Wall -Wextra -Werror)
    add_executable(secmon-requester-tests tests/requester_metadata.cpp src/fanotify/requester.cpp src/fanotify/metadata.cpp src/fanotify/decisions.cpp)
    target_include_directories(secmon-requester-tests PRIVATE src include)
    target_compile_options(secmon-requester-tests PRIVATE -Wall -Wextra -Werror)
    add_test(NAME requester-metadata-ownership COMMAND secmon-requester-tests)
    add_executable(secmon-permission-audit-tests tests/permission_audit.cpp src/fanotify/audit.cpp src/fanotify/requester.cpp src/fanotify/event_kind.cpp)
    target_include_directories(secmon-permission-audit-tests PRIVATE src include)
    target_compile_options(secmon-permission-audit-tests PRIVATE -Wall -Wextra -Werror)
    add_test(NAME fanotify-audit-format COMMAND secmon-permission-audit-tests)
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
        -DSECMON=$<TARGET_FILE:secmon> -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/fanotify_cli.cmake)
    add_test(NAME fanotify-help COMMAND secmon --help)
    add_executable(secmon-vault-file-fault-tests tests/vault_file_faults.cpp src/vault/policy_file.cpp)
    target_include_directories(secmon-vault-file-fault-tests PRIVATE src include)
    target_compile_options(secmon-vault-file-fault-tests PRIVATE -Wall -Wextra -Werror)
    target_link_options(secmon-vault-file-fault-tests PRIVATE -Wl,--wrap=fsync)
    add_executable(secmon-vault-edit-tests tests/vault_policy_edit.cpp src/vault/policy_edit.cpp)
    target_link_libraries(secmon-vault-edit-tests PRIVATE secmon-policy)
    target_compile_options(secmon-vault-edit-tests PRIVATE -Wall -Wextra -Werror)
    add_test(NAME vault-policy-edit COMMAND secmon-vault-edit-tests)
    add_test(NAME vaultctl-cli COMMAND ${Python3_EXECUTABLE} -B ${CMAKE_CURRENT_SOURCE_DIR}/tests/vaultctl_cli.py --binary $<TARGET_FILE:secmon-vaultctl>)
    add_library(secmon-deny-write-fault SHARED tests/deny_write_fault.cpp)
    target_link_libraries(secmon-deny-write-fault PRIVATE ${CMAKE_DL_LIBS})
    target_compile_options(secmon-deny-write-fault PRIVATE -Wall -Wextra -Werror)
    add_executable(secmon-notify-tests tests/service_notify.cpp src/service_notify.cpp)
    target_include_directories(secmon-notify-tests PRIVATE src)
    target_compile_options(secmon-notify-tests PRIVATE -Wall -Wextra -Werror)
    add_test(NAME service-notify COMMAND secmon-notify-tests)
    add_executable(secmon-mount-identity-tests tests/mount_identity.cpp src/decoy/mount_identity.cpp)
    target_include_directories(secmon-mount-identity-tests PRIVATE src)
    target_compile_options(secmon-mount-identity-tests PRIVATE -Wall -Wextra -Werror)
    add_test(NAME mount-identity COMMAND secmon-mount-identity-tests)
    add_executable(secmon-child-startup-tests tests/child_startup_cleanup.cpp
        src/analysis/client.cpp src/analysis/transport.cpp src/decoy/provider.cpp src/decoy/mount_identity.cpp)
    target_include_directories(secmon-child-startup-tests PRIVATE src)
    target_compile_options(secmon-child-startup-tests PRIVATE -Wall -Wextra -Werror)
    target_link_options(secmon-child-startup-tests PRIVATE
        -Wl,--wrap=posix_spawn -Wl,--wrap=syscall -Wl,--wrap=kill)
    add_test(NAME child-startup-cleanup COMMAND secmon-child-startup-tests)

    add_executable(secmon-decoy-fault-provider tests/decoy_fault_provider.cpp src/analysis/transport.cpp)
    target_include_directories(secmon-decoy-fault-provider PRIVATE src)
    target_compile_options(secmon-decoy-fault-provider PRIVATE -Wall -Wextra -Werror)

    add_test(NAME cli-help COMMAND secmon --help)
    add_test(NAME cli-validation COMMAND ${CMAKE_COMMAND}
        -DSECMON=$<TARGET_FILE:secmon> -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/cli.cmake)
    add_test(NAME scenario-exec COMMAND secmon-scenarios exec)
    add_test(NAME scenario-thread-exec COMMAND secmon-scenarios thread-exec)
    add_test(NAME scenario-threads COMMAND secmon-scenarios threads)
endif()

# 可选纯解析模糊测试，与特权服务构建无关；单独编译被测源以确保覆盖率和 sanitizer 真正插桩。
option(SECMON_BUILD_FUZZERS "Build Clang libFuzzer policy parser target" OFF)
if(SECMON_BUILD_FUZZERS)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "SECMON_BUILD_FUZZERS requires Clang; configure a separate build with clang++")
    endif()
    add_executable(secmon-policy-fuzzer tests/fuzz_policy.cpp src/policy_config.cpp
        src/policy/fanotify_fields.cpp src/policy/writer_fields.cpp)
    target_include_directories(secmon-policy-fuzzer PRIVATE src include)
    target_compile_options(secmon-policy-fuzzer PRIVATE -Wall -Wextra -Werror -g -O1
        -fno-omit-frame-pointer -fsanitize=fuzzer,address,undefined)
    target_link_options(secmon-policy-fuzzer PRIVATE -fsanitize=fuzzer,address,undefined)
endif()

# Install one matching runtime set. Internal helpers keep explicit configured
# paths; tests, generated headers and the private static library stay in build.
include(GNUInstallDirs)
install(TARGETS secmon secmon-policyctl secmon-vault-session secmon-vaultctl
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(TARGETS secmon-analyzer RUNTIME DESTINATION "${CMAKE_INSTALL_LIBEXECDIR}/secmon")
if(TARGET secmon-decoyfs)
    install(TARGETS secmon-decoyfs RUNTIME DESTINATION "${CMAKE_INSTALL_LIBEXECDIR}/secmon")
endif()
install(FILES README.md README_en.md DESIGN.md LICENSE LICENSE-MIT LICENSE-GPL
    DESTINATION "${CMAKE_INSTALL_DOCDIR}")
install(DIRECTORY docs/ DESTINATION "${CMAKE_INSTALL_DOCDIR}/docs" FILES_MATCHING PATTERN "*.md")
install(DIRECTORY examples/ DESTINATION "${CMAKE_INSTALL_DOCDIR}/examples" FILES_MATCHING PATTERN "*.conf" PATTERN "*.vim")

# Generate an operator-reviewed unit; installing binaries never enables it.
configure_file(packaging/secmon.service.in "${CMAKE_CURRENT_BINARY_DIR}/secmon.service" @ONLY)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/secmon.service" DESTINATION "${CMAKE_INSTALL_DOCDIR}/examples")
