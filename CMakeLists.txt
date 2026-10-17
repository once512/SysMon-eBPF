cmake_minimum_required(VERSION 3.20)
project(SecMon LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)
find_program(CLANG_EXE NAMES clang REQUIRED)
find_program(BPFTOOL_EXE NAMES bpftool REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED IMPORTED_TARGET libbpf)
if(NOT CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64)$")
    message(FATAL_ERROR "Current implementation targets the development x86_64 kernel")
endif()
set(BPF_OBJ "${CMAKE_CURRENT_BINARY_DIR}/secmon.bpf.o")
set(BPF_SKEL "${CMAKE_CURRENT_BINARY_DIR}/secmon.skel.h")
set(VMLINUX "${CMAKE_CURRENT_BINARY_DIR}/vmlinux.h")
# sysfs timestamps may be in the future. Track BTF content, not its mtime.
# Reconfigure after switching kernels to refresh this identity.
file(SHA256 /sys/kernel/btf/vmlinux KERNEL_BTF_HASH)
file(CONFIGURE OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/kernel-btf.identity"
    CONTENT "@KERNEL_BTF_HASH@\n" @ONLY)
add_custom_command(OUTPUT "${VMLINUX}"
    COMMAND ${CMAKE_COMMAND} -DTOOL=${BPFTOOL_EXE} -DMODE=btf
        -DINPUT=/sys/kernel/btf/vmlinux -DOUTPUT=${VMLINUX}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/Bpftool.cmake
    DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/kernel-btf.identity" cmake/Bpftool.cmake VERBATIM)
add_custom_command(OUTPUT "${BPF_OBJ}"
    COMMAND ${CLANG_EXE} -g -O2 -target bpf -D__TARGET_ARCH_x86
        -Wall -Werror -I${CMAKE_CURRENT_BINARY_DIR}
        -I${CMAKE_CURRENT_SOURCE_DIR}/eBPF ${LIBBPF_CFLAGS}
        -c ${CMAKE_CURRENT_SOURCE_DIR}/eBPF/secmon.bpf.c -o ${BPF_OBJ}
    DEPENDS eBPF/secmon.bpf.c eBPF/fileguard.bpf.c eBPF/selfguard.bpf.c eBPF/upchk.bpf.c eBPF/secmon.h "${VMLINUX}"
    VERBATIM)
add_custom_command(OUTPUT "${BPF_SKEL}"
    COMMAND ${CMAKE_COMMAND} -DTOOL=${BPFTOOL_EXE} -DMODE=skeleton
        -DINPUT=${BPF_OBJ} -DOUTPUT=${BPF_SKEL}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/Bpftool.cmake
    DEPENDS "${BPF_OBJ}" cmake/Bpftool.cmake VERBATIM)
add_executable(secmon
    src/main.cpp
    src/options.cpp
    src/events.cpp
    src/control.cpp
    src/file_policy.cpp
    "${BPF_SKEL}")
target_include_directories(secmon PRIVATE "${CMAKE_CURRENT_BINARY_DIR}" eBPF)
target_compile_options(secmon PRIVATE -Wall -Wextra -Werror)
target_link_libraries(secmon PRIVATE PkgConfig::LIBBPF)

add_executable(secmon-fanotify src/fanotify/main.cpp src/fanotify/gate.cpp
    src/fanotify/decisions.cpp src/fanotify/options.cpp src/fanotify/event_kind.cpp)
target_include_directories(secmon-fanotify PRIVATE src)
target_compile_options(secmon-fanotify PRIVATE -Wall -Wextra -Werror)

include(CTest)
if(BUILD_TESTING)
    find_package(Threads REQUIRED)
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
