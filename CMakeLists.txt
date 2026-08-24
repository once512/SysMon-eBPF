cmake_minimum_required(VERSION 3.10)

set(CMAKE_C_COMPILER "clang")
set(CMAKE_CXX_COMPILER "clang++")

project(SecMon C CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_program(CLANG_EXE clang REQUIRED)
find_program(BPFTOOL_EXE bpftool REQUIRED)

# 引入libbpf
include(3rdparty.cmake)

set(BPF_SRC "${CMAKE_CURRENT_SOURCE_DIR}/eBPF/secmon.bpf.c")
set(BPF_OBJ "${CMAKE_CURRENT_BINARY_DIR}/secmon.bpf.o")
set(BPF_SKEL "${CMAKE_CURRENT_BINARY_DIR}/secmon.skel.h")

# eBPF 源码
add_custom_command(
    OUTPUT ${BPF_OBJ}
    COMMAND ${CLANG_EXE} -g -O2 -target bpf -D__TARGET_ARCH_x86
            -I ${LIBBPF_INCLUDE_DIR}
            -Wno-missing-declarations
            -c ${BPF_SRC} -o ${BPF_OBJ}
    DEPENDS ${BPF_SRC}
    COMMENT "Compiling BPF object: ${BPF_OBJ}"
)

# 指定依赖关系
# 强制先编译完 libbpf，再编译 eBPF 源码
add_custom_target(generate_bpf_obj DEPENDS ${BPF_OBJ})
add_dependencies(generate_bpf_obj libbpf_ext)

# 生成 CO-RE 骨架
add_custom_command(
    OUTPUT ${BPF_SKEL}
    COMMAND ${BPFTOOL_EXE} gen skeleton ${BPF_OBJ} > ${BPF_SKEL}
    DEPENDS ${BPF_OBJ}
    COMMENT "Generating BPF skeleton: ${BPF_SKEL}"
)

add_custom_target(generate_bpf_skel DEPENDS ${BPF_SKEL})
add_dependencies(generate_bpf_skel generate_bpf_obj)

# 编译 C++ 宿主
add_executable(secmon main.cpp)
add_dependencies(secmon generate_bpf_skel)

target_include_directories(secmon PRIVATE
    ${CMAKE_CURRENT_BINARY_DIR}
    ${LIBBPF_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/libbpf/include/uapi
)

target_link_directories(secmon PRIVATE
    "${LIBBPF_BUILD_DIR}/usr/lib"
    "${LIBBPF_BUILD_DIR}/usr/lib64"
)

target_link_libraries(secmon bpf elf z)
