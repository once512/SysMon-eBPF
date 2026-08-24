include(ExternalProject)
# libbpf 编译输出重定向
set(LIBBPF_BUILD_DIR "${CMAKE_CURRENT_BINARY_DIR}/libbpf-build")
set(LIBBPF_INCLUDE_DIR "${LIBBPF_BUILD_DIR}/usr/include")
# 编译子模块中的 libbpf
# 用于生成所需的 bpf/bpf_helpers.h 以及静态链接库 libbpf.a
ExternalProject_Add(libbpf_ext
    SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/libbpf/src"
    CONFIGURE_COMMAND ""
    BUILD_COMMAND make BUILD_STATIC_ONLY=1 EXTRA_CFLAGS="-fPIE" DESTDIR=${LIBBPF_BUILD_DIR} install
    INSTALL_COMMAND ""
    BUILD_IN_SOURCE 1
)
