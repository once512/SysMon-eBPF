# bpftool 的生成步骤封装：BTF 导出内核类型，BPF ELF 导出宿主 skeleton；成功后才替换最终输出，避免留下半文件。
if(MODE STREQUAL "btf")
    set(ARGS btf dump file "${INPUT}" format c)
elseif(MODE STREQUAL "skeleton")
    set(ARGS gen skeleton "${INPUT}")
else()
    message(FATAL_ERROR "Unknown bpftool mode")
endif()
# OUTPUT_FILE 直接写临时文件，检查工具退出码后再 rename，失败时不留下貌似有效的最终生成物。
execute_process(COMMAND "${TOOL}" ${ARGS} OUTPUT_FILE "${OUTPUT}.tmp"
    RESULT_VARIABLE RESULT ERROR_VARIABLE ERROR)
if(NOT RESULT EQUAL 0)
    file(REMOVE "${OUTPUT}.tmp")
    message(FATAL_ERROR "bpftool failed: ${ERROR}")
endif()
file(RENAME "${OUTPUT}.tmp" "${OUTPUT}")
