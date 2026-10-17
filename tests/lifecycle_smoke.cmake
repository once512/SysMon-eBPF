execute_process(COMMAND "${SCENARIO}"
    INPUT_FILE "${CMAKE_CURRENT_LIST_DIR}/lifecycle_commands.txt"
    RESULT_VARIABLE status OUTPUT_VARIABLE output ERROR_VARIABLE error TIMEOUT 5)
if(NOT "${status}" STREQUAL "0")
    message(FATAL_ERROR "Lifecycle helper failed: ${status}: ${output}${error}")
endif()
foreach(phase threads_ready threads_joined exec_worker exec_complete)
    if(NOT output MATCHES "\"phase\":\"${phase}\"")
        message(FATAL_ERROR "Missing phase ${phase}: ${output}")
    endif()
endforeach()
