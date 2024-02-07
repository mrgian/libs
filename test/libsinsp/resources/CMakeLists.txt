include(ExternalProject)

install(
    DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    DESTINATION ${CMAKE_INSTALL_PREFIX}/test
    COMPONENT tests
)

add_subdirectory(health_dockerfiles)
add_subdirectory(large_container_dockerfiles)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/ipv6_traces/curl_google.scap 
    ${CMAKE_CURRENT_BINARY_DIR}/ipv6_traces/curl_google.scap COPYONLY
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/ipv6_traces/single_ipv6_conn.scap 
    ${CMAKE_CURRENT_BINARY_DIR}/ipv6_traces/single_ipv6_conn.scap COPYONLY
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/ipv6_traces/test_ipv6_client.scap
    ${CMAKE_CURRENT_BINARY_DIR}/ipv6_traces/test_ipv6_client.scap COPYONLY
)

execute_process(
    COMMAND "uname" "-m"
    OUTPUT_VARIABLE ARCH
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

if("${CMAKE_SIZEOF_VOID_P}" EQUAL "8")
    add_executable(execve execve.c)
    install(
        TARGETS execve
        DESTINATION ${CMAKE_INSTALL_PREFIX}/test/resources
        COMPONENT tests
    )

    # Build 32-bit tests only for architectures where that is supported
    if(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "x86_64")
        add_executable(execve32 execve.c)
        set_target_properties(execve32 PROPERTIES COMPILE_FLAGS "-m32" LINK_FLAGS "-m32")
        install(
            TARGETS execve32
            DESTINATION ${CMAKE_INSTALL_PREFIX}/test/resources
            COMPONENT tests
        )
    endif()
endif("${CMAKE_SIZEOF_VOID_P}" EQUAL "8")
