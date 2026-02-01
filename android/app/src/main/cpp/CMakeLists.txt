cmake_minimum_required(VERSION 3.4.1)

project("root_checker")

add_library(
    root_checker
    SHARED
    native-lib.cpp
    check_su.cpp
    anti_debugger_check.cpp
    bootloader_check.cpp
    calibrate_timing_threshold.cpp
    debuggable_check.cpp
    dynamic_instrumentation.cpp
    emulator_check.cpp
    env_variable_check.cpp
    fd_check.cpp
    got_check.cpp
    integrity_check.cpp
    kernelsu_active_check.cpp
    kernelsu_passive_check.cpp
    mount_namespaces_check.cpp
    mount_point_discovery.cpp
    nuclear_test.cpp
    port_scanning.cpp
    process_detection.cpp
    seal_inspection.cpp
    selinux_auditing.cpp
    smoke_test.cpp
    thread_check.cpp
    timing_check.cpp
    timing_side_channel.cpp
    path_check.cpp
)

find_library(
    log-lib
    log
)

target_link_libraries(
    root_checker
    ${log-lib}
)