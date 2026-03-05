#include <jni.h>
#include <stdint.h>
#ifndef HEADERS_H
#define HEADERS_H

extern uint64_t ROOT_FOUND;
extern uint64_t ROOT_NOT_FOUND;

#define FLAG_THREAT(error_code) \
    if (detected_error == 0 || (error_code < 400 && detected_error >= 400)) { \
        detected_error = error_code; \
    } \
    state = (state ^ ROOT_FOUND) << 1; \
    return;

#define FLAG_SAFE() \
    state = (state ^ ROOT_NOT_FOUND) >> 1; \
    return;

void check_su(unsigned long long &state, int &detected_error, const char *path);
void check_su_stat(unsigned long long &state, int &detected_error, const char *path);
void mount_point_discovery(unsigned long long &state, int &detected_error);
void mount_namespaces_check(unsigned long long &state, int &detected_error);
void env_variable_check(unsigned long long &state, int &detected_error, const char *target);
void debuggable_check(unsigned long long &state, int &detected_error);
void seal_inspection(unsigned long long &state, int &detected_error);
void process_detection(unsigned long long &state, int &detected_error, const char *target);
void dynamic_instrumentation_enabled(unsigned long long &state, int &detected_error, const char* target);
void selinux_auditing_enabled(unsigned long long &state, int &detected_error);
void port_scan(unsigned long long &state, int &detected_error, int port);
void nuclear_test(unsigned long long &state, int &detected_error, const char *path);
void anti_debugger_check(unsigned long long &state, int &detected_error);

long calibrate_timing_threshold(int iterations);

void time_check(unsigned long long &state, int &detected_error, long threshold);
void time_side_channel_vulnerability_detection_test(unsigned long long &state, int &detected_error);
void smoke_test(unsigned long long &state, int &detected_error);
void integrity_check(unsigned long long &state, int &detected_error, const char *target);
void bootloader_check(unsigned long long &state, int &detected_error);
void thread_check(unsigned long long &state, int &detected_error, const char *thread);
void fd_check(unsigned long long &state, int &detected_error, const char* target_path);
void emulator_check_properties(unsigned long long &state, int &detected_error, int choice, const char *target_value);
void emulator_check_battery_voltage(unsigned long long &state, int &detected_error);
void emulator_check_cpu_temperature(unsigned long long &state, int &detected_error);
void kernelsu_active_check(unsigned long long &state, int &detected_error);
void kernelsu_passive_check(unsigned long long &state, int &detected_error);
void got_check(unsigned long long &state, int &detected_error);
void path_check(unsigned long long &state, int &detected_error, const char *target);
void start_memory_monitor();

#endif