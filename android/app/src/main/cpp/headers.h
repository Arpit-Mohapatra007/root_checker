#include <jni.h>
#ifndef HEADERS_H
#define HEADERS_H
bool check_su(const char *path);
bool check_su_stat(const char *path);
bool mount_point_discovery();
bool mount_namespaces_check();
bool env_variable_check(const char *target);
bool debuggable_check();
bool seal_inspection(); 
bool process_detection(const char *target);
bool dynamic_instrumentation_enabled();
bool selinux_auditing_enabled();
bool port_scan(int port);
bool nuclear_test(const char *path); 
bool anti_debugger_check();
long calibrate_timing_threshold(int iterations);
bool time_check(long threshold);
bool time_side_channel_vulnerability_detection_test();
bool smoke_test();
bool integrity_check(const char *target);
bool bootloader_check();
bool thread_check(const char *thread);
bool fd_check(const char* target_path);
bool emulator_check_properties(int choice, const char *target_value);
bool emulator_check_battery_voltage();
bool emulator_check_cpu_temperature();
bool kernelsu_active_check();
bool kernelsu_passive_check();
bool got_check();
bool path_check(const char *target);
#endif