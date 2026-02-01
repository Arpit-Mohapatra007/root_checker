#include <jni.h>
#include <string>
#include <unordered_map>
#include <iostream>
#include "headers.h"

using namespace std;

extern "C" JNIEXPORT jint JNICALL
Java_com_example_root_1checker_MainActivity_nativeCheck(JNIEnv *env, jobject thisz){

    const char *target_path[]={
        "/sbin/su", "/system/bin/su", "/system/xbin/su",
        "/data/local/xbin/su", "/data/local/bin/su", "/system/sd/xbin/su",
        "/system/bin/failsafe/su", "/data/local/su", "/su/bin/su",
        "/system/bin/.ext/su", "/usr/bin/su",
        "/system/app/Superuser.apk", "/system/app/SuperSU/SuperSU.apk",
        "/system/app/SuperSU.apk", "/system/lib/libxposed_art.so"
    };

    const char *targets[]={
        "magisk", "magiskd", "su", "daemonsu",
        "super_user", "supersu", "superuser",
        "frida", "frida-server", "xposed", "substrate"
    };

    const char *dirty_paths[] = {
        "/sbin",
        "/system/bin/.ext",
        "/system/sd/xbin",
        "/data/local/xbin",
        "/su/bin"
    };

    unordered_map<int,string> target_properties={
        {6, "1"}, {8, "test-keys"}, {1, "sdk"}, {1, "google_sdk"},
        {1, "sdk_x86"}, {1, "Emulator"}, {5, "goldfish"},
        {5, "ranchu"}, {9, "android"}
    };

    int ports[]={ 27042, 27043 };

    const char *env_vars[]={
        "MAGISK_VER_CODE", "MAGISK_VER_NAME", "LD_PRELOAD", "XPOSED_FRAMEWORK"
    };

    const char *file_descriptors[]={
        "/dev/socket/magisk", "/dev/magisk",
        "/system/framework/XposedBridge.jar", "/sys/fs/selinux/enforce"
    };


    size_t len_paths = sizeof(target_path) / sizeof(target_path[0]);
    for (int i = 0; i < len_paths; i++) {
        if(check_su(target_path[i])) return 101;
        if(check_su_stat(target_path[i])) return 102;
        if(nuclear_test(target_path[i])) return 103;
    }

    size_t len_targets = sizeof(targets) / sizeof(targets[0]);
    for (int i = 0; i < len_targets; i++) {
        if(process_detection(targets[i])) return 201;
        if(thread_check(targets[i])) return 202;
    }

    size_t len_env = sizeof(env_vars) / sizeof(env_vars[0]);
    for (int i = 0; i < len_env; i++) {
        if(env_variable_check(env_vars[i])) return 203;
    }

    size_t len_dirty = sizeof(dirty_paths) / sizeof(dirty_paths[0]);
    for (int i = 0; i < len_dirty; i++) {
        if (path_check(dirty_paths[i])) return 104;
    }

    size_t len_ports = sizeof(ports) / sizeof(ports[0]);
    for (int i = 0; i < len_ports; i++) {
        if(port_scan(ports[i])) return 204;
    }

    if(mount_namespaces_check()) return 301;
    if(seal_inspection()) return 302;
    if(dynamic_instrumentation_enabled()) return 303;
    if(selinux_auditing_enabled()) return 304;
    if(kernelsu_active_check()) return 305;
    if(kernelsu_passive_check()) return 306;
    if(mount_point_discovery()) return 307;
    if(got_check()) return 308;
    

    int threshold = calibrate_timing_threshold(1000);
    if(time_check(threshold)) return 310;
    if(time_side_channel_vulnerability_detection_test()) return 311;

    if(smoke_test()) return 312;
    if(integrity_check("Java_com_example_root_1checker_MainActivity_nativeCheck")) return 313;

    for (const auto& prop : target_properties) {
        if(emulator_check_properties((int)prop.first, prop.second.c_str())){
            return 401;
        }
    }

    if(emulator_check_battery_voltage()) return 402;
    if(emulator_check_cpu_temperature()) return 403;
    if(bootloader_check()) return 404;
    if(debuggable_check()) return 405;
    if(anti_debugger_check()) return 406;

    if (sizeof(file_descriptors)/sizeof(file_descriptors[0]) > 0) {
        for (int i = 0; i < sizeof(file_descriptors)/sizeof(file_descriptors[0]); i++) {
            if(fd_check(file_descriptors[i])) return 205; 
        }
    }

    return 0;
}