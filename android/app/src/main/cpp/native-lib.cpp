#include <jni.h>
#include <string>
#include <unordered_map>
#include <initializer_list>
#include "headers.h"
#include "xorstr.h"

using namespace std;

#define JNI_METHOD __attribute__((visibility("default"))) extern "C" JNIEXPORT 

template <typename... Args>
int scan_files_detailed(Args... args) {
    int result = 0;
    auto check_file_raw = [&](const char* path) -> int {
        if (check_su(path)) return 101;
        if (check_su_stat(path)) return 102;
        if (check_su_syscall(path)) return 101;
        if (nuclear_test(path)) return 103;
        return 0;
    };
    (void)initializer_list<int>{ (result = (result ? result : check_file_raw(args)), 0)... };
    return result;
}

template <typename... Args>
int scan_processes_detailed(Args... args) {
    int result = 0;
    auto check_proc_raw = [&](const char* target) -> int {
        if (process_detection(target)) return 201;
        if (thread_check(target)) return 202;
        return 0;
    };
    (void)initializer_list<int>{ (result = (result ? result : check_proc_raw(args)), 0)... };
    return result;
}

template <typename... Args>
int scan_env_vars(Args... args) {
    int result = 0;
    (void)initializer_list<int>{ (result = (result ? result : (env_variable_check(args) ? 203 : 0)), 0)... };
    return result;
}

template <typename... Args>
int scan_dirty_paths(Args... args) {
    int result = 0;
    (void)initializer_list<int>{ (result = (result ? result : (path_check(args) ? 104 : 0)), 0)... };
    return result;
}

template <typename... Args>
int scan_file_descriptors(Args... args) {
    int result = 0;
    (void)initializer_list<int>{ (result = (result ? result : (fd_check(args) ? 205 : 0)), 0)... };
    return result;
}

JNI_METHOD jint JNICALL
Java_com_example_root_1checker_MainActivity_nativeCheck(JNIEnv *env, jobject thisz){

    int file_result = scan_files_detailed(
        XOR("/sbin/su"), XOR("/system/bin/su"), XOR("/system/xbin/su"),
        XOR("/data/local/xbin/su"), XOR("/data/local/bin/su"), XOR("/system/sd/xbin/su"),
        XOR("/system/bin/failsafe/su"), XOR("/data/local/su"), XOR("/su/bin/su"),
        XOR("/system/bin/.ext/su"), XOR("/usr/bin/su"),
        XOR("/system/app/Superuser.apk"), XOR("/system/app/SuperSU/SuperSU.apk"),
        XOR("/system/app/SuperSU.apk"), XOR("/system/lib/libxposed_art.so"),
        XOR("/data/adb/magisk"), XOR("/data/adb/magisk.db"), 
        XOR("/data/adb/magisk.img"), XOR("/data/adb/magisk.log"),
        XOR("/data/adb/magisk.apk"), XOR("/data/adb/magisk.zip"),
        XOR("/data/adb/modules"), XOR("/data/adb/magisk/modules")
    );
    if (file_result != 0) return file_result;

    int dirty_result = scan_dirty_paths(
        XOR("/sbin"), XOR("/system/bin/.ext"), XOR("/system/sd/xbin"),
        XOR("/data/local/xbin"), XOR("/su/bin")
    );
    if (dirty_result != 0) return dirty_result;

    int proc_result = scan_processes_detailed(
        XOR("magisk"), XOR("magiskd"), XOR("su"), XOR("daemonsu"),
        XOR("super_user"), XOR("supersu"), XOR("superuser"),
        XOR("frida"), XOR("frida-server"), XOR("xposed"), XOR("substrate")
    );
    if (proc_result != 0) return proc_result;

    int env_result = scan_env_vars(
        XOR("MAGISK_VER_CODE"), XOR("MAGISK_VER_NAME"), 
        XOR("LD_PRELOAD"), XOR("XPOSED_FRAMEWORK")
    );
    if (env_result != 0) return env_result;

    int fd_result = scan_file_descriptors(
        XOR("/dev/socket/magisk"), XOR("/dev/magisk"),
        XOR("/system/framework/XposedBridge.jar"), XOR("/sys/fs/selinux/enforce")
    );
    if (fd_result != 0) return fd_result;

    int ports[]={ 27042, 27043 };
    for (int port : ports) {
        if(port_scan(port)) return 204;
    }

    unordered_map<int,string> target_properties={
        {6, XOR("1")}, {8, XOR("test-keys")}, {1, XOR("sdk")}, {1, XOR("google_sdk")},
        {1, XOR("sdk_x86")}, {1, XOR("Emulator")}, {5, XOR("goldfish")},
        {5, XOR("ranchu")}, {9, XOR("android")}
    };

    for (const auto& prop : target_properties) {
        if(emulator_check_properties((int)prop.first, prop.second.c_str())){
            return 401;
        }
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

    if(emulator_check_battery_voltage()) return 402;
    if(emulator_check_cpu_temperature()) return 403;
    if(bootloader_check()) return 404;
    if(debuggable_check()) return 405;
    if(anti_debugger_check()) return 406;

    return 0;
}