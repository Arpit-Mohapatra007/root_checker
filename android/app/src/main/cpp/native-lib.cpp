#include <jni.h>
#include <string>
#include <vector>
#include <utility>
#include <initializer_list>
#include "headers.h"
#include "xorstr.h"

using namespace std;

uint64_t derive_constants(const string& nonce, uint64_t index){
    uint64_t hash = 14695981039346656037ULL;
    uint64_t prime = 1099511628211ULL;

    hash ^= (uint64_t)index;
    hash *= prime;

    for (char c:nonce){
        hash ^= (uint8_t)c;
        hash *= prime;
    }

    return hash;
}

#define JNI_METHOD __attribute__((visibility("default"))) extern "C" JNIEXPORT 
uint64_t ROOT_FOUND = 0;
uint64_t ROOT_NOT_FOUND = 0;

template <typename... Args>
void scan_files_detailed(unsigned long long &state, int &detected_error ,Args... args) {
    auto check_file_raw = [&](const char* path){
        int error_code = 0;
        if (check_su(path)) error_code = 101;
        if (check_su_stat(path)) error_code = 102;
        if (check_su_syscall(path)) error_code = 101;
        if (nuclear_test(path)) error_code = 103;
        if (error_code != 0) {
            if (detected_error == 0) detected_error = error_code;
            state = (state^ROOT_FOUND) << 1;
        } else {
            state = (state^ROOT_NOT_FOUND) >> 1;
        }
    };
    (void)initializer_list<int>{(check_file_raw(args), 0)... };
}

template <typename... Args>
void scan_processes_detailed(unsigned long long& state, int& detected_error, Args... args) {
    auto check_proc_raw = [&](const char* target) {
        int local_err = 0;
        if (process_detection(target)) local_err = 201;
        else if (thread_check(target)) local_err = 202;

        if (local_err != 0) {
            if (detected_error == 0) detected_error = local_err;
            state = (state ^ ROOT_FOUND) << 1;
        } else {
            state = (state ^ ROOT_NOT_FOUND) >> 1;
        }
    };
    (void)initializer_list<int>{ (check_proc_raw(args), 0)... };
}

template <typename... Args>
void scan_env_vars(unsigned long long& state, int& detected_error, Args... args) {
    auto check_env_raw = [&](const char* target) {
        if (env_variable_check(target)) {
            if (detected_error == 0) detected_error = 203;
            state = (state ^ ROOT_FOUND) << 1;
        } else {
            state = (state ^ ROOT_NOT_FOUND) >> 1;
        }
    };
    (void)initializer_list<int>{ (check_env_raw(args), 0)... };
}

template <typename... Args>
void scan_dirty_paths(unsigned long long& state, int& detected_error, Args... args) {
    auto check_path_raw = [&](const char* target) {
        if (path_check(target)) {
            if (detected_error == 0) detected_error = 104;
            state = (state ^ ROOT_FOUND) << 1;
        } else {
            state = (state ^ ROOT_NOT_FOUND) >> 1;
        }
    };
    (void)initializer_list<int>{ (check_path_raw(args), 0)... };
}

template <typename... Args>
void scan_file_descriptors(unsigned long long& state, int& detected_error, Args... args) {
    auto check_fd_raw = [&](const char* target) {
        if (fd_check(target)) {
            if (detected_error == 0) detected_error = 205;
            state = (state ^ ROOT_FOUND) << 1;
        } else {
            state = (state ^ ROOT_NOT_FOUND) >> 1;
        }
    };
    (void)initializer_list<int>{ (check_fd_raw(args), 0)... };
}

JNI_METHOD jstring JNICALL
Java_com_example_root_1checker_MainActivity_nativeCheck(JNIEnv *env, jobject thisz, jstring nonce_from_java) {
    const char *nonce_cstr = env->GetStringUTFChars(nonce_from_java,0);
    string nonce_str(nonce_cstr);

    env->ReleaseStringUTFChars(nonce_from_java, nonce_cstr);


    ROOT_FOUND = derive_constants(nonce_str, 1759639709ULL);
    ROOT_NOT_FOUND = derive_constants(nonce_str, 3726535711ULL);
    
    unsigned long long state = stoull(nonce_str, nullptr, 16);
    
    int detected_error = 0;

    scan_files_detailed(
        state, detected_error,
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
    scan_dirty_paths(
        state, detected_error,
        XOR("/sbin"), XOR("/system/bin/.ext"), XOR("/system/sd/xbin"),
        XOR("/data/local/xbin"), XOR("/su/bin")
    );
    scan_processes_detailed(
        state, detected_error,
        XOR("magisk"), XOR("magiskd"), XOR("su"), XOR("daemonsu"),
        XOR("super_user"), XOR("supersu"), XOR("superuser"),
        XOR("frida"), XOR("frida-server"), XOR("xposed"), XOR("substrate")
    );
    scan_env_vars(
        state, detected_error,
        XOR("MAGISK_VER_CODE"), XOR("MAGISK_VER_NAME"), 
        XOR("LD_PRELOAD"), XOR("XPOSED_FRAMEWORK")
    );
    scan_file_descriptors(
        state, detected_error,
        XOR("/dev/socket/magisk"), XOR("/dev/magisk"),
        XOR("/system/framework/XposedBridge.jar"), XOR("/sys/fs/selinux/enforce")
    );

    int ports[]={ 27042, 27043 };
    for (int port : ports) {
        if(port_scan(port)){
            if (detected_error == 0) detected_error = 204;
            state = (state ^ ROOT_FOUND) << 1;
        } else {
            state = (state ^ ROOT_NOT_FOUND) >> 1;
        }
    }

    vector<pair<int,string>> target_properties={
        {6, XOR("1")}, {8, XOR("test-keys")}, {1, XOR("sdk")}, {1, XOR("google_sdk")},
        {1, XOR("sdk_x86")}, {1, XOR("Emulator")}, {5, XOR("goldfish")},
        {5, XOR("ranchu")}, {9, XOR("android")}
    };

    for (const auto& prop : target_properties) {
        if(emulator_check_properties((int)prop.first, prop.second.c_str())){
            if (detected_error == 0) detected_error = 401;
            state = (state ^ ROOT_FOUND) << 1;
        } else {
            state = (state ^ ROOT_NOT_FOUND) >> 1;
        }
    }

    auto run_check = [&](bool is_dirty, int error_code) {
        if (is_dirty) {
            if (detected_error == 0) detected_error = error_code;
            state = (state ^ ROOT_FOUND) << 1;
        } else {
            state = (state ^ ROOT_NOT_FOUND) >> 1;
        }
    };

    run_check(mount_namespaces_check(), 301);
    run_check(seal_inspection(), 302);
    run_check(dynamic_instrumentation_enabled(), 303);
    run_check(selinux_auditing_enabled(), 304);
    run_check(kernelsu_active_check(), 305);
    run_check(kernelsu_passive_check(), 306);
    run_check(mount_point_discovery(), 307);
    run_check(got_check(), 308);

    int threshold = calibrate_timing_threshold(1000);
    run_check(time_check(threshold), 310);
    run_check(time_side_channel_vulnerability_detection_test(), 311);
    run_check(smoke_test(), 312);
    run_check(integrity_check("Java_com_example_root_1checker_MainActivity_nativeCheck"), 313);

    run_check(emulator_check_battery_voltage(), 402);
    run_check(emulator_check_cpu_temperature(), 403);
    run_check(bootloader_check(), 404);
    run_check(debuggable_check(), 405);
    run_check(anti_debugger_check(), 406);

    char result[256];
    snprintf(result, sizeof(result), "%llx|%d" , state, detected_error);
    return env->NewStringUTF(result);
}