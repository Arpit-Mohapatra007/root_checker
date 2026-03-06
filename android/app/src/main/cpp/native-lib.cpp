#include <jni.h>
#include <string>
#include <vector>
#include <utility>
#include <initializer_list>
#include "headers.h"
#include "xorstr.h"
#define JNI_METHOD __attribute__((visibility("default"))) extern "C" JNIEXPORT 
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

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    start_memory_monitor();
    return JNI_VERSION_1_6;
}

JNI_METHOD jstring JNICALL
Java_com_example_root_1checker_PackageObfuscator_getPackageKey(JNIEnv *env, jclass) {
    return env->NewStringUTF(XOR("AegIs_Pkg_S3cur3K"));
}

JNI_METHOD jstring JNICALL
Java_com_example_root_1checker_UrlObfuscator_getUrlKey(JNIEnv *env, jclass) {
    return env->NewStringUTF(XOR("AegIs_Url_S3cur3K"));
}

JNI_METHOD jstring JNICALL
Java_com_example_root_1checker_SignatureVerifier_getXorKey(JNIEnv *env, jclass) {
    return env->NewStringUTF(XOR("AegIs_Sig_S3cur3K"));
}

uint64_t ROOT_FOUND = 0;
uint64_t ROOT_NOT_FOUND = 0;

template <typename... Args>
void scan_files_detailed(unsigned long long &state, int &detected_error, Args... args) {
    auto check_file_raw = [&](const char* path){
        check_su(state, detected_error, path);
        check_su_stat(state, detected_error, path);
        nuclear_test(state, detected_error, path);
    };
    (void)initializer_list<int>{(check_file_raw(args), 0)... };
}

template <typename... Args>
void scan_processes_detailed(unsigned long long& state, int& detected_error, Args... args) {
    auto check_proc_raw = [&](const char* target) {
        process_detection(state, detected_error, target);
        thread_check(state, detected_error, target);
    };
    (void)initializer_list<int>{ (check_proc_raw(args), 0)... };
}

template <typename... Args>
void scan_env_vars(unsigned long long& state, int& detected_error, Args... args) {
    auto check_env_raw = [&](const char* target) {
        env_variable_check(state, detected_error, target);
    };
    (void)initializer_list<int>{ (check_env_raw(args), 0)... };
}

template <typename... Args>
void scan_dirty_paths(unsigned long long& state, int& detected_error, Args... args) {
    auto check_path_raw = [&](const char* target) {
        path_check(state, detected_error, target);
    };
    (void)initializer_list<int>{ (check_path_raw(args), 0)... };
}

template <typename... Args>
void scan_file_descriptors(unsigned long long& state, int& detected_error, Args... args) {
    auto check_fd_raw = [&](const char* target) {
        fd_check(state, detected_error, target);
    };
    (void)initializer_list<int>{ (check_fd_raw(args), 0)... };
}

template <typename... Args>
void scan_dynamic_instrumentation(unsigned long long &state, int &detected_error, Args... args){
    auto check_dynamic_raw = [&](const char* target) {
        dynamic_instrumentation_enabled(state, detected_error, target);
    };
    (void)initializer_list<int>{ (check_dynamic_raw(args), 0)... };
}

JNI_METHOD jstring JNICALL
Java_com_example_root_1checker_MainActivity_nativeCheck(JNIEnv *env, jobject thisz, jstring nonce_from_java,jboolean is_repackaged, jboolean is_tampered, jboolean is_adb, jboolean is_accessibility, jboolean is_dev, jboolean has_malicious) {
    const char *nonce_cstr = env->GetStringUTFChars(nonce_from_java,0);
    string nonce_str(nonce_cstr);

    env->ReleaseStringUTFChars(nonce_from_java, nonce_cstr);

    ROOT_FOUND = derive_constants(nonce_str, 1759639709ULL);
    ROOT_NOT_FOUND = derive_constants(nonce_str, 3726535711ULL);
    
    unsigned long long state = 0;
    for (char c : nonce_str) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            char result[256];
            snprintf(result, sizeof(result),"0|999");
            return env->NewStringUTF(result);
        }
        state = state * 16 + (c >= 'a' ? c - 'a' + 10 : c >= 'A' ? c - 'A' + 10 : c - '0');
    }
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
        XOR("frida"), XOR("frida-server"), XOR("xposed"), XOR("substrate"),
        XOR("gum-js-loop"), XOR("gmain"), XOR("linjector"), XOR("frida-agent")
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

    scan_dynamic_instrumentation(
        state, detected_error,
        XOR("/data/local/tmp"), XOR("frida"), XOR("xposed"), XOR("substrate"), XOR("gum"), XOR("gum-js-loop")
    );

    int ports[]={ 27042, 27043, 9999, 12345 };
    for (int port : ports) {
        port_scan(state, detected_error, port);
    }

    vector<pair<int,string>> target_properties={
        {6, XOR("1")}, {8, XOR("test-keys")}, {1, XOR("sdk")}, {1, XOR("google_sdk")},
        {1, XOR("sdk_x86")}, {1, XOR("Emulator")}, {5, XOR("goldfish")},
        {5, XOR("ranchu")}, {9, XOR("android")}
    };

    for (const auto& prop : target_properties) {
        emulator_check_properties(state, detected_error, (int)prop.first, prop.second.c_str());
    }

    mount_namespaces_check(state, detected_error);
    seal_inspection(state, detected_error);
    selinux_auditing_enabled(state, detected_error);
    kernelsu_active_check(state, detected_error);
    kernelsu_passive_check(state, detected_error);
    mount_point_discovery(state, detected_error);
    got_check(state, detected_error);

    int threshold = calibrate_timing_threshold(1000);
    time_check(state, detected_error, threshold);
    time_side_channel_vulnerability_detection_test(state, detected_error);
    smoke_test(state, detected_error);
    integrity_check(state, detected_error, XOR("Java_com_example_root_1checker_MainActivity_nativeCheck"));

    emulator_check_battery_voltage(state, detected_error);
    emulator_check_cpu_temperature(state, detected_error);
    bootloader_check(state, detected_error);
    debuggable_check(state, detected_error);
    anti_debugger_check(state, detected_error);


    if (is_repackaged) { 
        if (detected_error == 0 || detected_error >= 400) detected_error = 314; 
        state = (state ^ ROOT_FOUND) << 1; 
    }
    if (has_malicious) { 
        if (detected_error == 0 || detected_error >= 400) detected_error = 201; 
        state = (state ^ ROOT_FOUND) << 1; 
    }
    if (is_tampered) { 
        if (detected_error == 0 || detected_error >= 400) detected_error = 316; 
        state = (state ^ ROOT_FOUND) << 1; 
    }
    if (is_adb) { 
        if (detected_error == 0) detected_error = 407; 
        state = (state ^ ROOT_FOUND) << 1; 
    }
    if (is_accessibility) { 
        if (detected_error == 0) detected_error = 408; 
        state = (state ^ ROOT_FOUND) << 1; 
    }
    if (is_dev) { 
        if (detected_error == 0) detected_error = 409; 
        state = (state ^ ROOT_FOUND) << 1; 
    }

    char result[256];
    snprintf(result, sizeof(result), "%llx|%d" , state, detected_error);
    return env->NewStringUTF(result);
}