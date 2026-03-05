#include <sys/system_properties.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include "headers.h"
#include "xorstr.h"
#include "inline_syscall.h"

void emulator_check_properties(unsigned long long &state, int &detected_error, int choice, const char *target_value) {
    const char *property_name = nullptr;
    switch (choice) {
        case 1:
            property_name = XOR("ro.product.model");
            break;
        case 2:
            property_name = XOR("ro.build.fingerprint");
            break;
        case 3:
            property_name = XOR("ro.product.manufacturer");
            break;
        case 4:
            property_name = XOR("ro.product.device");
            break;
        case 5:
            property_name = XOR("ro.hardware");
            break;
        case 6:
            property_name = XOR("ro.kernel.qemu");
            break;
        case 7:
            property_name = XOR("ro.build.type");
            break;
        case 8:
            property_name = XOR("ro.build.tags");
            break;
        case 9:
            property_name = XOR("ro.board.platform");
            break;
        default:
            FLAG_SAFE()
    }

    char property_value[PROP_VALUE_MAX];
    if (__system_property_get(property_name, property_value) > 0) {
        if (strstr(property_value, target_value) != nullptr) {
            FLAG_THREAT(401)
        }
    }
    FLAG_SAFE()
}

long get_battery_voltage() {
    int fd = (int) cmd(__NR_openat, AT_FDCWD, (long) XOR("/sys/class/power_supply/battery/voltage_now"), O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) {
        return -1; 
    }

    char buffer[32];
    ssize_t bytes_read = (ssize_t) cmd(__NR_read, fd, (long) buffer, sizeof(buffer) - 1);
    cmd(__NR_close, fd);

    if (bytes_read <= 0) {
        return -1; 
    }

    buffer[bytes_read] = '\0';
    
    return strtol(buffer, nullptr, 10); 
}

void emulator_check_battery_voltage(unsigned long long &state, int &detected_error){
    long voltage = get_battery_voltage();
    if (voltage == -1){
        FLAG_SAFE()
    }
    if (voltage == 0){
        FLAG_THREAT(402)
    }
    FLAG_SAFE()
}

long get_cpu_temperature(int zone_index) {
    char path[256];
    snprintf(path, sizeof(path), "/sys/class/thermal/thermal_zone%d/temp", zone_index);
    int fd = (int) cmd(__NR_openat, AT_FDCWD, (long) path, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) {
        return -1; 
    }

    char buffer[32];
    ssize_t bytes_read = (ssize_t) cmd(__NR_read, fd, (long) buffer, sizeof(buffer) - 1);
    cmd(__NR_close, fd);

    if (bytes_read <= 0) {
        return -1; 
    }

    buffer[bytes_read] = '\0';

    return strtol(buffer, nullptr, 10); 
}

void emulator_check_cpu_temperature(unsigned long long &state, int &detected_error){
    int readable_sensors = 0;
    for (int i = 0; i < 10; i++) {
        long temperature = get_cpu_temperature(i);
        if (temperature > 0){
            FLAG_SAFE()
        }
        if (temperature == 0){
            readable_sensors++;
        }
    }
    if (readable_sensors > 0){
        FLAG_THREAT(403)
    }
    FLAG_SAFE()
}