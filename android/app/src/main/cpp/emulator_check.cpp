#include <sys/system_properties.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

bool emulator_check_properties(int choice, const char *target_value) {
    const char *property_name = nullptr;
    switch (choice) {
        case 1:
            property_name = "ro.product.model";
            break;
        case 2:
            property_name = "ro.build.fingerprint";
            break;
        case 3:
            property_name = "ro.product.manufacturer";
            break;
        case 4:
            property_name = "ro.product.device";
            break;
        case 5:
            property_name = "ro.hardware";
            break;
        case 6:
            property_name = "ro.kernel.qemu";
            break;
        case 7:
            property_name = "ro.build.type";
            break;
        case 8:
            property_name = "ro.build.tags";
            break;
        case 9:
            property_name = "ro.board.platform";
            break;
        default:
            return false; 
    }

    char property_value[PROP_VALUE_MAX];
    if (__system_property_get(property_name, property_value) > 0) {
        if (strstr(property_value, target_value) != nullptr) {
            return true; 
        }
    }
    return false; 
}
long get_battery_voltage() {
    FILE *fp = fopen("/sys/class/power_supply/battery/voltage_now", "r");
    if (fp == nullptr) {
        return -1; 
    }

    char buffer[32];
    if (fgets(buffer, sizeof(buffer), fp) == nullptr) {
        fclose(fp);
        return -1; 
    }
    fclose(fp);
    return strtol(buffer, nullptr, 10); 
}

bool emulator_check_battery_voltage(){
    long voltage = get_battery_voltage();
    if (voltage == -1){
        return false;
    }
    if (voltage == 0){
        return true;
    }
    return false;
}

long get_cpu_temperature(int zone_index) {
    char path[256];
    snprintf(path, sizeof(path), "/sys/class/thermal/thermal_zone%d/temp", zone_index);
    FILE *fp = fopen(path, "r");
    if (fp == nullptr) {
        return -1; 
    }

    char buffer[32];
    if (fgets(buffer, sizeof(buffer), fp) == nullptr) {
        fclose(fp);
        return -1; 
    }
    fclose(fp);

    return strtol(buffer, nullptr, 10); 
}

bool emulator_check_cpu_temperature(){
    int readable_sensors = 0;
    for (int i = 0; i < 10; i++) {
        long temperature = get_cpu_temperature(i);
        if (temperature > 0){
            return false;
        }
        if (temperature == 0){
            readable_sensors++;
        }
    }
    if (readable_sensors == 0){
        return false;
    }
    return true;
}