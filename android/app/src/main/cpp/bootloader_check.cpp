#include <sys/system_properties.h>
#include <string.h>
#include "headers.h"
#include "xorstr.h"

void bootloader_check(unsigned long long &state, int &detected_error){
    char flash_locked_prop[PROP_VALUE_MAX];
    char verified_boot_state_prop[PROP_VALUE_MAX];
    __system_property_get(XOR("ro.boot.flash.locked"), flash_locked_prop);
    __system_property_get(XOR("ro.boot.verifiedbootstate"), verified_boot_state_prop);
    
    if (strcmp(flash_locked_prop, XOR("1")) != 0 || strcmp(verified_boot_state_prop, XOR("green")) != 0) {
        FLAG_THREAT(404)
    }
    FLAG_SAFE()
}