#include <sys/system_properties.h>
#include <string.h>

bool bootloader_check(){
    char flash_locked_prop[PROP_VALUE_MAX];
    char verified_boot_state_prop[PROP_VALUE_MAX];
    __system_property_get("ro.boot.flash.locked", flash_locked_prop);
    __system_property_get("ro.boot.verifiedbootstate", verified_boot_state_prop);
    return strcmp(flash_locked_prop, "1") != 0 || strcmp(verified_boot_state_prop, "green") != 0;
}