#include <sys/system_properties.h>
#include <string.h>

bool debuggable_check(){
    char prop_value[PROP_VALUE_MAX];
    __system_property_get("ro.debuggable", prop_value);
    return strcmp(prop_value,"1") == 0;
}