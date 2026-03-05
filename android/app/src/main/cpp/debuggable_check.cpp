#include <sys/system_properties.h>
#include <string.h>
#include "headers.h"
#include "xorstr.h"

void debuggable_check(unsigned long long &state, int &detected_error){
    char prop_value[PROP_VALUE_MAX];
    __system_property_get(XOR("ro.debuggable"), prop_value);
    if (strcmp(prop_value, XOR("1")) == 0) {
        FLAG_THREAT(405)
    }
    FLAG_SAFE()
}