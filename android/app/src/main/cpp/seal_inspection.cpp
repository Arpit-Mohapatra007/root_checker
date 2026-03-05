#include <sys/system_properties.h>
#include <string.h>
#include "headers.h"
#include "xorstr.h"

void seal_inspection(unsigned long long &state, int &detected_error) {
    char prop_value[PROP_VALUE_MAX];
    __system_property_get(XOR("ro.build.tags"), prop_value);
    if (strstr(prop_value,XOR("test-keys")) != nullptr) {
        FLAG_THREAT(302)
    }
    FLAG_SAFE()
}