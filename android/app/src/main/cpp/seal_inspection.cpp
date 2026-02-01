#include <sys/system_properties.h>
#include <string.h>
bool seal_inspection() {
    char prop_value[PROP_VALUE_MAX];
    __system_property_get("ro.build.tags", prop_value);
    return strstr(prop_value,"test-keys") != nullptr;
}