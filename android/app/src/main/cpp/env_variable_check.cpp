#include <stdlib.h>
#include <string.h>
#include "headers.h"

void env_variable_check(unsigned long long &state, int &detected_error, const char *target){
    if (getenv(target) != NULL) {
        FLAG_THREAT(203)
    }
    FLAG_SAFE()
}