#include <stdlib.h>
#include <string.h>
#include "headers.h"

void path_check(unsigned long long &state, int &detected_error, const char *target){
    const char *env = getenv("PATH");
    if (env == nullptr) {
        FLAG_THREAT(104)
    }
    if(strstr(env,target) != nullptr){
        FLAG_THREAT(104)
    }
    FLAG_SAFE()
}