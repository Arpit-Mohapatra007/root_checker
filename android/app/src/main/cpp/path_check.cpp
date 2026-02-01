#include <stdlib.h>
#include <string.h>

bool path_check(const char *target){
    const char *env = getenv("PATH");
    if (env == nullptr) {
        return true;
    }
    if(strstr(env,target) != nullptr){
        return true;
    }
    return false;
}