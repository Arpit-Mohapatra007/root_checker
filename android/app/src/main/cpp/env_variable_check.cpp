#include <stdlib.h>
#include <string.h>

bool env_variable_check(const char *target){
    if (getenv(target) != NULL) {
        return true;
    }
    return false;
}