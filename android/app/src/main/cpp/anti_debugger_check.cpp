#include <stdio.h>
#include <string.h>
#include <stdlib.h>

bool anti_debugger_check(){
    FILE *fp = fopen("/proc/self/status", "r");
    if (fp == nullptr) {
        return true;
    }
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "TracerPid")) {
            char *value = strpbrk(line, "0123456789");
            if (value && atoi(value) != 0) {
                fclose(fp);
                return true;
            }
        }
    }
    fclose(fp);
    return false;
}