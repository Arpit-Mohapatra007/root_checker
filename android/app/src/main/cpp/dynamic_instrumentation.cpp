#include <stdio.h>
#include <string.h>

bool dynamic_instrumentation_enabled() {
    FILE *fp = fopen("/proc/self/maps","r");
    if (fp == nullptr) {
        return true;
    }
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "r-xp") && 
            (strstr(line, "/data/local/tmp") || 
             strstr(line, "frida") || 
             strstr(line, "xposed") ||
             strstr(line, "substrate"))) {
            fclose(fp);
            return true;
        }
    }
    fclose(fp);
    return false;
}