#include <stdio.h>
#include <string.h>

bool mount_point_discovery(){
    FILE *fp = fopen("/proc/mounts", "r");
    if (fp == nullptr) {
        return true;
    }
    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        if(strstr(line,"/system") && strstr(line,"rw")){
            fclose(fp);
            return true;
        }
    }
    fclose(fp);
    return false;
}