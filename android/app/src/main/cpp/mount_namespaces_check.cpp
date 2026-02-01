#include <stdio.h>
#include <string.h>

bool mount_namespaces_check(){
    FILE *fp = fopen("/proc/self/mountinfo", "r");
    if (fp == nullptr) {
        return true;
    }
    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        if(strstr(line,"/data/") != nullptr){
            continue;
        }
        if(strstr(line,"/apex/") != nullptr){
            continue;
        }
        if(strstr(line,"/mnt/") != nullptr){
            continue;
        }
        if(strstr(line,"/storage") != nullptr){
            continue;
        }
        if(strstr(line,"/system/apex") != nullptr){
            continue;
        }
        if(strstr(line,"/vendor/overlay") != nullptr){
            continue;
        }
        if((strstr(line,"/system")||strstr(line,"/vendor")) && (strstr(line,"tmpfs") || strstr(line,"overlay"))){
            fclose(fp);
            return true;
        }
    }
    fclose(fp);
    return false;
}