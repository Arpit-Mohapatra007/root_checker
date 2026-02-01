#include <dirent.h>
#include <stdio.h>
#include <string.h>

bool process_detection(const char *target){
    DIR *dir = opendir("/proc");
    if(dir == nullptr){
        return false;
    }
    struct dirent *entry;
    while((entry = readdir(dir)) != nullptr){
        if(entry->d_name[0]>='0' && entry->d_name[0]<='9'){
            char path[256];
            snprintf(path, sizeof(path), "/proc/%s/cmdline", entry->d_name);
            FILE *fp = fopen(path, "r");
            if (fp == nullptr) {
                continue;
            }
            char cmdline[256];
            if (fgets(cmdline, sizeof(cmdline), fp) != nullptr){
                if (strstr(cmdline, target)) {
                    fclose(fp);
                    closedir(dir);
                    return true;
                }
            }
            fclose(fp);
        }
    }
    closedir(dir);
    return false;
}