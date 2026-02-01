#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <unistd.h>

int get_kernelsu_major_ID(){
    FILE *file = fopen("/proc/devices", "r");
    if (file == NULL) {
        return -1;
    }
    char line[256];
    while (fgets(line, sizeof(line), file) != NULL) {
        if (strstr(line, "kernelsu") != NULL || strstr(line, "ksu") != NULL) {
            fclose(file);
            return atoi(strtok(line, " "));
        }
    }
    fclose(file);
    return -1;
}

bool scan_dev_kernelsu(int major_id) {
    if (major_id == -1) {
        return false;
    }
    DIR *dir = opendir("/dev");
    if (dir == NULL) {
        return true;
    }
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        char path[256];
        snprintf(path, sizeof(path), "/dev/%s", entry->d_name);
        struct stat st;
        if (stat(path, &st) == 0) {
            if (S_ISCHR(st.st_mode) && major(st.st_rdev) == major_id) {
                closedir(dir);
                return true;
            }
        }
    }
    closedir(dir);
    return false;
}

bool kernelsu_passive_check() {
    int major_id = get_kernelsu_major_ID();
    if (major_id != -1) {
        if(scan_dev_kernelsu(major_id)) {
            return true;
        }
        return true;
    }

    if(access("/dev/kernelsu", F_OK) == 0 || access("/dev/ksu", F_OK) == 0) {
        return true;
    }
    return false;
}