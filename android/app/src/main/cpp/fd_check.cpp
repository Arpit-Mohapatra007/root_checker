#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <stdio.h>
bool fd_check(const char* target_path){
    DIR *dir = opendir("/proc/self/fd");
    if (dir == nullptr) {
        return true;
    }
    struct dirent *entry;
    char path[256];
    char linked_path[256];
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_name[0] == '.') continue;
        snprintf(path, sizeof(path), "/proc/self/fd/%s", entry->d_name);
        ssize_t len = readlink(path, linked_path, sizeof(linked_path) - 1);
        if (len != -1){
            linked_path[len] = '\0';
            if (strstr(linked_path, target_path) != nullptr){
                closedir(dir);
                return true;
            }
        }
    }
    closedir(dir);
    return false;
}