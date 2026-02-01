#include <dirent.h>
#include <stdio.h>
#include <string.h>

bool thread_check(const char *thread){
    DIR *dir = opendir("/proc/self/task/");
    if (dir == nullptr) {
        return true;
    }
    struct dirent *entry;
    while ((entry = readdir(dir)) != nullptr) {
        char path[256];
        snprintf(path, sizeof(path), "/proc/self/task/%s/comm", entry->d_name);
        FILE *file = fopen(path, "r");
        if (file == nullptr) {
            continue;
        }
        char threads[1024];
        if (fgets(threads, sizeof(threads), file) != nullptr) {
            threads[strcspn(threads, "\n")] = '\0';
            if(strstr(threads, thread) != nullptr){
                fclose(file);
                closedir(dir);
                return true;
            }
        }
        fclose(file);
    }
    closedir(dir);
    return false;
}