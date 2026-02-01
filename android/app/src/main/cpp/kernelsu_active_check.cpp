#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>

bool kernelsu_active_check(){
    DIR *dir = opendir("/dev");
    if (dir == NULL) {
        return false;
    }
    struct dirent *entry;
    while((entry = readdir(dir)) != nullptr){
        if (entry->d_name[0] == '.') {
            continue;
        }
        if (strstr(entry->d_name, "watchdog") != nullptr){
            continue;
        }
        char path[1024];
        snprintf(path, sizeof(path), "/dev/%s", entry->d_name);
        int fd = open(path, O_RDONLY|O_NONBLOCK);
        if (fd < 0) {
            continue;
        }
        int result = ioctl(fd, 0xDEADBEEF, nullptr);
        close(fd);
        if (result == 0) {
            closedir(dir);
            return true;
        }
    }
    closedir(dir);
    return false;
}