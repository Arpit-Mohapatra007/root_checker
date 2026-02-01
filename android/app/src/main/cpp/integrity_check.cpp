#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <dlfcn.h>
bool integrity_check(const char *target){
    void *handle = dlsym(RTLD_DEFAULT, target);
    if(handle == nullptr){
        return false;
    }
    Dl_info info;
    if(dladdr(handle, &info) == 0){
        return false;
    }
    uintptr_t clean_handle = (uintptr_t)handle & ~1;
    uintptr_t clean_base = (uintptr_t)info.dli_fbase;

    long offset = (long)handle - (long)info.dli_fbase;
    int fd = open(info.dli_fname, O_RDONLY);
    if (fd < 0) {
        return false;
    }
    lseek(fd, offset, SEEK_SET);
    char disk_bytes[8];
    read(fd, disk_bytes, 8);
    close(fd);
    char *ram_bytes = (char *)handle;
    if(memcmp(disk_bytes, ram_bytes, 8) != 0){
        return true;
    }
    return false;
}