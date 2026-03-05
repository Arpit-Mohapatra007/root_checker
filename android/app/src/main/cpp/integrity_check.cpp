#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>
#include <dlfcn.h>
#include "headers.h"
#include "inline_syscall.h"

void integrity_check(unsigned long long &state, int &detected_error, const char *target){
    void *handle = dlsym(RTLD_DEFAULT, target);
    if(handle == nullptr){
        FLAG_SAFE()
    }
    Dl_info info;
    if(dladdr(handle, &info) == 0){
        FLAG_SAFE()
    }
    uintptr_t clean_handle = (uintptr_t)handle & ~1;
    uintptr_t clean_base = (uintptr_t)info.dli_fbase;

    long offset = (long)clean_handle - (long)clean_base;
    int fd = (int)cmd(__NR_openat, AT_FDCWD, (long)info.dli_fname, O_RDONLY|O_CLOEXEC, 0);
    if (fd < 0) {
        FLAG_SAFE()
    }
    off_t seek_result = (off_t)cmd(__NR_lseek, fd, offset, SEEK_SET);
    if (seek_result == -1){
        cmd(__NR_close, fd);
        FLAG_SAFE()
    }
    char disk_bytes[32];
    size_t bytes_read = (size_t)cmd(__NR_read, fd, (long)disk_bytes, sizeof(disk_bytes));
    cmd(__NR_close, fd);
    if (bytes_read != sizeof(disk_bytes)) {
        FLAG_SAFE()
    }
    char *ram_bytes = (char *)clean_handle;
    if(memcmp(disk_bytes, ram_bytes, sizeof(disk_bytes)) != 0){
        FLAG_THREAT(313)
    }
    FLAG_SAFE()
}