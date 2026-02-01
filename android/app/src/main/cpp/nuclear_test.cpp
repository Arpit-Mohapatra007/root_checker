#include <unistd.h>
#include <sys/syscall.h>
#include <fcntl.h>

bool nuclear_test(const char *path){
    int fd = syscall(__NR_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
    if (fd >= 0){
        syscall(__NR_close, fd);
        return true;
    }
    return false;
}