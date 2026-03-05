#include <unistd.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include "headers.h"
#include "inline_syscall.h"

void nuclear_test(unsigned long long &state, int &detected_error, const char *path){
    int fd = (int)cmd(__NR_openat, AT_FDCWD, (long)path, O_RDONLY | O_CLOEXEC, 0);
    if (fd >= 0){
        cmd(__NR_close, fd);
        FLAG_THREAT(103)
    }
    FLAG_SAFE()
}