#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>
#include "xorstr.h"
#include <errno.h>
#include "headers.h"
#include "inline_syscall.h"

void selinux_auditing_enabled(unsigned long long &state, int &detected_error){
    int fd = (int)cmd(__NR_openat, AT_FDCWD, (long)XOR("/sys/fs/selinux/enforce"), O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) {
        if (fd == -EACCES || fd == -ENOENT){
            FLAG_SAFE()
        }
        FLAG_SAFE()
    }
    char buffer[4];
    ssize_t bytes = (ssize_t)cmd(__NR_read, fd, (long)buffer, sizeof(buffer) - 1);
    cmd(__NR_close, fd);
    if (bytes <= 0) {
        FLAG_SAFE()
    }
    if (buffer[0] == '0') {
        FLAG_THREAT(304)
    }
    FLAG_SAFE()
}