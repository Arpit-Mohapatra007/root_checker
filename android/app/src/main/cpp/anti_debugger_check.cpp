#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include "headers.h"
#include "xorstr.h"
#include "inline_syscall.h"

void anti_debugger_check(unsigned long long &state, int &detected_error){
    int fd = (int)cmd(__NR_openat, AT_FDCWD, (long)XOR("/proc/self/status"), O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) {
        FLAG_THREAT(406)
    }

    char buffer[4096];
    ssize_t bytes_read = (ssize_t)cmd(__NR_read, fd, (long)buffer, sizeof(buffer)-1);
    cmd(__NR_close, fd);

    if (bytes_read < 0) {
        FLAG_THREAT(406)
    }
    buffer[bytes_read] = '\0';

    char *tracer_pid = strstr(buffer, XOR("TracerPid:"));
    if(!tracer_pid) {
        FLAG_THREAT(406)
    }

    char *value = strpbrk(tracer_pid, XOR("0123456789"));

    if (value && atoi(value) != 0) {
        FLAG_THREAT(406)
    }
    
    FLAG_SAFE()
}