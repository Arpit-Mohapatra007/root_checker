#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>
#include "headers.h"
#include "xorstr.h"
#include "inline_syscall.h"

void dynamic_instrumentation_enabled(unsigned long long &state, int &detected_error, const char* target) {
    int fd = (int)cmd(__NR_openat, AT_FDCWD, (long)XOR("/proc/self/maps"), O_RDONLY|O_CLOEXEC, 0);
    if (fd < 0) {
        FLAG_SAFE()
    }

    char buffer[4096];
    char line[1024];
    int line_pos = 0;

    while(true) {
        ssize_t bytes_read = (ssize_t)cmd(__NR_read, fd, (long)buffer, sizeof(buffer));
        if (bytes_read <= 0) {
            break;
        }
        for (ssize_t i = 0; i<bytes_read; i++) {
            if (buffer[i] == '\n' || line_pos >= sizeof(line) - 1){
                line[line_pos] = '\0';
                if (strstr(line, XOR("r-xp")) && strstr(line, target)) {
                    cmd(__NR_close, fd);
                    FLAG_THREAT(303)
                }
                line_pos = 0;
            } else {
                line[line_pos++] = buffer[i];
            }
        }
    }
    cmd(__NR_close, fd);
    FLAG_SAFE()
}