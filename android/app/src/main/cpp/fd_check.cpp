#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include "headers.h"
#include "xorstr.h"
#include "inline_syscall.h"

struct linux_dirent64 {
    uint64_t d_ino;
    int64_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

void fd_check(unsigned long long &state, int &detected_error, const char* target_path){
    int fd = (int)cmd(__NR_openat, AT_FDCWD, (long)XOR("/proc/self/fd"), O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    if (fd < 0) {
        FLAG_THREAT(205)
    }

    char buffer[4096];
    char path[256];
    char linked_path[256];

    while (true) {
        long dir_read = (long)cmd(__NR_getdents64, fd, (long)buffer, sizeof(buffer));
        if (dir_read < 0) {
            cmd(__NR_close, fd);
            FLAG_THREAT(205)
        }
        if (dir_read == 0) break;

        long buffer_pos = 0;
        while (buffer_pos < dir_read) {
            struct linux_dirent64 *entry = (struct linux_dirent64 *) (buffer + buffer_pos);
            if (entry->d_name[0] != '.') {
                snprintf(path, sizeof(path), "/proc/self/fd/%s", entry->d_name);
                
                ssize_t len = (ssize_t)cmd(__NR_readlinkat, AT_FDCWD, (long)path, (long)linked_path, sizeof(linked_path) - 1);
                if (len > 0) {
                    linked_path[len] = '\0';
                    if (strstr(linked_path, target_path) != nullptr) {
                        cmd(__NR_close, fd);
                        FLAG_THREAT(205)
                    }
                }
            }
            buffer_pos += entry->d_reclen;
        }
    }
    cmd(__NR_close, fd);
    FLAG_SAFE()
}