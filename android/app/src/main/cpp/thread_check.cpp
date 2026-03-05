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

void thread_check(unsigned long long &state, int &detected_error, const char *thread){
    int dir_fd = (int)cmd(__NR_openat, AT_FDCWD, (long)XOR("/proc/self/task/"), O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    if (dir_fd < 0) {
        FLAG_THREAT(202)
    }
    char buffer[4096];
    char path[256];
    char threads[1024];

    while (true) {
        long dir_read = (long)cmd(__NR_getdents64, dir_fd, (long)buffer, sizeof(buffer));
        if (dir_read <= 0) break;

        long buffer_pos = 0;
        while (buffer_pos < dir_read) {
            struct linux_dirent64 *entry = (struct linux_dirent64 *) (buffer + buffer_pos);
            if (entry->d_name[0] != '.') {
                snprintf(path, sizeof(path), "/proc/self/task/%s/comm", entry->d_name);
                int file_fd = (int)cmd(__NR_openat, AT_FDCWD, (long)path, O_RDONLY | O_CLOEXEC, 0);
                if (file_fd >= 0) {
                    ssize_t bytes = (ssize_t)cmd(__NR_read, file_fd, (long)threads, sizeof(threads) - 1);
                    cmd(__NR_close, file_fd);
                    if (bytes > 0) {
                        threads[bytes] = '\0';
                        threads[strcspn(threads, XOR("\n"))] = '\0';
                        if (strstr(threads, thread) != nullptr) {
                            cmd(__NR_close, dir_fd);
                            FLAG_THREAT(202)
                        }
                    }
                }
            }
            buffer_pos += entry->d_reclen;
        }
    }
    cmd(__NR_close, dir_fd);
    FLAG_SAFE()
}