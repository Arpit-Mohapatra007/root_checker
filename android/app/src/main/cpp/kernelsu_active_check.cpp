#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
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

void kernelsu_active_check(unsigned long long &state, int &detected_error){
    int fd = (int)cmd(__NR_openat, AT_FDCWD, (long)XOR("/dev"), O_RDONLY|O_DIRECTORY|O_CLOEXEC, 0);
    if (fd < 0) {
        FLAG_SAFE()
    }
    char buffer[4096];
    char path[256];
    while (true){
        long dir_read = (long)cmd(__NR_getdents64, fd, (long)buffer, sizeof(buffer));
        if (dir_read < 0) {
            cmd(__NR_close, fd);
            FLAG_SAFE()
        }
        if (dir_read == 0) break;
        long buffer_pos = 0;
        while (buffer_pos < dir_read) {
            struct linux_dirent64 *entry = (struct linux_dirent64 *) (buffer + buffer_pos);
            if (entry->d_name[0] != '.' && strstr(entry->d_name, XOR("watchdog")) == nullptr) {
                snprintf(path, sizeof(path), "/dev/%s", entry->d_name);
                int fp = (int)cmd(__NR_openat, AT_FDCWD, (long)path, O_RDONLY|O_NONBLOCK|O_CLOEXEC, 0);
                if (fp >= 0) {
                    long result = (long)cmd(__NR_ioctl, fp, 0xDEADBEEF, 0);
                    cmd(__NR_close, fp);
                    if (result == 0) {
                        cmd(__NR_close, fd);
                        FLAG_THREAT(305)
                    }
                }
            }
            buffer_pos += entry->d_reclen;
        }
    }
    cmd(__NR_close, fd);
    FLAG_SAFE()
}