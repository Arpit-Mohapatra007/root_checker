#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <fcntl.h>
#include <unistd.h>
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

int get_kernelsu_major_ID(){
    int fd = (int)cmd(__NR_openat, AT_FDCWD, (long)XOR("/proc/devices"), O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) {
        return -1;
    }
    char buffer [4096];
    char line[256];
    int line_pos = 0;
    int major_id = -1;
    while (true) {
        ssize_t bytes_read = (ssize_t)cmd(__NR_read, fd, (long)buffer, sizeof(buffer));
        if (bytes_read <= 0) {
            break;
        }
        for (ssize_t i = 0; i < bytes_read; i++) {
            if (buffer[i] == '\n' || line_pos >= sizeof(line) - 1) {
                line[line_pos] = '\0';
                if (strstr(line, XOR("kernelsu")) != NULL || strstr(line, XOR("ksu")) != NULL) {
                    char *token = strtok(line, " ");
                    if (token) major_id = atoi(token);
                    break;
                }
                line_pos = 0;
            } else {
                line[line_pos++] = buffer[i];
            }
        }
        if (major_id != -1) break;
    }
    cmd(__NR_close, fd);
    return major_id;
}

bool scan_dev_kernelsu(int major_id) {
    if (major_id == -1) return false;
    int fd = (int)cmd(__NR_openat, AT_FDCWD, (long)XOR("/dev"), O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    if (fd < 0) return false;

    char buffer [4096];
    char path [256];
    while (true) {
        long dir_read = (long)cmd(__NR_getdents64, fd, (long)buffer, sizeof(buffer));
        if (dir_read <= 0) break;

        long buffer_pos = 0;
        while (buffer_pos < dir_read) {
            struct linux_dirent64 *entry = (struct linux_dirent64 *) (buffer + buffer_pos);
            if (entry->d_name[0] != '.') {
                snprintf(path, sizeof(path), "/dev/%s", entry->d_name);
                struct stat stats;
                #ifdef __NR_newfstatat
                if (cmd(__NR_newfstatat, AT_FDCWD, (long)path, (long)&stats, 0) == 0) {
                #else
                if (cmd(__NR_fstatat64, AT_FDCWD, (long)path, (long)&stats, 0) == 0) {
                #endif       
                    if (S_ISCHR(stats.st_mode) && major(stats.st_rdev) == (unsigned int)major_id) {
                        cmd(__NR_close, fd);
                        return true;
                    }
                }
            }
            buffer_pos += entry->d_reclen;
        }
    }
    cmd(__NR_close, fd);
    return false;
}

void kernelsu_passive_check(unsigned long long &state, int &detected_error) {
    int major_id = get_kernelsu_major_ID();
    if (major_id != -1) {
        if(scan_dev_kernelsu(major_id)) {
            FLAG_THREAT(306)
        }
        FLAG_SAFE()
    }

    if (cmd(__NR_faccessat, AT_FDCWD, (long)XOR("/dev/kernelsu"), F_OK, 0) == 0 || 
        cmd(__NR_faccessat, AT_FDCWD, (long)XOR("/dev/ksu"),  F_OK, 0) == 0) {
        FLAG_THREAT(306)
    }
    FLAG_SAFE()
}