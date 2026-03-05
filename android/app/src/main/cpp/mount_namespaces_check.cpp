#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include "headers.h"
#include "xorstr.h"
#include "inline_syscall.h"

static bool parse_line(const char *line) {
    const char *ptr = line;
    for (int field = 1; field < 5; field++) {
        while (*ptr && *ptr != ' ') ptr++;
        if (*ptr == '\0') return false;
        while (*ptr == ' ') ptr++;
    }

    char mount_point[1024];
    int mp_len = 0;
    while (*ptr && *ptr != ' ' && mp_len < sizeof(mount_point) - 1) {
        mount_point[mp_len++] = *ptr++;
    }
    mount_point[mp_len] = '\0';

    if (strcmp(mount_point, XOR("/system")) != 0 && strcmp(mount_point, XOR("/vendor")) != 0) return false;

    const char *sep = strstr(line, XOR(" - "));
    if (!sep) return false;

    const char * fs_start = sep + 3;
    char fs_type[1024];
    int fs_type_len = 0;
    while (*fs_start && *fs_start != ' ' && fs_type_len < sizeof(fs_type) -1 ) {
        fs_type[fs_type_len++] = *fs_start++;
    }
    fs_type[fs_type_len] = '\0';

    if (strcmp(fs_type, XOR("tmpfs")) == 0 || strcmp(fs_type, XOR("overlay")) == 0) return true;

    return false;
}

void mount_namespaces_check(unsigned long long &state, int &detected_error){
    int fd = (int)cmd(__NR_openat, AT_FDCWD, (long)XOR("/proc/self/mountinfo"), O_RDONLY|O_CLOEXEC, 0);
    if (fd < 0) {
        FLAG_THREAT(301)
    }
    char buffer [4096];
    char line [1024];
    int line_pos = 0;

    while(true) {
        ssize_t bytes_read = (ssize_t)cmd(__NR_read, fd, (long)buffer, sizeof(buffer));
        if (bytes_read <= 0) break;
        for (ssize_t i = 0; i<bytes_read; i++) {
         if (buffer[i] == '\n' || line_pos >= sizeof(line) - 1) {
            line[line_pos] = '\0';
            if (parse_line(line)) {
                cmd(__NR_close, fd);
                FLAG_THREAT(301)
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