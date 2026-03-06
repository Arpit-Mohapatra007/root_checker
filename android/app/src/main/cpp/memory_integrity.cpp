#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>
#include "headers.h"
#include "xorstr.h"
#include "inline_syscall.h"

void* memory_monitor_thread(void* arg) {
    while (true) {
        int fd = (int)cmd(__NR_openat, AT_FDCWD, (long)XOR("/proc/self/maps"), O_RDONLY | O_CLOEXEC, 0);
        if (fd >= 0) {
            char buffer[4096];
            char line[1024];
            int line_pos = 0;
            
            while (true) {
                ssize_t bytes_read = (ssize_t)cmd(__NR_read, fd, (long)buffer, sizeof(buffer));
                if (bytes_read <= 0) break;
                
                for (ssize_t i = 0; i < bytes_read; i++) {
                    if (buffer[i] == '\n' || line_pos >= sizeof(line) - 1) {
                        line[line_pos] = '\0';
                        if (strstr(line, XOR("libroot_checker.so")) && strstr(line, XOR("rwx"))) {
                            cmd(__NR_close, fd);
                            cmd(__NR_exit_group, 0); 
                        }

                        if (strstr(line, XOR("frida")) || 
                            strstr(line, XOR("xposed")) ||
                            strstr(line, XOR("substrate")) ||
                            strstr(line, XOR("gum-js-loop"))) {
                            cmd(__NR_close, fd);
                            cmd(__NR_exit_group, 137);
                        }
                        
                        line_pos = 0;
                    } else {
                        line[line_pos++] = buffer[i];
                    }
                }
            }
            cmd(__NR_close, fd);
        }
        
        struct timespec ts;
        ts.tv_sec = 2;
        ts.tv_nsec = 0;
        cmd(__NR_nanosleep, (long)&ts, 0);
    }
    return nullptr;
}

void start_memory_monitor() {
    pthread_t thread_id;
    if (pthread_create(&thread_id, nullptr, memory_monitor_thread, nullptr) == 0) {
        pthread_detach(thread_id); 
    }
}