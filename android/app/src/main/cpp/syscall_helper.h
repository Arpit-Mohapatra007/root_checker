#ifndef SYSCALL_HELPER_H
#define SYSCALL_HELPER_H

#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>

static inline int sys_access(const char *pathname, int mode){
    return syscall(__NR_faccessat, AT_FDCWD, pathname, mode,0);
}

#endif