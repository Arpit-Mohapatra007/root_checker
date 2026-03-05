#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "headers.h"
#include "inline_syscall.h"

void check_su(unsigned long long &state, int &detected_error, const char *path){
    int result = (int)cmd(__NR_faccessat, AT_FDCWD, (long)path, F_OK, 0);
    if (result == 0){
        FLAG_THREAT(101)
    }
    FLAG_SAFE()
}

void check_su_stat(unsigned long long &state, int &detected_error, const char *path){
    struct stat stats;
    #ifdef __NR_newfstatat
    int result = (int) cmd(__NR_newfstatat, AT_FDCWD, (long)path, (long)&stats, 0);
    #else
    int result = (int) cmd(__NR_fstatat64, AT_FDCWD, (long)path, (long)&stats, 0);
    #endif
    if(result == 0 && stats.st_uid == 0){
        FLAG_THREAT(102)
    }
    FLAG_SAFE()
}