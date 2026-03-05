#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include "headers.h"
#include "inline_syscall.h"

void time_check(unsigned long long &state, int &detected_error, long threshold) {
    struct timespec start, end;
    cmd(__NR_clock_gettime, CLOCK_MONOTONIC, (long)&start);
    cmd(__NR_getpid);
    cmd(__NR_clock_gettime, CLOCK_MONOTONIC, (long)&end);
    long long duration = (end.tv_sec - start.tv_sec) * 1000000000L + (end.tv_nsec - start.tv_nsec);
    if (duration > threshold) {
        FLAG_THREAT(310)
    }
    FLAG_SAFE()
}