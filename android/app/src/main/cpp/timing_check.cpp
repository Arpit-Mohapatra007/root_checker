#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#ifndef __NR_clock_gettime
#define __NR_clock_gettime 113
#endif
bool time_check(long threshold) {
    struct timespec start, end;
    syscall(__NR_clock_gettime, CLOCK_MONOTONIC, &start);
    getpid();
    syscall(__NR_clock_gettime, CLOCK_MONOTONIC, &end);
    long long duration = (end.tv_sec - start.tv_sec) * 1000000000L + (end.tv_nsec - start.tv_nsec);
    return duration > threshold;
}