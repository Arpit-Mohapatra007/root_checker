#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include "headers.h"
#ifndef __NR_clock_gettime
#define __NR_clock_gettime 113
#endif
bool time_side_channel_vulnerability_detection_test () {
    struct timespec start, end;
    long baseline_duration = 0;
    long su_duration = 0;
    nuclear_test("/system/bin/test");
    syscall(__NR_clock_gettime, CLOCK_MONOTONIC, &start);
    nuclear_test("/system/bin/test");
    syscall(__NR_clock_gettime, CLOCK_MONOTONIC, &end);
    baseline_duration = (end.tv_sec - start.tv_sec) * 1000000000L + (end.tv_nsec - start.tv_nsec);
    syscall(__NR_clock_gettime, CLOCK_MONOTONIC, &start);
    nuclear_test("/system/bin/su");
    syscall(__NR_clock_gettime, CLOCK_MONOTONIC, &end);
    long duration = (end.tv_sec - start.tv_sec) * 1000000000L + (end.tv_nsec - start.tv_nsec);
    return duration > ((baseline_duration * 10) + 20000);
}