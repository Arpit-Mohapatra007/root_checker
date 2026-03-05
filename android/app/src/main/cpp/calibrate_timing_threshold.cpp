#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include "inline_syscall.h"

long calibrate_timing_threshold(int iterations){
    long max_duration = 0;

    for(int i = 0; i < iterations; i++){
        struct timespec start, end;
        cmd(__NR_clock_gettime, CLOCK_MONOTONIC, (long)&start);
        cmd(__NR_getpid);
        cmd(__NR_clock_gettime, CLOCK_MONOTONIC, (long)&end);

        long duration = (end.tv_sec - start.tv_sec) * 1000000000L + (end.tv_nsec - start.tv_nsec);
        if(duration > max_duration){
            max_duration = duration;
        }
    }
    return max_duration*3;
}