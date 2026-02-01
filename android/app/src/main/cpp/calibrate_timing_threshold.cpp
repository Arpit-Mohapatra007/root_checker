#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#ifndef __NR_clock_gettime
#define __NR_clock_gettime 113
#endif

long calibrate_timing_threshold(int iterations){
    long max_duration = 0;

    for(int i = 0; i < iterations; i++){
        struct timespec start, end;
        syscall(__NR_clock_gettime, CLOCK_MONOTONIC, &start);
        getpid();
        syscall(__NR_clock_gettime, CLOCK_MONOTONIC, &end);

        long duration = (end.tv_sec - start.tv_sec) * 1000000000L + (end.tv_nsec - start.tv_nsec);
        if(duration > max_duration){
            max_duration = duration;
        }
    }
    return max_duration*3;
}