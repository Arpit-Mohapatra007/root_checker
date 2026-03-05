#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include "headers.h"
#include "xorstr.h"
#include "inline_syscall.h"

void time_side_channel_vulnerability_detection_test(unsigned long long &state, int &detected_error) {
    struct timespec start, end;
    long long baseline_duration = 0;
    
    nuclear_test(state, detected_error, XOR("/system/bin/nofile12345"));
    cmd(__NR_clock_gettime, CLOCK_MONOTONIC, (long)&start);
    nuclear_test(state, detected_error, XOR("/system/bin/nofile12345"));
    cmd(__NR_clock_gettime, CLOCK_MONOTONIC, (long)&end);
    baseline_duration = (end.tv_sec - start.tv_sec) * 1000000000L + (end.tv_nsec - start.tv_nsec);
    
    cmd(__NR_clock_gettime, CLOCK_MONOTONIC, (long)&start);
    nuclear_test(state, detected_error, XOR("/system/bin/su"));
    cmd(__NR_clock_gettime, CLOCK_MONOTONIC, (long)&end);
    
    long long duration = (end.tv_sec - start.tv_sec) * 1000000000L + (end.tv_nsec - start.tv_nsec);
    if (duration > ((baseline_duration * 10) + 20000)) {
        FLAG_THREAT(311)
    }
    FLAG_SAFE()
}