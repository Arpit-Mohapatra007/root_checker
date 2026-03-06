#ifndef INLINE_SYSCALL_H
#define INLINE_SYSCALL_H

#include <sys/syscall.h>

#if defined(__aarch64__)
__attribute__((always_inline)) inline long cmd(long __number, long __arg1 = 0, long __arg2 = 0, long __arg3 = 0, long __arg4 = 0, long __arg5 = 0, long __arg6 = 0) {
    register long x8 __asm__("x8") = __number;
    register long x0 __asm__("x0") = __arg1;
    register long x1 __asm__("x1") = __arg2;
    register long x2 __asm__("x2") = __arg3;
    register long x3 __asm__("x3") = __arg4;
    register long x4 __asm__("x4") = __arg5;
    register long x5 __asm__("x5") = __arg6;

    __asm__ volatile(
        "svc #0\n"
        : "+r"(x0)
        : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
        : "memory", "cc"
    );
    return x0;
}

#else

#include <unistd.h>
#define cmd syscall

#endif

#endif