#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include "headers.h"
#include "inline_syscall.h"

static long va_to_file_offset(uintptr_t base, uintptr_t va) {
    ElfW(Ehdr) *ehdr = (ElfW(Ehdr) *)base;
    ElfW(Phdr) *phdr = (ElfW(Phdr) *)(base + ehdr->e_phoff);

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type != PT_LOAD) continue;

        uintptr_t seg_start = base + phdr[i].p_vaddr;
        uintptr_t seg_end   = seg_start + phdr[i].p_filesz;

        if (va >= seg_start && va < seg_end) {
            long file_offset = (long)phdr[i].p_offset + (long)(va - seg_start);
            return file_offset;
        }
    }
    return -1;
}

void integrity_check(unsigned long long &state, int &detected_error, const char *target) {
    void *handle = dlsym(RTLD_DEFAULT, target);
    if (handle == nullptr) {
        FLAG_SAFE()
    }

    Dl_info info;
    if (dladdr(handle, &info) == 0) {
        FLAG_SAFE()
    }

    uintptr_t clean_handle = (uintptr_t)handle & ~1UL;
    uintptr_t base         = (uintptr_t)info.dli_fbase;

    long file_offset = va_to_file_offset(base, clean_handle);
    if (file_offset < 0) {
        FLAG_SAFE()
    }

    int fd = (int)cmd(__NR_openat, AT_FDCWD, (long)info.dli_fname, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) {
        FLAG_SAFE()
    }

    off_t seek_result = (off_t)cmd(__NR_lseek, fd, file_offset, SEEK_SET);
    if (seek_result == -1) {
        cmd(__NR_close, fd);
        FLAG_SAFE()
    }

    char disk_bytes[32];
    ssize_t bytes_read = (ssize_t)cmd(__NR_read, fd, (long)disk_bytes, sizeof(disk_bytes));
    cmd(__NR_close, fd);

    if (bytes_read != sizeof(disk_bytes)) {
        FLAG_SAFE()
    }

    char *ram_bytes = (char *)clean_handle;
    if (memcmp(disk_bytes, ram_bytes, sizeof(disk_bytes)) != 0) {
        FLAG_THREAT(313)
    }

    FLAG_SAFE()
}