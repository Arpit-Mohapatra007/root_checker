#include <link.h>
#include <dlfcn.h>
#include <string.h>
#include "headers.h"
#include "xorstr.h"

void got_check(unsigned long long &state, int &detected_error){
    Dl_info info;
    if (dladdr((void*)&got_check, &info) == 0) {
        FLAG_THREAT(308)
    }
    uintptr_t base_address = (uintptr_t)info.dli_fbase;
    ElfW(Ehdr) *ehdr = (ElfW(Ehdr) *)base_address;
    ElfW(Phdr) *phdr = (ElfW(Phdr) *)(base_address + ehdr->e_phoff);
    ElfW(Dyn) *dyn = nullptr;

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            dyn = (ElfW(Dyn)*)(base_address + phdr[i].p_vaddr);
            break;
        }
    }

    if (dyn == nullptr) {
        FLAG_THREAT(308)
    }

    uintptr_t * got_start = nullptr;
    for (ElfW(Dyn) *entry = dyn; entry->d_tag != DT_NULL; entry++) {
        if (entry->d_tag == DT_PLTGOT) {
            got_start = (uintptr_t *)(base_address + entry->d_un.d_ptr);
            break;
        }
    }

    if (got_start == nullptr) {
        FLAG_THREAT(308)
    }

    for (int i = 3; i<8; i++){
        uintptr_t func_addr = got_start[i];
        if(func_addr == 0){
            continue; 
        }
        Dl_info got_info;
        if (dladdr((void*) func_addr, &got_info) != 0){
            if(got_info.dli_fname == nullptr){
                FLAG_THREAT(308)
            }

            if(strstr(got_info.dli_fname, XOR("/data/")) != nullptr){
                if(strstr(got_info.dli_fname, XOR("/dalvik-cache/")) != nullptr || 
                    strstr(got_info.dli_fname, XOR("/data/app")) != nullptr ||
                    strstr(got_info.dli_fname, XOR("/data/apex/")) != nullptr ||
                    strstr(got_info.dli_fname, XOR("com.google.android.gms")) != nullptr ||
                    strstr(got_info.dli_fname, XOR("libhoudini")) != nullptr ||
                    strstr(got_info.dli_fname, XOR("libndk_translation")) != nullptr) {
                        continue; 
                }
                FLAG_THREAT(308)
            }
        }
    }
    FLAG_SAFE()
}