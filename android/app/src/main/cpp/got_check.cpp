#include <link.h>
#include <dlfcn.h>
#include <string.h>
bool got_check(){
    Dl_info info;
    if (dladdr((void*)&got_check, &info) == 0) {
        return true;  
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
        return true;  
    }

    uintptr_t * got_start = nullptr;
    for (ElfW(Dyn) *entry = dyn; entry->d_tag != DT_NULL; entry++) {
        if (entry->d_tag == DT_PLTGOT) {
            got_start = (uintptr_t *)(base_address + entry->d_un.d_ptr);
            break;
        }
    }

    if (got_start == nullptr) {
        return true;  
    }

    for (int i = 3; i<8; i++){
        uintptr_t func_addr = got_start[i];
        if(func_addr == 0){
            continue; 
        }
        Dl_info got_info;
        if (dladdr((void*) func_addr, &got_info) != 0){
            if(got_info.dli_fname == nullptr){
                return true; 
            }

            if(strstr(got_info.dli_fname,"/data/") != nullptr){
                if(strstr(got_info.dli_fname, "/dalvik-cache/") != nullptr || 
                    strstr(got_info.dli_fname,"/data/app") != nullptr ||
                    strstr(got_info.dli_fname, "/data/apex/") != nullptr ||
                    strstr(got_info.dli_fname, "com.google.android.gms") != nullptr ||
                    strstr(got_info.dli_fname, "libhoudini") != nullptr ||
                    strstr(got_info.dli_fname, "libndk_translation") != nullptr) {
                        continue; 
                }
                return true;
            }
        }
    }
    return false;
}