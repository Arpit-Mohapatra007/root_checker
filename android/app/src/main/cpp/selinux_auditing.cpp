#include <stdio.h>
#include <string.h>
#include <errno.h>

bool selinux_auditing_enabled(){
    FILE *fp = fopen("/sys/fs/selinux/enforce", "r");
    if (fp == nullptr) {
        if (errno == EACCES){
            return false;
        }
        return true;
    }
    char ch;
    if (fscanf(fp, "%c",&ch)>0){
        if (ch == '0'){
            fclose(fp);
            return true;
        }
    }
    fclose(fp);
    return false;    
}