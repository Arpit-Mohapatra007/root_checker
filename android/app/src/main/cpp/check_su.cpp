#include <unistd.h>
#include <errno.h>
bool check_su(const char *path){
    int result =  access(path,F_OK);
    if (result == 0){
        return true;
    }else{
        if(errno == ENOENT){
            return false;
        }else if(errno == EACCES){
            return true;
        }
        return false;
    } 
}

#include <sys/stat.h>

bool check_su_stat(const char *path){
    struct stat stats;
    int result = stat(path,&stats);
    if(result == 0 && stats.st_uid == 0){
        return true;
    }
    return false;
}