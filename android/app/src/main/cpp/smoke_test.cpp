#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/wait.h>
#include "headers.h"
#include "xorstr.h"

void smoke_test(unsigned long long &state, int &detected_error){
    FILE *pipe = popen(XOR("su -c id"), XOR("r"));
    if(!pipe){
        FLAG_SAFE()
    }
    
    char buffer[1024];
    char *line = fgets(buffer, sizeof(buffer), pipe);
    int status = pclose(pipe);  
    
    if(line && strstr(line, XOR("uid=0")) != nullptr){
        FLAG_THREAT(312)
    }
    
    if (status != -1 && WIFEXITED(status)) {
        int exit_code = WEXITSTATUS(status);
        if (exit_code != 127) {
            FLAG_THREAT(312)
        }
    }
    FLAG_SAFE()
}