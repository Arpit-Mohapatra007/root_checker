#include <stdio.h>
#include <string.h>
bool smoke_test(){
    FILE *pipe = popen("su -c id","r");
    if(!pipe){
        return false;
    }
    
    char buffer[1024];
    char *line = fgets(buffer, sizeof(buffer), pipe);
    pclose(pipe);  
    if(line && strstr(line, "uid=0") != nullptr){
        return true;
    }
    
    pipe = popen("su -c whoami","r");
    if(!pipe){
        return false;
    }
    
    line = fgets(buffer, sizeof(buffer), pipe);
    pclose(pipe);
    
    return (line && strstr(line, "root") != nullptr);
}