#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

bool port_scan(int port){
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0){
        return false;
    }
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    int result = connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr));
    close(sock);
    return result == 0;
}