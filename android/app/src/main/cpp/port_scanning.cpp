#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "headers.h"
#include "xorstr.h"

void port_scan(unsigned long long &state, int &detected_error, int port){
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0){
        FLAG_SAFE()
    }
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = inet_addr(XOR("127.0.0.1"));
    int result = connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr));
    close(sock);
    if (result == 0) {
        FLAG_THREAT(204)
    }
    FLAG_SAFE()
}