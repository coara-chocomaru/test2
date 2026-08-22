#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <signal.h>
#include <errno.h>

#define PORT 1234
#define BUFFER_SIZE 1024
#define MAX_CLIENTS 10
#define BACKLOG 5

volatile sig_atomic_t keep_running = 1;

void handle_signal(int sig) {
    keep_running = 0;
}

void handle_client(int client_fd, struct sockaddr_in client_addr) {
    char buffer[BUFFER_SIZE];
    char client_ip[INET_ADDRSTRLEN];
    
    inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
    printf("客户端已连接: %s:%d\n", client_ip, ntohs(client_addr.sin_port));

    while (1) {
        int bytes_read = recv(client_fd, buffer, BUFFER_SIZE - 1, 0);
        if (bytes_read <= 0) {
            if (bytes_read == 0) {
                printf("客户端 %s:%d 断开连接\n", client_ip, ntohs(client_addr.sin_port));
            } else {
                perror("接收数据错误");
            }
            break;
        }
        
        buffer[bytes_read] = '\0';
        printf("来自 %s:%d 的消息: %s", client_ip, ntohs(client_addr.sin_port), buffer);
        
        // 可以添加命令处理逻辑
        if (strstr(buffer, "exit") != NULL) {
            printf("客户端 %s:%d 请求退出\n", client_ip, ntohs(client_addr.sin_port));
            break;
        }
    }
    
    close(client_fd);
}

int main() {
    
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("创建socket失败");
        exit(EXIT_FAILURE);
    }

    // 设置socket选项
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("设置socket选项失败");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("绑定端口失败");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, BACKLOG) < 0) {
        perror("监听失败");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("服务器已启动，监听端口 %d...\n", PORT);
    printf("按Ctrl+C停止服务器...\n");

    while (keep_running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd < 0) {
            if (errno == EINTR && !keep_running) {
                break; // 正常退出
            }
            perror("接受连接失败");
            continue;
        }

        // 处理客户端连接
        pid_t pid = fork();
        if (pid < 0) {
            perror("创建子进程失败");
            close(client_fd);
            continue;
        } else if (pid == 0) {
            // 子进程处理客户端
            close(server_fd); // 子进程不需要监听socket
            handle_client(client_fd, client_addr);
            exit(EXIT_SUCCESS);
        } else {
            // 父进程继续监听
            close(client_fd); // 父进程不需要客户端socket
        }
    }

    printf("\n正在关闭服务器...\n");
    close(server_fd);
    printf("服务器已关闭\n");
    return EXIT_SUCCESS;
}
