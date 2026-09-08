#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>

#define SOCKET_PATH "/dev/socket/qemud"
#define ABSTRACT_NAME "qemud"
#define SERVICE_NAME "boot-properties"

// ファイルシステムソケットに接続
int connect_filesystem(const char *path) {
    int sock = socket(AF_LOCAL, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_LOCAL;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect filesystem");
        close(sock);
        return -1;
    }
    printf("[+] Connected to filesystem socket: %s\n", path);
    return sock;
}

// 抽象ソケットに接続（Android固有）
int connect_abstract(const char *name) {
    int sock = socket(AF_LOCAL, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_LOCAL;
    // 抽象ソケットは先頭を '\0' にする
    addr.sun_path[0] = '\0';
    strncpy(addr.sun_path + 1, name, sizeof(addr.sun_path) - 2);

    // 抽象ソケットの長さは、ファミリー + ヌル文字 + 名前の長さ
    socklen_t len = offsetof(struct sockaddr_un, sun_path) + 1 + strlen(name);

    if (connect(sock, (struct sockaddr*)&addr, len) < 0) {
        perror("connect abstract");
        close(sock);
        return -1;
    }
    printf("[+] Connected to abstract socket: @%s\n", name);
    return sock;
}

// ハンドシェイク: サービス名送信 → "OK" 受信
int handshake(int sock) {
    // サービス名を送信（改行なし）
    if (write(sock, SERVICE_NAME, strlen(SERVICE_NAME)) != (ssize_t)strlen(SERVICE_NAME)) {
        perror("write service name");
        return -1;
    }
    printf("[>] Sent service: %s\n", SERVICE_NAME);

    char buf[8] = {0};
    ssize_t n = read(sock, buf, 2);
    if (n < 0) {
        perror("read OK");
        return -1;
    }
    if (n == 0) {
        fprintf(stderr, "[!] Connection closed by peer (no OK)\n");
        return -1;
    }
    buf[n] = '\0';
    printf("[<] Received: %s\n", buf);

    if (strncmp(buf, "OK", 2) == 0) {
        printf("[+] Handshake OK\n");
        return 0;
    } else {
        fprintf(stderr, "[!] Unexpected response: %s\n", buf);
        return -1;
    }
}

// "list" コマンドを送信して結果を受信
void list_properties(int sock) {
    // "list" コマンド送信（4バイトヘッダ + データ）
    char cmd[] = "list";
    char header[5];
    snprintf(header, sizeof(header), "%04x", (unsigned int)strlen(cmd));
    
    if (write(sock, header, 4) != 4) {
        perror("write header");
        return;
    }
    if (write(sock, cmd, strlen(cmd)) != (ssize_t)strlen(cmd)) {
        perror("write cmd");
        return;
    }
    printf("[>] Sent command: %s (header: %s)\n", cmd, header);

    // レスポンスの長さを受信（4バイト16進数）
    char len_hex[5] = {0};
    if (read(sock, len_hex, 4) != 4) {
        perror("read length");
        return;
    }
    int data_len = (int)strtol(len_hex, NULL, 16);
    printf("[<] Data length: %d (0x%04x)\n", data_len, data_len);

    // データ本体を受信
    char *data = malloc(data_len + 1);
    if (!data) {
        perror("malloc");
        return;
    }
    ssize_t total = 0;
    while (total < data_len) {
        ssize_t n = read(sock, data + total, data_len - total);
        if (n <= 0) break;
        total += n;
    }
    data[total] = '\0';
    printf("[<] Data:\n%s\n", data);
    free(data);
}

// プロパティデータをプッシュ
void push_properties(int sock, int argc, char **argv) {
    // ペイロードを構築（key=value\n の連続）
    size_t total_len = 0;
    for (int i = 0; i < argc; i++) {
        total_len += strlen(argv[i]) + 1; // +1 for '\n'
    }

    char *payload = malloc(total_len + 1);
    if (!payload) {
        perror("malloc");
        return;
    }
    char *ptr = payload;
    for (int i = 0; i < argc; i++) {
        size_t len = strlen(argv[i]);
        memcpy(ptr, argv[i], len);
        ptr += len;
        *ptr++ = '\n';
    }
    *ptr = '\0';

    // ヘッダ（長さ）を送信
    char header[5];
    snprintf(header, sizeof(header), "%04x", (unsigned int)total_len);
    if (write(sock, header, 4) != 4) {
        perror("write header");
        free(payload);
        return;
    }
    if (write(sock, payload, total_len) != (ssize_t)total_len) {
        perror("write payload");
        free(payload);
        return;
    }
    printf("[>] Pushed %zu bytes: %s\n", total_len, payload);
    free(payload);
}

int main(int argc, char **argv) {
    int sock = -1;

    // 1. まずファイルシステムソケットを試す
    sock = connect_filesystem(SOCKET_PATH);
    if (sock < 0) {
        // 2. 失敗したら抽象ソケットを試す
        sock = connect_abstract(ABSTRACT_NAME);
    }
    if (sock < 0) {
        fprintf(stderr, "[!] Could not connect to qemud.\n");
        return 1;
    }

    // 3. ハンドシェイク
    if (handshake(sock) < 0) {
        close(sock);
        return 1;
    }

    // 4. 引数に応じて動作
    if (argc == 1) {
        // 引数なし: list を実行
        list_properties(sock);
    } else {
        // 引数あり: key=value としてプッシュ
        push_properties(sock, argc - 1, &argv[1]);
        // プッシュ後、確認のため list
        sleep(1);
        printf("\n[*] Fetching list after push:\n");
        list_properties(sock);
    }

    close(sock);
    return 0;
}
