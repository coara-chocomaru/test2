/*
 * Android RTSP Fuzzer - 拡張版（修正: pthread を fork に置き換え）
 * 対象: /system/bin/rtspclient および /system/bin/rtspserver
 * 脆弱性検証: スタック/ヒープオーバーフロー, 書式文字列, 整数オーバーフロー, コマンドインジェクション等
 * コンパイル: Android NDK または AOSP ビルド環境
 * 実行: ./rtsp_fuzzer <client|server> [オプション]
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/select.h>
#include <stdint.h>

#define MAX_BUFFER 65536
#define TEST_PORT 5555
#define LOCAL_HOST "127.0.0.1"
#define MAX_TEST_CASES 20

// グローバル設定
typedef struct {
    int target_port;
    char target_host[64];
    int test_count;
    int verbose;
    int timeout_sec;
    int target_type; // 0: client, 1: server
    int crash_detected;
    int crash_signal;
} config_t;

config_t g_config = {
    .target_port = 554,
    .target_host = "127.0.0.1",
    .test_count = 1,
    .verbose = 1,
    .timeout_sec = 10,
    .target_type = 0,
    .crash_detected = 0,
    .crash_signal = 0
};

// テストケース構造体
typedef struct {
    const char *name;
    void (*func)(int sock, void *arg);
    void *arg;
} test_case_t;

// ユーティリティ: データ送受信（タイムアウト付き）
int send_recv(int sock, const char *send_data, size_t send_len, char *recv_buf, size_t recv_size, int timeout_sec) {
    if (send(sock, send_data, send_len, 0) < 0) {
        perror("send");
        return -1;
    }
    if (recv_buf == NULL) return 0;
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    struct timeval tv = {timeout_sec, 0};
    int ret = select(sock + 1, &fds, NULL, NULL, &tv);
    if (ret <= 0) {
        if (ret == 0) fprintf(stderr, "recv timeout\n");
        else perror("select");
        return -1;
    }
    int n = recv(sock, recv_buf, recv_size - 1, 0);
    if (n < 0) {
        perror("recv");
        return -1;
    }
    recv_buf[n] = '\0';
    return n;
}

// ターゲットプロセス起動
pid_t start_target(const char *target, int port) {
    pid_t pid = fork();
    if (pid == 0) {
        char port_str[16];
        snprintf(port_str, sizeof(port_str), "%d", port);
        if (strcmp(target, "client") == 0) {
            char url[128];
            snprintf(url, sizeof(url), "rtsp://%s:%d/", g_config.target_host, port);
            execl("/system/bin/rtspclient", "rtspclient", url, NULL);
        } else if (strcmp(target, "server") == 0) {
            // サーバーによっては -p を受け付けない場合もある
            execl("/system/bin/rtspserver", "rtspserver", "-p", port_str, NULL);
        } else {
            fprintf(stderr, "Unknown target: %s\n", target);
            exit(1);
        }
        perror("execl");
        exit(1);
    } else if (pid < 0) {
        perror("fork");
        return -1;
    }
    sleep(1); // 起動待ち
    return pid;
}

// 接続確立
int connect_target(int port, const char *host) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        perror("inet_pton");
        close(sock);
        return -1;
    }
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect");
        close(sock);
        return -1;
    }
    return sock;
}

// ---------- テストケース実装 ----------
// （前回と同様、省略せずに全て含める）

// 1. 超長 URI（スタック破壊）
void test_long_uri(int sock, void *arg) {
    char buffer[MAX_BUFFER * 4];
    memset(buffer, 'A', sizeof(buffer) - 1);
    buffer[sizeof(buffer)-1] = '\0';
    char req[8192];
    snprintf(req, sizeof(req), "DESCRIBE rtsp://%s/%s RTSP/1.0\r\nCSeq: 1\r\n\r\n",
             g_config.target_host, buffer);
    send_recv(sock, req, strlen(req), NULL, 0, g_config.timeout_sec);
}

// 2. 書式文字列攻撃
void test_format_string(int sock, void *arg) {
    const char *payload = "OPTIONS %s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s RTSP/1.0\r\nCSeq: 1\r\n\r\n";
    char buffer[2048];
    snprintf(buffer, sizeof(buffer), payload, 
             "AAAA","BBBB","CCCC","DDDD","EEEE",
             "FFFF","GGGG","HHHH","IIII","JJJJ",
             "KKKK","LLLL","MMMM","NNNN","OOOO",
             "PPPP","QQQQ","RRRR","SSSS","TTTT");
    send_recv(sock, buffer, strlen(buffer), NULL, 0, g_config.timeout_sec);
}

// 3. Content-Length オーバーフロー（巨大値）
void test_content_length_overflow(int sock, void *arg) {
    const char *payload = "SETUP rtsp://example.com/stream RTSP/1.0\r\n"
                          "CSeq: 2\r\n"
                          "Transport: RTP/AVP;unicast;client_port=8000-8001\r\n"
                          "Content-Length: 4294967295\r\n"
                          "\r\n";
    send_recv(sock, payload, strlen(payload), NULL, 0, g_config.timeout_sec);
}

// 4. 不正なメソッド名
void test_invalid_method(int sock, void *arg) {
    const char *payload = "INVALID / RTSP/1.0\r\nCSeq: 1\r\n\r\n";
    send_recv(sock, payload, strlen(payload), NULL, 0, g_config.timeout_sec);
}

// 5. 重複ヘッダー
void test_duplicate_headers(int sock, void *arg) {
    const char *payload = "DESCRIBE rtsp://example.com RTSP/1.0\r\n"
                          "CSeq: 1\r\nCSeq: 2\r\nCSeq: 3\r\n"
                          "User-Agent: Fuzzer\r\nUser-Agent: Another\r\n\r\n";
    send_recv(sock, payload, strlen(payload), NULL, 0, g_config.timeout_sec);
}

// 6. 制御文字（NULL, CR, LF）
void test_control_characters(int sock, void *arg) {
    const char *payload = "OPTIONS rtsp://example.com RTSP/1.0\r\n"
                          "CSeq: 1\r\n"
                          "Header: value\r\n"
                          "Header\x00: value\r\n"
                          "\r\n";
    send_recv(sock, payload, strlen(payload), NULL, 0, g_config.timeout_sec);
}

// 7. 極端に長いリクエスト行
void test_very_long_request_line(int sock, void *arg) {
    char buffer[8192];
    memset(buffer, 'B', sizeof(buffer)-1);
    buffer[sizeof(buffer)-1] = '\0';
    char req[16384];
    snprintf(req, sizeof(req), "DESCRIBE rtsp://%s/%s RTSP/1.0\r\nCSeq: 1\r\n\r\n",
             g_config.target_host, buffer);
    send_recv(sock, req, strlen(req), NULL, 0, g_config.timeout_sec);
}

// 8. コマンドインジェクション（シェルメタ文字）
void test_command_injection(int sock, void *arg) {
    const char *payload = "DESCRIBE rtsp://example.com/;ls -la RTSP/1.0\r\nCSeq: 1\r\n\r\n";
    send_recv(sock, payload, strlen(payload), NULL, 0, g_config.timeout_sec);
}

// 9. 必須ヘッダー欠落
void test_missing_headers(int sock, void *arg) {
    const char *payload = "DESCRIBE rtsp://example.com RTSP/1.0\r\n\r\n";
    send_recv(sock, payload, strlen(payload), NULL, 0, g_config.timeout_sec);
}

// 10. 大量ヘッダー（リソース枯渇）
void test_many_headers(int sock, void *arg) {
    char buffer[16384];
    int pos = snprintf(buffer, sizeof(buffer), "OPTIONS rtsp://example.com RTSP/1.0\r\n");
    for (int i = 0; i < 500; i++) {
        pos += snprintf(buffer + pos, sizeof(buffer) - pos, "X-Header-%d: value%d\r\n", i, i);
    }
    snprintf(buffer + pos, sizeof(buffer) - pos, "\r\n");
    send_recv(sock, buffer, strlen(buffer), NULL, 0, g_config.timeout_sec);
}

// 11. Range ヘッダー異常値（CVE-2018-4013 類似）
void test_range_header_overflow(int sock, void *arg) {
    const char *payload = "DESCRIBE rtsp://example.com RTSP/1.0\r\n"
                          "CSeq: 1\r\n"
                          "Range: npt=0-999999999999999999999999999999\r\n"
                          "\r\n";
    send_recv(sock, payload, strlen(payload), NULL, 0, g_config.timeout_sec);
}

// 12. Transport ヘッダーインジェクション
void test_transport_injection(int sock, void *arg) {
    const char *payload = "SETUP rtsp://example.com/stream RTSP/1.0\r\n"
                          "CSeq: 3\r\n"
                          "Transport: RTP/AVP;unicast;client_port=8000-8001\r\n"
                          "Transport: RTP/AVP;unicast;client_port=9000-9001\r\n"
                          "\r\n";
    send_recv(sock, payload, strlen(payload), NULL, 0, g_config.timeout_sec);
}

// 13. sscanf 攻撃（数値解析のバッファオーバーラン）
void test_sscanf_overflow(int sock, void *arg) {
    char payload[2048];
    memset(payload, 'C', sizeof(payload)-1);
    snprintf(payload + sizeof(payload)-100, 100, "\r\nCSeq: 9999\r\n\r\n");
    send_recv(sock, payload, strlen(payload), NULL, 0, g_config.timeout_sec);
}

// 14. 二重解放（TEARDOWN 連続送信）
void test_double_free(int sock, void *arg) {
    const char *setup = "SETUP rtsp://example.com/stream RTSP/1.0\r\n"
                        "CSeq: 4\r\n"
                        "Transport: RTP/AVP;unicast;client_port=8000-8001\r\n"
                        "\r\n";
    char recv_buf[1024];
    send_recv(sock, setup, strlen(setup), recv_buf, sizeof(recv_buf), g_config.timeout_sec);
    // Session ID を抽出（簡易的に固定値）
    const char *teardown = "TEARDOWN rtsp://example.com/stream RTSP/1.0\r\n"
                           "CSeq: 5\r\n"
                           "Session: 123456\r\n"
                           "\r\n";
    send_recv(sock, teardown, strlen(teardown), NULL, 0, g_config.timeout_sec);
    // 二回目
    send_recv(sock, teardown, strlen(teardown), NULL, 0, g_config.timeout_sec);
}

// 15. 巨大なContent-Length と実際のデータ不足（ヒープオーバーフロー）
void test_heap_overflow(int sock, void *arg) {
    char req[4096];
    snprintf(req, sizeof(req),
             "DESCRIBE rtsp://example.com RTSP/1.0\r\n"
             "CSeq: 6\r\n"
             "Content-Length: 1048576\r\n"
             "\r\n"
             "shortdata");
    send_recv(sock, req, strlen(req), NULL, 0, g_config.timeout_sec);
}

// 16. 異常なCSeq（負の値）
void test_negative_cseq(int sock, void *arg) {
    const char *payload = "OPTIONS rtsp://example.com RTSP/1.0\r\n"
                          "CSeq: -1\r\n"
                          "\r\n";
    send_recv(sock, payload, strlen(payload), NULL, 0, g_config.timeout_sec);
}

// 17. 未対応のバージョン
void test_wrong_version(int sock, void *arg) {
    const char *payload = "DESCRIBE rtsp://example.com RTSP/2.0\r\nCSeq: 1\r\n\r\n";
    send_recv(sock, payload, strlen(payload), NULL, 0, g_config.timeout_sec);
}

// 18. ヘッダーに改行のみ（空行攻撃）
void test_empty_headers(int sock, void *arg) {
    const char *payload = "OPTIONS rtsp://example.com RTSP/1.0\r\n\r\n\r\n";
    send_recv(sock, payload, strlen(payload), NULL, 0, g_config.timeout_sec);
}

// ---------- テスト実行 ----------

void run_test_case(test_case_t tc, int port, const char *host, pid_t target_pid) {
    if (g_config.verbose) {
        printf("[*] Running test: %s\n", tc.name);
    }
    int sock = connect_target(port, host);
    if (sock < 0) {
        fprintf(stderr, "Failed to connect to target\n");
        return;
    }
    tc.func(sock, tc.arg);
    close(sock);

    // ターゲットプロセス状態確認
    int status;
    pid_t result = waitpid(target_pid, &status, WNOHANG);
    if (result == target_pid) {
        if (WIFEXITED(status)) {
            fprintf(stderr, "[-] Target exited with code %d during test '%s'\n", WEXITSTATUS(status), tc.name);
            g_config.crash_detected = 1;
            g_config.crash_signal = 0;
        } else if (WIFSIGNALED(status)) {
            fprintf(stderr, "[-] Target crashed with signal %d during test '%s'\n", WTERMSIG(status), tc.name);
            g_config.crash_detected = 1;
            g_config.crash_signal = WTERMSIG(status);
        }
    } else {
        if (g_config.verbose) {
            printf("[+] Target still running after test '%s'\n", tc.name);
        }
    }
}

// サーバーモード: サーバーを起動し、クライアントとして攻撃
void test_server_mode() {
    printf("[*] Starting server target on port %d\n", g_config.target_port);
    pid_t server_pid = start_target("server", g_config.target_port);
    if (server_pid < 0) return;

    test_case_t tests[] = {
        {"Long URI", test_long_uri, NULL},
        {"Format String", test_format_string, NULL},
        {"Content-Length Overflow", test_content_length_overflow, NULL},
        {"Invalid Method", test_invalid_method, NULL},
        {"Duplicate Headers", test_duplicate_headers, NULL},
        {"Control Characters", test_control_characters, NULL},
        {"Very Long Request Line", test_very_long_request_line, NULL},
        {"Command Injection", test_command_injection, NULL},
        {"Missing Headers", test_missing_headers, NULL},
        {"Many Headers", test_many_headers, NULL},
        {"Range Header Overflow", test_range_header_overflow, NULL},
        {"Transport Injection", test_transport_injection, NULL},
        {"sscanf Overflow", test_sscanf_overflow, NULL},
        {"Double Free", test_double_free, NULL},
        {"Heap Overflow", test_heap_overflow, NULL},
        {"Negative CSeq", test_negative_cseq, NULL},
        {"Wrong Version", test_wrong_version, NULL},
        {"Empty Headers", test_empty_headers, NULL},
    };
    int num_tests = sizeof(tests)/sizeof(tests[0]);

    for (int i = 0; i < num_tests; i++) {
        for (int c = 0; c < g_config.test_count; c++) {
            run_test_case(tests[i], g_config.target_port, g_config.target_host, server_pid);
            if (g_config.crash_detected) {
                // クラッシュしたらサーバーを再起動して次のテストに備える
                kill(server_pid, SIGKILL);
                waitpid(server_pid, NULL, 0);
                printf("[*] Restarting server after crash\n");
                server_pid = start_target("server", g_config.target_port);
                if (server_pid < 0) return;
                g_config.crash_detected = 0;
            }
        }
    }

    kill(server_pid, SIGTERM);
    waitpid(server_pid, NULL, 0);
}

// クライアントモード: モックサーバーを子プロセスで起動し、クライアントを起動
// モックサーバープロセス
void mock_server_process(int port) {
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        return;
    }
    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(listen_fd);
        return;
    }
    if (listen(listen_fd, 5) < 0) {
        perror("listen");
        close(listen_fd);
        return;
    }
    printf("[Mock] RTSP mock server running on port %d (pid=%d)\n", port, getpid());

    // 悪意応答のリスト
    const char *malicious_responses[] = {
        "RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: 999999999\r\n\r\n",
        "RTSP/1.0 200 OK\r\nCSeq: 1\r\nSession: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n\r\n",
        "RTSP/2.0 200 OK\r\nCSeq: 1\r\n\r\n",
        "RTSP/1.0 200 OK\r\nCSeq: 1\r\nServer: %s%s%s%s%s%s%s%s%s%s\r\n\r\n",
        "",
        "RTSP/1.0 200 OK\r\nCSeq: 1\r\nX-Data: 0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789\r\n\r\n"
    };
    int num_responses = sizeof(malicious_responses)/sizeof(malicious_responses[0]);
    int response_index = 0;

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t len = sizeof(client_addr);
        int client = accept(listen_fd, (struct sockaddr*)&client_addr, &len);
        if (client < 0) {
            perror("accept");
            continue;
        }
        // リクエスト受信（ログ用）
        char req_buf[4096];
        int n = recv(client, req_buf, sizeof(req_buf)-1, 0);
        if (n > 0) req_buf[n] = '\0';
        if (g_config.verbose) {
            printf("[Mock] Received request: %.100s...\n", req_buf);
        }

        // 応答送信
        const char *resp = malicious_responses[response_index % num_responses];
        if (strlen(resp) > 0) {
            send(client, resp, strlen(resp), 0);
        }
        close(client);
        response_index++;
        // 適当な回数で終了（親プロセスが kill するので、ここでは無限ループ）
        // 実際は親が kill するまで続ける
    }
    close(listen_fd);
}

void test_client_mode() {
    int mock_port = g_config.target_port;
    pid_t mock_pid = fork();
    if (mock_pid == 0) {
        // 子プロセス：モックサーバー実行
        mock_server_process(mock_port);
        exit(0);
    } else if (mock_pid < 0) {
        perror("fork mock");
        return;
    }

    // サーバー起動待ち
    sleep(1);

    // クライアント起動（複数回試行）
    for (int i = 0; i < 3; i++) {
        printf("[*] Starting client target (attempt %d)\n", i+1);
        pid_t client_pid = start_target("client", mock_port);
        if (client_pid < 0) {
            kill(mock_pid, SIGTERM);
            waitpid(mock_pid, NULL, 0);
            return;
        }
        // クライアントが接続し、応答を受け取るまで待つ
        sleep(2);
        int status;
        pid_t result = waitpid(client_pid, &status, WNOHANG);
        if (result == client_pid) {
            if (WIFEXITED(status)) {
                fprintf(stderr, "[-] Client exited with code %d\n", WEXITSTATUS(status));
                g_config.crash_detected = 1;
            } else if (WIFSIGNALED(status)) {
                fprintf(stderr, "[-] Client crashed with signal %d\n", WTERMSIG(status));
                g_config.crash_detected = 1;
                g_config.crash_signal = WTERMSIG(status);
            }
        } else {
            printf("[+] Client still running, terminating.\n");
            kill(client_pid, SIGTERM);
            waitpid(client_pid, NULL, 0);
        }
    }

    // モックサーバー停止
    kill(mock_pid, SIGTERM);
    waitpid(mock_pid, NULL, 0);
}

// ---------- メイン ----------

void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s <client|server> [-p port] [-h host] [-c count] [-v]\n", prog);
    fprintf(stderr, "  -p port     Target port (default 554)\n");
    fprintf(stderr, "  -h host     Target host (default 127.0.0.1)\n");
    fprintf(stderr, "  -c count    Number of times to send each test case (default 1)\n");
    fprintf(stderr, "  -v          Verbose output\n");
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "client") == 0) {
        g_config.target_type = 0;
    } else if (strcmp(argv[1], "server") == 0) {
        g_config.target_type = 1;
    } else {
        fprintf(stderr, "Invalid target: %s\n", argv[1]);
        return 1;
    }

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i+1 < argc) {
            g_config.target_port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-h") == 0 && i+1 < argc) {
            strncpy(g_config.target_host, argv[++i], sizeof(g_config.target_host)-1);
        } else if (strcmp(argv[i], "-c") == 0 && i+1 < argc) {
            g_config.test_count = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-v") == 0) {
            g_config.verbose = 1;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            return 1;
        }
    }

    signal(SIGPIPE, SIG_IGN);

    if (g_config.target_type == 0) {
        test_client_mode();
    } else {
        test_server_mode();
    }

    printf("[*] Fuzzing completed. Crash detected: %s\n", 
           g_config.crash_detected ? "YES" : "NO");
    if (g_config.crash_detected) {
        printf("[*] Last crash signal: %d\n", g_config.crash_signal);
    }
    return 0;
}
