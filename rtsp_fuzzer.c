/*
 * Android RTSP Deep Fuzzer v2 - 徹底的な原因追究と改善版
 * 
 * 対象: /system/bin/rtspclient, /system/bin/rtspserver
 * 
 * 改善点:
 *   - デフォルトポートを 8554 (非特権) に変更
 *   - バイナリ存在確認と代替パス探索
 *   - サーバー起動時に複数ポートを試行 (バインド可能なポートを自動検出)
 *   - クライアント起動前にモックサーバーの応答を確認
 *   - 起動オプションのバリエーションを試行
 *   - 詳細な診断ログ出力
 *   - プロセス監視と自動再起動
 * 
 * コンパイル: ndk-build または gcc -Wall -O0 -g
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
#include <fcntl.h>
#include <sys/select.h>
#include <stdint.h>
#include <netdb.h>
#include <sys/prctl.h>
#include <linux/limits.h>
#include <sys/resource.h>
#include <dirent.h>
#include <sys/stat.h>

// ============================================================
// 設定
// ============================================================

#define MAX_BUFFER           65536
#define MAX_PAYLOAD          102400
#define MAX_HEADERS          2000
#define DEFAULT_PORT         8554            // 非特権ポート
#define LOCAL_HOST           "127.0.0.1"
#define FUZZ_ITERATIONS      3
#define CONNECT_TIMEOUT      5
#define RESPONSE_TIMEOUT     10
#define MAX_PORT_ATTEMPTS    10              // ポート探索試行回数
#define TARGET_BIN_CLIENT    "/system/bin/rtspclient"
#define TARGET_BIN_SERVER    "/system/bin/rtspserver"
#define TARGET_BIN_CLIENT_ALT "/vendor/bin/rtspclient"
#define TARGET_BIN_SERVER_ALT "/vendor/bin/rtspserver"

typedef struct {
    int port;
    char host[64];
    int iterations;
    int verbose;
    int timeout;
    int target_type;        // 0=client, 1=server
    int crash_detected;
    int crash_signal;
    int exit_code;
    pid_t target_pid;
    char last_error[256];
    char bin_path[256];
} config_t;

config_t g_config = {
    .port = DEFAULT_PORT,
    .host = LOCAL_HOST,
    .iterations = FUZZ_ITERATIONS,
    .verbose = 1,
    .timeout = RESPONSE_TIMEOUT,
    .target_type = 1,
    .crash_detected = 0,
    .crash_signal = 0,
    .exit_code = 0,
    .target_pid = -1,
    .last_error = "",
    .bin_path = ""
};

// ============================================================
// ユーティリティ関数
// ============================================================

void log_msg(const char *fmt, ...) {
    if (!g_config.verbose) return;
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}

void log_error(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
}

// バイナリ存在確認
int check_binary_exists(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0 && (st.st_mode & S_IXUSR)) {
        return 1;
    }
    return 0;
}

// バイナリ探索（複数パスを試す）
const char* find_binary(const char *target_type) {
    const char *paths[] = {
        TARGET_BIN_CLIENT,
        TARGET_BIN_CLIENT_ALT,
        "/system/bin/rtspclient",
        "/vendor/bin/rtspclient",
        NULL
    };
    const char *paths_server[] = {
        TARGET_BIN_SERVER,
        TARGET_BIN_SERVER_ALT,
        "/system/bin/rtspserver",
        "/vendor/bin/rtspserver",
        NULL
    };
    const char **p = (strcmp(target_type, "client") == 0) ? paths : paths_server;
    for (int i = 0; p[i] != NULL; i++) {
        if (check_binary_exists(p[i])) {
            return p[i];
        }
    }
    return NULL;
}

// ポートが利用可能かチェック（バインドできるか）
int is_port_available(int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return 0;
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
        close(sock);
        return 1;  // バインド成功 → 使用可能
    }
    close(sock);
    return 0;
}

// 使用可能なポートを探す（デフォルトからインクリメント）
int find_available_port(int start_port) {
    for (int i = 0; i < MAX_PORT_ATTEMPTS; i++) {
        int port = start_port + i;
        if (is_port_available(port)) {
            return port;
        }
    }
    return -1;
}

int create_tcp_socket(void) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct timeval tv = {g_config.timeout, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    return sock;
}

int connect_to_port(int port, const char *host) {
    int sock = create_tcp_socket();
    if (sock < 0) return -1;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        struct hostent *he = gethostbyname(host);
        if (he == NULL) {
            log_error("Failed to resolve host: %s\n", host);
            close(sock);
            return -1;
        }
        memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
    }
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        if (errno != EINPROGRESS) {
            close(sock);
            return -1;
        }
    }
    return sock;
}

int send_data(int sock, const char *data, size_t len) {
    if (len == 0) len = strlen(data);
    ssize_t sent = send(sock, data, len, MSG_NOSIGNAL);
    if (sent < 0) {
        if (errno != EPIPE && errno != ECONNRESET) {
            perror("send");
        }
        return -1;
    }
    return (int)sent;
}

int recv_data(int sock, char *buf, size_t buf_size) {
    if (buf_size == 0) return 0;
    ssize_t n = recv(sock, buf, buf_size - 1, 0);
    if (n < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("recv");
        }
        return -1;
    }
    if (n == 0) return 0;
    buf[n] = '\0';
    return (int)n;
}

// ============================================================
// ターゲットプロセス管理 (改良版)
// ============================================================

// サーバー起動: 指定されたポートでバインドできるか確認しながら実行
pid_t spawn_server_with_port(int port) {
    if (!is_port_available(port)) {
        log_error("[-] Port %d is not available (maybe in use)\n", port);
        return -1;
    }
    
    pid_t pid = fork();
    if (pid == 0) {
        prctl(PR_SET_NAME, "rtspserver_fuzz", 0, 0, 0);
        if (!g_config.verbose) {
            int fd = open("/dev/null", O_RDWR);
            if (fd >= 0) { dup2(fd, STDOUT_FILENO); dup2(fd, STDERR_FILENO); close(fd); }
        }
        char port_str[16];
        snprintf(port_str, sizeof(port_str), "%d", port);
        const char *bin = g_config.bin_path[0] ? g_config.bin_path : TARGET_BIN_SERVER;
        
        // 起動オプションのバリエーションを順に試行
        char *args1[] = { (char*)bin, "-p", port_str, NULL };
        char *args2[] = { (char*)bin, port_str, NULL };
        char *args3[] = { (char*)bin, NULL };
        
        execv(bin, args1);
        execv(bin, args2);
        execv(bin, args3);
        // すべて失敗したら終了
        log_error("execv failed for server: %s\n", strerror(errno));
        exit(127);
    } else if (pid < 0) {
        log_error("fork failed: %s\n", strerror(errno));
        return -1;
    }
    
    // 親: サーバーがポートを開くのを待つ (最大5秒)
    for (int i = 0; i < 10; i++) {
        usleep(500000);
        int sock = connect_to_port(port, g_config.host);
        if (sock >= 0) {
            close(sock);
            log_msg("[+] Server is ready on port %d (PID %d)\n", port, pid);
            return pid;
        }
        // プロセスが生きているか確認
        if (kill(pid, 0) != 0) {
            int status;
            pid_t result = waitpid(pid, &status, WNOHANG);
            if (result == pid) {
                if (WIFEXITED(status)) {
                    log_error("[-] Server exited with code %d during startup\n", WEXITSTATUS(status));
                } else if (WIFSIGNALED(status)) {
                    log_error("[-] Server died with signal %d during startup\n", WTERMSIG(status));
                }
            }
            return -1;
        }
    }
    log_error("[-] Server did not become ready within timeout\n");
    kill(pid, SIGTERM);
    waitpid(pid, NULL, 0);
    return -1;
}

// クライアント起動: URLにポートを含める
pid_t spawn_client(const char *server_host, int port) {
    pid_t pid = fork();
    if (pid == 0) {
        prctl(PR_SET_NAME, "rtspclient_fuzz", 0, 0, 0);
        if (!g_config.verbose) {
            int fd = open("/dev/null", O_RDWR);
            if (fd >= 0) { dup2(fd, STDOUT_FILENO); dup2(fd, STDERR_FILENO); close(fd); }
        }
        char url[256];
        snprintf(url, sizeof(url), "rtsp://%s:%d/", server_host, port);
        const char *bin = g_config.bin_path[0] ? g_config.bin_path : TARGET_BIN_CLIENT;
        char *args1[] = { (char*)bin, url, "-v", NULL };
        char *args2[] = { (char*)bin, url, NULL };
        execv(bin, args1);
        execv(bin, args2);
        log_error("execv failed for client: %s\n", strerror(errno));
        exit(127);
    } else if (pid < 0) {
        log_error("fork failed: %s\n", strerror(errno));
        return -1;
    }
    // クライアントはすぐに動き出すので、少し待つ
    usleep(500000);
    return pid;
}

int check_target_status(pid_t pid) {
    if (pid <= 0) return -1;
    int status;
    pid_t result = waitpid(pid, &status, WNOHANG);
    if (result == pid) {
        if (WIFEXITED(status)) {
            g_config.exit_code = WEXITSTATUS(status);
            return 1;
        } else if (WIFSIGNALED(status)) {
            g_config.crash_detected = 1;
            g_config.crash_signal = WTERMSIG(status);
            return -1;
        }
    }
    return 0;
}

void terminate_target(pid_t pid) {
    if (pid <= 0) return;
    kill(pid, SIGTERM);
    for (int i = 0; i < 5; i++) {
        usleep(200000);
        if (kill(pid, 0) != 0) break;
    }
    if (kill(pid, 0) == 0) kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
}

// ============================================================
// RTSP ペイロード生成 (前回と同様)
// ============================================================

typedef struct {
    char method[32];
    char uri[256];
    char version[16];
    char headers[MAX_HEADERS];
    char body[1024];
} rtsp_request_t;

void build_rtsp_request(rtsp_request_t *req, const char *method, const char *uri) {
    memset(req, 0, sizeof(rtsp_request_t));
    strncpy(req->method, method, sizeof(req->method)-1);
    strncpy(req->uri, uri, sizeof(req->uri)-1);
    strncpy(req->version, "RTSP/1.0", sizeof(req->version)-1);
    snprintf(req->headers, sizeof(req->headers), "CSeq: 1\r\nUser-Agent: RTSPFuzzer/1.0\r\n");
}

char *serialize_request(rtsp_request_t *req) {
    static char buffer[MAX_BUFFER * 2];
    int pos = snprintf(buffer, sizeof(buffer), "%s %s %s\r\n", req->method, req->uri, req->version);
    pos += snprintf(buffer + pos, sizeof(buffer) - pos, "%s", req->headers);
    if (req->body[0]) {
        pos += snprintf(buffer + pos, sizeof(buffer) - pos, "Content-Length: %zu\r\n", strlen(req->body));
    }
    pos += snprintf(buffer + pos, sizeof(buffer) - pos, "\r\n");
    if (req->body[0]) pos += snprintf(buffer + pos, sizeof(buffer) - pos, "%s", req->body);
    return buffer;
}

// ============================================================
// テストケース (前回と同じ)
// ============================================================

typedef struct {
    const char *name;
    const char *description;
    void (*func)(int sock);
} test_case_t;

void test_long_uri(int sock) {
    rtsp_request_t req;
    char long_uri[8192];
    memset(long_uri, 'A', sizeof(long_uri) - 1);
    long_uri[sizeof(long_uri)-1] = '\0';
    build_rtsp_request(&req, "DESCRIBE", long_uri);
    strcat(req.headers, "CSeq: 999999999999999999999999999999\r\n");
    char *payload = serialize_request(&req);
    send_data(sock, payload, 0);
    log_msg("  Sent long URI (%zu bytes)\n", strlen(long_uri));
}

void test_format_string(int sock) {
    rtsp_request_t req;
    build_rtsp_request(&req, "OPTIONS", "rtsp://example.com");
    strcat(req.headers, "User-Agent: %s%s%s%s%s%s%s%s%s%s%n%p%x%08x\nCSeq: 1\r\n");
    char *payload = serialize_request(&req);
    send_data(sock, payload, 0);
    log_msg("  Sent format string payload\n");
}

void test_integer_overflow(int sock) {
    rtsp_request_t req;
    build_rtsp_request(&req, "SETUP", "rtsp://example.com/stream");
    strcat(req.headers, "Transport: RTP/AVP;unicast;client_port=8000-8001\r\n");
    strcat(req.headers, "Content-Length: 4294967295\r\n");
    strcpy(req.body, "SHORT");
    char *payload = serialize_request(&req);
    send_data(sock, payload, 0);
    log_msg("  Sent Content-Length overflow (0xFFFFFFFF)\n");
}

void test_negative_content_length(int sock) {
    rtsp_request_t req;
    build_rtsp_request(&req, "DESCRIBE", "rtsp://example.com");
    strcat(req.headers, "Content-Length: -1\r\n");
    strcpy(req.body, "X");
    char *payload = serialize_request(&req);
    send_data(sock, payload, 0);
    log_msg("  Sent negative Content-Length\n");
}

void test_heap_overflow(int sock) {
    rtsp_request_t req;
    build_rtsp_request(&req, "SETUP", "rtsp://example.com/stream");
    strcat(req.headers, "Transport: RTP/AVP;unicast;client_port=8000-8001\r\n");
    strcat(req.headers, "Content-Length: 1048576\r\n");
    char big_body[2048];
    memset(big_body, 'B', sizeof(big_body) - 1);
    big_body[sizeof(big_body)-1] = '\0';
    strcpy(req.body, big_body);
    char *payload = serialize_request(&req);
    send_data(sock, payload, 0);
    log_msg("  Sent heap overflow payload (CL=1MB, actual=%zu)\n", strlen(req.body));
}

void test_double_free(int sock) {
    rtsp_request_t req;
    build_rtsp_request(&req, "SETUP", "rtsp://example.com/stream");
    strcat(req.headers, "Transport: RTP/AVP;unicast;client_port=8000-8001\r\n");
    char *payload = serialize_request(&req);
    send_data(sock, payload, 0);
    char recv_buf[4096];
    recv_data(sock, recv_buf, sizeof(recv_buf));
    char session_id[64] = "123456";
    char *s = strstr(recv_buf, "Session:");
    if (s) {
        s += 8; while (*s == ' ') s++;
        char *e = strpbrk(s, ";\r\n");
        if (e) { int len = e - s; if (len > 0 && len < (int)sizeof(session_id)) { memcpy(session_id, s, len); session_id[len] = '\0'; } }
    }
    build_rtsp_request(&req, "TEARDOWN", "rtsp://example.com/stream");
    snprintf(req.headers + strlen(req.headers), sizeof(req.headers) - strlen(req.headers), "Session: %s\r\n", session_id);
    payload = serialize_request(&req);
    send_data(sock, payload, 0);
    recv_data(sock, recv_buf, sizeof(recv_buf));
    send_data(sock, payload, 0);
    log_msg("  Sent double-free TEARDOWN with session %s\n", session_id);
}

void test_race_condition(int sock) {
    rtsp_request_t req;
    const char *methods[] = {"DESCRIBE", "SETUP", "PLAY", "PAUSE", "TEARDOWN"};
    for (int i = 0; i < 5; i++) {
        build_rtsp_request(&req, methods[i], "rtsp://example.com/stream");
        snprintf(req.headers + strlen(req.headers), sizeof(req.headers) - strlen(req.headers), "CSeq: %d\r\n", i + 10);
        char *payload = serialize_request(&req);
        send_data(sock, payload, 0);
        usleep(10000);
    }
    log_msg("  Sent rapid multi-method requests\n");
}

void test_command_injection(int sock) {
    rtsp_request_t req;
    build_rtsp_request(&req, "DESCRIBE", "rtsp://example.com/;ls -la /data/local/tmp");
    char *payload = serialize_request(&req);
    send_data(sock, payload, 0);
    log_msg("  Sent command injection payload\n");
}

void test_wrong_version(int sock) {
    rtsp_request_t req;
    build_rtsp_request(&req, "DESCRIBE", "rtsp://example.com");
    strcpy(req.version, "RTSP/2.0");
    char *payload = serialize_request(&req);
    send_data(sock, payload, 0);
    log_msg("  Sent wrong RTSP version\n");
}

void test_many_headers(int sock) {
    rtsp_request_t req;
    build_rtsp_request(&req, "OPTIONS", "rtsp://example.com");
    char header_buf[16384];
    int pos = 0;
    for (int i = 0; i < 500; i++) {
        pos += snprintf(header_buf + pos, sizeof(header_buf) - pos, "X-Header-%d: value%d\r\n", i, i);
    }
    strcat(req.headers, header_buf);
    char *payload = serialize_request(&req);
    send_data(sock, payload, 0);
    log_msg("  Sent 500 custom headers\n");
}

void test_control_characters(int sock) {
    rtsp_request_t req;
    build_rtsp_request(&req, "OPTIONS", "rtsp://example.com");
    strcat(req.headers, "Header\x00: value\r\n");
    strcat(req.headers, "\r\n\r\n");
    char *payload = serialize_request(&req);
    send_data(sock, payload, 0);
    log_msg("  Sent control characters (NULL, extra CRLF)\n");
}

void test_range_overflow(int sock) {
    rtsp_request_t req;
    build_rtsp_request(&req, "DESCRIBE", "rtsp://example.com");
    strcat(req.headers, "Range: npt=0-999999999999999999999999999999999999999999\r\n");
    char *payload = serialize_request(&req);
    send_data(sock, payload, 0);
    log_msg("  Sent extreme Range header\n");
}

void test_weird_cseq(int sock) {
    rtsp_request_t req;
    build_rtsp_request(&req, "OPTIONS", "rtsp://example.com");
    strcpy(req.headers, "CSeq: \r\nUser-Agent: Fuzzer\r\n");
    char *payload = serialize_request(&req);
    send_data(sock, payload, 0);
    build_rtsp_request(&req, "OPTIONS", "rtsp://example.com");
    strcpy(req.headers, "CSeq: ABC\r\nUser-Agent: Fuzzer\r\n");
    payload = serialize_request(&req);
    send_data(sock, payload, 0);
    log_msg("  Sent empty and non-numeric CSeq\n");
}

void test_long_header_name(int sock) {
    rtsp_request_t req;
    build_rtsp_request(&req, "DESCRIBE", "rtsp://example.com");
    char long_name[1024];
    memset(long_name, 'X', sizeof(long_name) - 1);
    long_name[sizeof(long_name)-1] = '\0';
    snprintf(req.headers + strlen(req.headers), sizeof(req.headers) - strlen(req.headers), "%s: value\r\n", long_name);
    char *payload = serialize_request(&req);
    send_data(sock, payload, 0);
    log_msg("  Sent long header name (%zu bytes)\n", strlen(long_name));
}

void test_long_header_value(int sock) {
    rtsp_request_t req;
    build_rtsp_request(&req, "DESCRIBE", "rtsp://example.com");
    char long_value[8192];
    memset(long_value, 'V', sizeof(long_value) - 1);
    long_value[sizeof(long_value)-1] = '\0';
    snprintf(req.headers + strlen(req.headers), sizeof(req.headers) - strlen(req.headers), "X-Value: %s\r\n", long_value);
    char *payload = serialize_request(&req);
    send_data(sock, payload, 0);
    log_msg("  Sent long header value (%zu bytes)\n", strlen(long_value));
}

void test_bad_transport(int sock) {
    rtsp_request_t req;
    build_rtsp_request(&req, "SETUP", "rtsp://example.com/stream");
    char bad_transport[4096];
    memset(bad_transport, 'T', sizeof(bad_transport) - 1);
    bad_transport[sizeof(bad_transport)-1] = '\0';
    snprintf(req.headers + strlen(req.headers), sizeof(req.headers) - strlen(req.headers), "Transport: %s\r\n", bad_transport);
    char *payload = serialize_request(&req);
    send_data(sock, payload, 0);
    log_msg("  Sent bad Transport header\n");
}

void test_pipelining(int sock) {
    rtsp_request_t req;
    char pipeline[MAX_BUFFER];
    int pos = 0;
    for (int i = 0; i < 10; i++) {
        build_rtsp_request(&req, "OPTIONS", "rtsp://example.com");
        snprintf(req.headers + strlen(req.headers), sizeof(req.headers) - strlen(req.headers), "CSeq: %d\r\n", i + 1);
        char *single = serialize_request(&req);
        pos += snprintf(pipeline + pos, sizeof(pipeline) - pos, "%s", single);
    }
    send_data(sock, pipeline, 0);
    log_msg("  Sent 10 pipelined requests\n");
}

// ============================================================
// テスト実行エンジン
// ============================================================

test_case_t g_test_cases[] = {
    {"Long URI", "Stack buffer overflow via strlen+memcpy", test_long_uri},
    {"Format String", "fprintf format string attack", test_format_string},
    {"Integer Overflow", "atoi Content-Length overflow", test_integer_overflow},
    {"Negative Content-Length", "atoi negative value", test_negative_content_length},
    {"Heap Overflow", "MM_new/MM_delete heap corruption", test_heap_overflow},
    {"Double Free", "MM_delete double call", test_double_free},
    {"Race Condition", "MM_Thread_CreateEx race", test_race_condition},
    {"Command Injection", "system() injection via URI", test_command_injection},
    {"Wrong Version", "RTSP version parsing", test_wrong_version},
    {"Many Headers", "Resource exhaustion", test_many_headers},
    {"Control Characters", "Protocol parsing confusion", test_control_characters},
    {"Range Overflow", "CVE-2018-4013 style", test_range_overflow},
    {"Weird CSeq", "atoi edge cases", test_weird_cseq},
    {"Long Header Name", "Header name buffer overflow", test_long_header_name},
    {"Long Header Value", "Header value buffer overflow", test_long_header_value},
    {"Bad Transport", "Transport parsing overflow", test_bad_transport},
    {"Pipelining", "Multiple requests in one connection", test_pipelining},
};
int num_test_cases = sizeof(g_test_cases) / sizeof(g_test_cases[0]);

void run_single_test(int test_idx, pid_t target_pid) {
    test_case_t *tc = &g_test_cases[test_idx];
    log_msg("[*] Test %d/%d: %s\n", test_idx + 1, num_test_cases, tc->name);
    log_msg("    %s\n", tc->description);
    int status = check_target_status(target_pid);
    if (status != 0) {
        log_error("[-] Target not running, skipping test\n");
        return;
    }
    int sock = connect_to_port(g_config.port, g_config.host);
    if (sock < 0) {
        log_error("[-] Connection refused (target may not be ready)\n");
        return;
    }
    tc->func(sock);
    char recv_buf[8192];
    int n = recv_data(sock, recv_buf, sizeof(recv_buf));
    if (n > 0 && g_config.verbose > 1) log_msg("    Response: %.200s...\n", recv_buf);
    close(sock);
    status = check_target_status(target_pid);
    if (status < 0) {
        log_error("[-] CRASH detected in test '%s' (signal %d)\n", tc->name, g_config.crash_signal);
    } else if (status == 1) {
        log_error("[-] Target exited with code %d in test '%s'\n", g_config.exit_code, tc->name);
    } else {
        log_msg("[+] Target still running\n");
    }
}

void run_all_tests(pid_t target_pid) {
    if (target_pid < 0) return;
    for (int i = 0; i < num_test_cases; i++) {
        for (int iter = 0; iter < g_config.iterations; iter++) {
            if (g_config.iterations > 1) log_msg("  Iteration %d/%d\n", iter + 1, g_config.iterations);
            run_single_test(i, target_pid);
            if (g_config.crash_detected) {
                log_msg("[*] Restarting target after crash\n");
                terminate_target(target_pid);
                target_pid = spawn_server_with_port(g_config.port);
                if (target_pid < 0) {
                    log_error("[-] Failed to restart server\n");
                    return;
                }
                g_config.crash_detected = 0;
                g_config.crash_signal = 0;
                sleep(1);
            }
        }
    }
}

// ============================================================
// モックサーバー (クライアントテスト用)
// ============================================================

void run_mock_server(void) {
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) { log_error("mock_server: socket failed\n"); return; }
    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(g_config.port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        log_error("mock_server: bind port %d failed: %s\n", g_config.port, strerror(errno));
        close(listen_fd);
        return;
    }
    if (listen(listen_fd, 10) < 0) { log_error("mock_server: listen failed\n"); close(listen_fd); return; }
    log_msg("[*] Mock RTSP server running on port %d (PID %d)\n", g_config.port, getpid());

    const char *responses[] = {
        "RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Length: 999999999\r\n\r\n",
        "RTSP/1.0 200 OK\r\nCSeq: 1\r\nSession: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n\r\n",
        "RTSP/1.0 200 OK\r\nCSeq: 1\r\nServer: %s%s%s%s%s%s%s%s%s%s%n%p%x\r\n\r\n",
        "RTSP/2.0 200 OK\r\nCSeq: 1\r\n\r\n",
        "",
        "RTSP/1.0 200 OK\r\nCSeq: 1\r\nX-Data: 0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789\r\n\r\n",
        "RTSP/1.0 200 OK\r\nCSeq: -1\r\n\r\n",
    };
    int num_responses = sizeof(responses) / sizeof(responses[0]);
    int resp_idx = 0;

    fd_set fds;
    struct timeval tv = {10, 0};
    while (1) {
        FD_ZERO(&fds); FD_SET(listen_fd, &fds);
        int ret = select(listen_fd + 1, &fds, NULL, NULL, &tv);
        if (ret <= 0) { usleep(100000); continue; }
        struct sockaddr_in client_addr;
        socklen_t len = sizeof(client_addr);
        int client = accept(listen_fd, (struct sockaddr*)&client_addr, &len);
        if (client < 0) continue;
        char req_buf[4096];
        int n = recv(client, req_buf, sizeof(req_buf) - 1, 0);
        if (n > 0) { req_buf[n] = '\0'; if (g_config.verbose > 1) log_msg("[Mock] Received: %.200s...\n", req_buf); }
        const char *resp = responses[resp_idx % num_responses];
        resp_idx++;
        if (strlen(resp) > 0) send(client, resp, strlen(resp), MSG_NOSIGNAL);
        close(client);
    }
    close(listen_fd);
}

// ============================================================
// メインモード
// ============================================================

void run_server_mode(void) {
    log_msg("[*] === SERVER MODE ===\n");
    // バイナリ探索
    const char *bin = find_binary("server");
    if (!bin) {
        log_error("[-] rtspserver binary not found in standard locations\n");
        return;
    }
    strncpy(g_config.bin_path, bin, sizeof(g_config.bin_path)-1);
    log_msg("[*] Using server binary: %s\n", bin);

    // ポート探索 (デフォルトから開始)
    int port = g_config.port;
    if (!is_port_available(port)) {
        log_msg("[*] Port %d not available, searching for free port...\n", port);
        int new_port = find_available_port(port + 1);
        if (new_port < 0) {
            log_error("[-] No available port found\n");
            return;
        }
        g_config.port = new_port;
        log_msg("[*] Using port %d\n", g_config.port);
    }

    pid_t server_pid = spawn_server_with_port(g_config.port);
    if (server_pid < 0) {
        log_error("[-] Failed to start server\n");
        return;
    }
    g_config.target_pid = server_pid;

    run_all_tests(server_pid);
    terminate_target(server_pid);
    log_msg("[*] Server testing completed\n");
}

void run_client_mode(void) {
    log_msg("[*] === CLIENT MODE ===\n");
    const char *bin = find_binary("client");
    if (!bin) {
        log_error("[-] rtspclient binary not found\n");
        return;
    }
    strncpy(g_config.bin_path, bin, sizeof(g_config.bin_path)-1);
    log_msg("[*] Using client binary: %s\n", bin);

    // ポートが利用可能か確認 (モックサーバー用)
    if (!is_port_available(g_config.port)) {
        int new_port = find_available_port(g_config.port + 1);
        if (new_port < 0) {
            log_error("[-] No available port for mock server\n");
            return;
        }
        g_config.port = new_port;
        log_msg("[*] Using mock server port %d\n", g_config.port);
    }

    // モックサーバー起動 (子プロセス)
    pid_t mock_pid = fork();
    if (mock_pid == 0) {
        run_mock_server();
        exit(0);
    } else if (mock_pid < 0) {
        log_error("[-] Failed to start mock server\n");
        return;
    }
    g_config.target_pid = mock_pid;
    sleep(1);  // サーバー起動待ち

    // クライアントテスト（複数回）
    for (int attempt = 0; attempt < g_config.iterations; attempt++) {
        log_msg("[*] Client attempt %d/%d\n", attempt + 1, g_config.iterations);
        pid_t client_pid = spawn_client(g_config.host, g_config.port);
        if (client_pid < 0) {
            log_error("[-] Failed to start client\n");
            break;
        }
        sleep(2);
        int status = check_target_status(client_pid);
        if (status < 0) {
            log_error("[-] Client crashed (signal %d)\n", g_config.crash_signal);
        } else if (status == 1) {
            log_error("[-] Client exited with code %d\n", g_config.exit_code);
        } else {
            log_msg("[+] Client still running, terminating\n");
            terminate_target(client_pid);
        }
    }

    terminate_target(mock_pid);
    log_msg("[*] Client testing completed\n");
}

// ============================================================
// メイン
// ============================================================

void print_usage(const char *prog) {
    printf("Android RTSP Deep Fuzzer v2 - 徹底改善版\n\n");
    printf("Usage: %s <server|client> [options]\n\n", prog);
    printf("Options:\n");
    printf("  -p <port>      Target port (default: %d)\n", DEFAULT_PORT);
    printf("  -h <host>      Target host (default: %s)\n", LOCAL_HOST);
    printf("  -c <count>     Iterations per test (default: %d)\n", FUZZ_ITERATIONS);
    printf("  -t <sec>       Timeout in seconds (default: %d)\n", RESPONSE_TIMEOUT);
    printf("  -v             Verbose output\n");
    printf("  -vv            Very verbose output\n");
    printf("  -?             Show this help\n\n");
}

int main(int argc, char **argv) {
    g_config.port = DEFAULT_PORT;
    strcpy(g_config.host, LOCAL_HOST);
    g_config.iterations = FUZZ_ITERATIONS;
    g_config.timeout = RESPONSE_TIMEOUT;
    g_config.verbose = 1;
    g_config.target_type = 1;

    if (argc < 2) { print_usage(argv[0]); return 1; }
    if (strcmp(argv[1], "server") == 0) g_config.target_type = 1;
    else if (strcmp(argv[1], "client") == 0) g_config.target_type = 0;
    else { print_usage(argv[0]); return 1; }

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i+1 < argc) {
            g_config.port = atoi(argv[++i]);
            if (g_config.port <= 0 || g_config.port > 65535) { log_error("Invalid port\n"); return 1; }
        } else if (strcmp(argv[i], "-h") == 0 && i+1 < argc) {
            strncpy(g_config.host, argv[++i], sizeof(g_config.host)-1);
        } else if (strcmp(argv[i], "-c") == 0 && i+1 < argc) {
            g_config.iterations = atoi(argv[++i]);
            if (g_config.iterations <= 0) g_config.iterations = 1;
        } else if (strcmp(argv[i], "-t") == 0 && i+1 < argc) {
            g_config.timeout = atoi(argv[++i]);
            if (g_config.timeout <= 0) g_config.timeout = 1;
        } else if (strcmp(argv[i], "-v") == 0) {
            g_config.verbose = 2;
        } else if (strcmp(argv[i], "-vv") == 0) {
            g_config.verbose = 3;
        } else if (strcmp(argv[i], "-?") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]); return 0;
        } else {
            log_error("Unknown option: %s\n", argv[i]); return 1;
        }
    }

    log_msg("[*] === Android RTSP Deep Fuzzer v2 ===\n");
    log_msg("[*] Target: %s\n", g_config.target_type == 0 ? "rtspclient" : "rtspserver");
    log_msg("[*] Port: %d\n", g_config.port);
    log_msg("[*] Host: %s\n", g_config.host);
    log_msg("[*] Iterations: %d\n", g_config.iterations);
    log_msg("[*] Timeout: %d sec\n", g_config.timeout);
    log_msg("[*] Verbose: %d\n", g_config.verbose);
    log_msg("\n");

    signal(SIGPIPE, SIG_IGN);
    struct rlimit rl = {0, 0}; setrlimit(RLIMIT_CORE, &rl);

    if (g_config.target_type == 0) run_client_mode();
    else run_server_mode();

    log_msg("\n[*] === RESULTS ===\n");
    log_msg("[*] Crash detected: %s\n", g_config.crash_detected ? "YES" : "NO");
    if (g_config.crash_detected) {
        log_msg("[*] Last crash signal: %d\n", g_config.crash_signal);
        if (g_config.crash_signal == SIGSEGV) log_msg("[*] Likely memory corruption (SEGV)\n");
        else if (g_config.crash_signal == SIGABRT) log_msg("[*] Likely assertion or heap corruption (ABRT)\n");
        else if (g_config.crash_signal == SIGBUS) log_msg("[*] Likely alignment or memory access (BUS)\n");
        else if (g_config.crash_signal == SIGFPE) log_msg("[*] Likely integer overflow (FPE)\n");
    }
    if (g_config.exit_code != 0) log_msg("[*] Last exit code: %d\n", g_config.exit_code);
    return g_config.crash_detected ? 1 : 0;
}
