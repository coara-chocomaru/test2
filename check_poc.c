/*
 * set_fastboot_deep.c
 * 多角的アプローチで Fastboot 移行フラグを確実に設定する
 * コンパイル: aarch64-linux-android-gcc -static -O2 -o set_fastboot_deep set_fastboot_deep.c
 * 実行: adb shell su -c "/data/local/tmp/set_fastboot_deep"
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#define DNAND_DEVICE "/dev/dnand_cdev"
#define DNAND_IOCTL_WRITE   0x10
#define DNAND_IOCTL_READ    0x11

// ターゲット ID
#define DNAND_ID_FASTBOOT_FLAG  29
#define DNAND_ID_REBOOT_PARM    20
#define DNAND_ID_OS_MODE        27

// 20バイトパック構造体
struct __attribute__((packed)) dnand_req {
    uint32_t id;
    uint32_t value;
    uint64_t data_ptr;
    uint32_t data_len;
};
_Static_assert(sizeof(struct dnand_req) == 20, "struct must be 20 bytes");

/* ====== DNAND 基本 I/O ====== */
static int dnand_open(void) {
    int fd = open(DNAND_DEVICE, O_RDWR);
    if (fd < 0)
        fprintf(stderr, "open %s failed: %s\n", DNAND_DEVICE, strerror(errno));
    return fd;
}

/* 読み取り (data_ptr にバッファを渡す) */
static int dnand_read_id(int id, uint32_t *out) {
    int fd = dnand_open();
    if (fd < 0) return -1;
    struct dnand_req req = {
        .id = id,
        .value = 0,
        .data_ptr = (uint64_t)out,
        .data_len = sizeof(*out)
    };
    int ret = ioctl(fd, DNAND_IOCTL_READ, &req);
    close(fd);
    if (ret < 0) fprintf(stderr, "read id %d failed: %s\n", id, strerror(errno));
    return ret;
}

/* 数値書き込み (ID + value) */
static int dnand_write_value(int id, uint32_t val) {
    int fd = dnand_open();
    if (fd < 0) return -1;
    struct dnand_req req = {
        .id = id,
        .value = 0,
        .data_ptr = (uint64_t)&val,
        .data_len = sizeof(val)
    };
    int ret = ioctl(fd, DNAND_IOCTL_WRITE, &req);
    close(fd);
    if (ret < 0) fprintf(stderr, "write id %d val %u failed: %s\n", id, val, strerror(errno));
    return ret;
}

/* 文字列書き込み (ID + 文字列) */
static int dnand_write_string(int id, const char *str) {
    int fd = dnand_open();
    if (fd < 0) return -1;
    size_t len = strlen(str) + 1; // NULL終端含む
    struct dnand_req req = {
        .id = id,
        .value = 0,
        .data_ptr = (uint64_t)str,
        .data_len = len
    };
    int ret = ioctl(fd, DNAND_IOCTL_WRITE, &req);
    close(fd);
    if (ret < 0) fprintf(stderr, "write string id %d failed: %s\n", id, strerror(errno));
    return ret;
}

/* ====== MISC パーティション書き込み (従来方式) ====== */
static int write_misc(const char *data) {
    const char *paths[] = {
        "/dev/block/bootdevice/by-name/misc",
        "/dev/block/by-name/misc",
        NULL
    };
    int fd = -1;
    for (int i = 0; paths[i]; i++) {
        fd = open(paths[i], O_RDWR | O_SYNC);
        if (fd >= 0) break;
    }
    if (fd < 0) {
        fprintf(stderr, "misc partition not found\n");
        return -1;
    }
    size_t len = strlen(data);
    ssize_t written = write(fd, data, len);
    close(fd);
    if (written != (ssize_t)len) {
        fprintf(stderr, "misc write failed: %s\n", strerror(errno));
        return -1;
    }
    printf("[+] misc パーティションに '%s' を書き込みました\n", data);
    return 0;
}

/* ====== メイン ====== */
int main(void) {
    uint32_t val29, val20, val27;

    printf("=== Fastboot 移行フラグ ディープ設定 ===\n\n");

    // 1. 現在値の読み取り
    printf("[*] 現在の各フラグ値を読み取り中...\n");
    if (dnand_read_id(DNAND_ID_FASTBOOT_FLAG, &val29) == 0)
        printf("    ID 29 (FASTBOOT_FLAG) = %u\n", val29);
    if (dnand_read_id(DNAND_ID_REBOOT_PARM, &val20) == 0)
        printf("    ID 20 (REBOOT_PARM)   = %u (数値として)\n", val20);
    if (dnand_read_id(DNAND_ID_OS_MODE, &val27) == 0)
        printf("    ID 27 (OS_MODE)       = %u\n", val27);
    printf("\n");

    // 2. すべての関連フラグを設定
    printf("[*] Fastboot 移行のための全フラグを設定します...\n");

    // 2-1: FASTBOOT_FLAG = 1
    if (dnand_write_value(DNAND_ID_FASTBOOT_FLAG, 1) == 0)
        printf("[+] ID 29 (FASTBOOT_FLAG) = 1 設定完了\n");

    // 2-2: REBOOT_PARM に "bootloader" を書き込む (文字列)
    if (dnand_write_string(DNAND_ID_REBOOT_PARM, "bootloader") == 0)
        printf("[+] ID 20 (REBOOT_PARM) に 'bootloader' 書き込み完了\n");

    // 2-3: OS_MODE = 0 (通常起動? 1だとリカバリ? 0が安全)
    if (dnand_write_value(DNAND_ID_OS_MODE, 0) == 0)
        printf("[+] ID 27 (OS_MODE) = 0 設定完了\n");

    printf("\n");

    // 3. 従来の MISC パーティション方式も併用
    printf("[*] /misc パーティションにも 'bootloader' を書き込みます\n");
    write_misc("bootloader");

    printf("\n");
    printf("[完了] すべての設定が完了しました。\n");
    printf("[注意] 必ず 'adb shell reboot' または 'reboot' で再起動してください。\n");
    printf("       再起動後、デバイスが Fastboot モードで起動するはずです。\n");

    // 念のため再読み取りして確認
    printf("\n[*] 設定後の値を再確認...\n");
    if (dnand_read_id(DNAND_ID_FASTBOOT_FLAG, &val29) == 0)
        printf("    ID 29 (FASTBOOT_FLAG) = %u\n", val29);
    if (dnand_read_id(DNAND_ID_REBOOT_PARM, &val20) == 0) {
        // 文字列として読めるか試す (安全のため数値表示)
        printf("    ID 20 (REBOOT_PARM)   = %u (数値)\n", val20);
    }

    return 0;
}
