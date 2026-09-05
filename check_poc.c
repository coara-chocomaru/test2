/*
 * set_fastboot_flag.c
 * DNAND_ID_FASTBOOT_FLAG (ID=29) を /dev/dnand_cdev に ioctl で書き込む
 * コンパイル: aarch64-linux-android-gcc -static -O2 -o set_fastboot_flag set_fastboot_flag.c
 * 実行: adb shell su -c "/data/local/tmp/set_fastboot_flag 1"   (有効化)
 *       adb shell su -c "/data/local/tmp/set_fastboot_flag 0"   (無効化)
 *       引数なしの場合は現在の値を読み取って表示
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/ioctl.h>

/* DNAND デバイスパス */
#define DNAND_DEVICE "/dev/dnand_cdev"

/* ioctl コマンド (カーネルドライバ定義) */
#define DNAND_IOCTL_WRITE   0x10
#define DNAND_IOCTL_READ    0x11

/* ターゲット ID */
#define DNAND_ID_FASTBOOT_FLAG 29

/* カーネルとの通信構造体 (64bit アーキテクチャ準拠) */
struct dnand_ioctl_req {
    uint32_t id;       /* オフセット 0x00 */
    uint32_t value;    /* オフセット 0x04 : 書き込み値または読み取りバッファサイズ */
    uint64_t data_ptr; /* オフセット 0x08 : データバッファポインタ (フラグ操作時は 0) */
    uint32_t data_len; /* オフセット 0x10 : バッファサイズ (フラグ操作時は 0) */
};

/* フラグを設定する (enable=1 で有効、0 で無効) */
static int set_fastboot_flag(int enable) {
    int fd;
    int ret;
    struct dnand_ioctl_req req = {0};

    fd = open(DNAND_DEVICE, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "Failed to open %s: %s (errno=%d)\n", DNAND_DEVICE, strerror(errno), errno);
        return -1;
    }

    req.id = DNAND_ID_FASTBOOT_FLAG;
    req.value = enable ? 1 : 0;
    req.data_ptr = 0;
    req.data_len = 0;

    ret = ioctl(fd, DNAND_IOCTL_WRITE, &req);
    if (ret < 0) {
        fprintf(stderr, "ioctl WRITE failed: %s (errno=%d)\n", strerror(errno), errno);
        close(fd);
        return -1;
    }

    printf("Successfully wrote FASTBOOT_FLAG = %d\n", enable);
    close(fd);
    return 0;
}

/* 現在のフラグ値を読み取る */
static int get_fastboot_flag(void) {
    int fd;
    int ret;
    uint32_t val = 0;
    struct dnand_ioctl_req req = {0};

    fd = open(DNAND_DEVICE, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "Failed to open %s: %s\n", DNAND_DEVICE, strerror(errno));
        return -1;
    }

    req.id = DNAND_ID_FASTBOOT_FLAG;
    req.value = sizeof(val);
    req.data_ptr = (uint64_t)&val;
    req.data_len = sizeof(val);

    ret = ioctl(fd, DNAND_IOCTL_READ, &req);
    if (ret < 0) {
        fprintf(stderr, "ioctl READ failed: %s (errno=%d)\n", strerror(errno), errno);
        close(fd);
        return -1;
    }

    printf("Current FASTBOOT_FLAG value = %u\n", val);
    close(fd);
    return val;
}

int main(int argc, char *argv[]) {
    if (argc >= 2) {
        int val = atoi(argv[1]);
        if (val == 0 || val == 1) {
            return set_fastboot_flag(val);
        } else {
            fprintf(stderr, "Usage: %s [0|1]  (0=disable, 1=enable)\n", argv[0]);
            fprintf(stderr, "       %s          (read current value)\n", argv[0]);
            return 1;
        }
    } else {
        return get_fastboot_flag();
    }
}
