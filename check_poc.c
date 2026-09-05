/*
 * set_fastboot_final.c
 * 完全に成功が確認された方法:
 *   - 構造体: 20バイト (packed)
 *   - ioctlコマンド: 生の数値 0x10 (write) / 0x11 (read)
 *   - データ: data_ptr に値のアドレス、data_len=4 (value=0)
 *
 * コンパイル: aarch64-linux-android-gcc -static -O2 -o set_fastboot_final set_fastboot_final.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/ioctl.h>

#define DNAND_DEVICE "/dev/dnand_cdev"
#define DNAND_IOCTL_WRITE   0x10
#define DNAND_IOCTL_READ    0x11
#define DNAND_ID_FASTBOOT_FLAG 29

/* 20バイトのパック構造体 (これがドライバの期待値) */
struct __attribute__((packed)) dnand_req {
    uint32_t id;       // 0x00
    uint32_t value;    // 0x04
    uint64_t data_ptr; // 0x08
    uint32_t data_len; // 0x10
};
_Static_assert(sizeof(struct dnand_req) == 20, "struct must be 20 bytes");

static int dnand_open(void) {
    int fd = open(DNAND_DEVICE, O_RDWR);
    if (fd < 0)
        fprintf(stderr, "open %s failed: %s (errno=%d)\n", DNAND_DEVICE, strerror(errno), errno);
    return fd;
}

/* 書き込み (成功パターン固定) */
static int dnand_set_flag(int enable) {
    int fd = dnand_open();
    if (fd < 0) return -1;

    uint32_t val = enable ? 1 : 0;
    struct dnand_req req = {
        .id = DNAND_ID_FASTBOOT_FLAG,
        .value = 0,                     // value は使わない (0固定)
        .data_ptr = (uint64_t)&val,     // 値のアドレスを渡す
        .data_len = sizeof(val)         // 4 バイト
    };

    int ret = ioctl(fd, DNAND_IOCTL_WRITE, &req);
    close(fd);

    if (ret < 0) {
        fprintf(stderr, "ioctl WRITE failed: %s (errno=%d)\n", strerror(errno), errno);
        return -1;
    }
    return 0;
}

/* 読み取り (同様の方法) */
static int dnand_get_flag(int *val) {
    int fd = dnand_open();
    if (fd < 0) return -1;

    uint32_t buf = 0;
    struct dnand_req req = {
        .id = DNAND_ID_FASTBOOT_FLAG,
        .value = 0,                     // value は使わない
        .data_ptr = (uint64_t)&buf,     // 読み取りバッファのアドレス
        .data_len = sizeof(buf)         // 4 バイト
    };

    int ret = ioctl(fd, DNAND_IOCTL_READ, &req);
    close(fd);

    if (ret < 0) {
        fprintf(stderr, "ioctl READ failed: %s (errno=%d)\n", strerror(errno), errno);
        return -1;
    }
    *val = (int)buf;
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc >= 2) {
        if (strcmp(argv[1], "--get") == 0) {
            int val;
            if (dnand_get_flag(&val) == 0) {
                printf("FASTBOOT_FLAG = %d\n", val);
            }
            return 0;
        } else if (strcmp(argv[1], "--set") == 0 && argc >= 3) {
            int val = atoi(argv[2]);
            if (val != 0 && val != 1) {
                fprintf(stderr, "値は 0 または 1 を指定\n");
                return 1;
            }
            printf("[実行] FASTBOOT_FLAG を %d に設定します...\n", val);
            if (dnand_set_flag(val) == 0) {
                printf("[成功] 書き込み完了\n");
                // 検証
                int new_val;
                if (dnand_get_flag(&new_val) == 0) {
                    printf("[検証] 読み取り結果: %d\n", new_val);
                    if (new_val == val) {
                        printf("[OK] 正しく反映されました。再起動後に Fastboot モードになります。\n");
                    } else {
                        printf("[警告] 値が期待通りではありません。\n");
                    }
                }
            }
            return 0;
        }
    }

    fprintf(stderr, "使用法: %s --get  または  %s --set 0|1\n", argv[0], argv[0]);
    return 1;
}
