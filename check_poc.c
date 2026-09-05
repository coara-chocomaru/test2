/*
 * set_fastboot_fixed.c
 * パディングを排除して /dev/dnand_cdev に正しく ioctl を送信する
 * コンパイル: aarch64-linux-android-gcc -static -O2 -o set_fastboot_fixed set_fastboot_fixed.c
 * 使用法:
 *   ./set_fastboot_fixed --get
 *   ./set_fastboot_fixed --set 1
 *   ./set_fastboot_fixed --set 0
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

/* パディングなし構造体 (20バイト) */
struct __attribute__((packed)) dnand_ioctl_req {
    uint32_t id;       /* 0x00 */
    uint32_t value;    /* 0x04 */
    uint64_t data_ptr; /* 0x08 */
    uint32_t data_len; /* 0x10 */
};

/* 構造体サイズが期待通りかコンパイル時チェック */
_Static_assert(sizeof(struct dnand_ioctl_req) == 20, "struct size must be 20 bytes");

/* ----- 基本 I/O ----- */
static int dnand_open(void) {
    int fd = open(DNAND_DEVICE, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "Failed to open %s: %s (errno=%d)\n", DNAND_DEVICE, strerror(errno), errno);
    }
    return fd;
}

/* 読み取り */
static int dnand_get_flag(int *val) {
    int fd = dnand_open();
    if (fd < 0) return -1;

    uint32_t read_val = 0;
    struct dnand_ioctl_req req = {
        .id = DNAND_ID_FASTBOOT_FLAG,
        .value = sizeof(read_val),
        .data_ptr = (uint64_t)&read_val,
        .data_len = sizeof(read_val)
    };
    int ret = ioctl(fd, DNAND_IOCTL_READ, &req);
    close(fd);
    if (ret < 0) {
        fprintf(stderr, "ioctl READ failed: %s (errno=%d)\n", strerror(errno), errno);
        return -1;
    }
    *val = (int)read_val;
    return 0;
}

/* 書き込み (パディングなし構造体版) */
static int write_with_packed_struct(int fd, int enable) {
    struct dnand_ioctl_req req = {
        .id = DNAND_ID_FASTBOOT_FLAG,
        .value = enable ? 1 : 0,
        .data_ptr = 0,
        .data_len = 0
    };
    return ioctl(fd, DNAND_IOCTL_WRITE, &req);
}

/* 書き込み (生バッファ版 – より確実) */
static int write_with_raw_buffer(int fd, int enable) {
    uint8_t buf[20] = {0};
    uint32_t id = DNAND_ID_FASTBOOT_FLAG;
    uint32_t val = enable ? 1 : 0;
    uint64_t ptr = 0;
    uint32_t len = 0;

    memcpy(buf + 0, &id, 4);
    memcpy(buf + 4, &val, 4);
    memcpy(buf + 8, &ptr, 8);
    memcpy(buf + 16, &len, 4);

    return ioctl(fd, DNAND_IOCTL_WRITE, buf);
}

/* 両方の方法を試行 */
static int try_both_methods(int enable) {
    int fd = dnand_open();
    if (fd < 0) return -1;

    int ret = -1;
    // 方法1: パディングなし構造体
    printf("[*] パディングなし構造体で書き込みを試行...\n");
    ret = write_with_packed_struct(fd, enable);
    if (ret == 0) {
        printf("[+] 構造体方式成功\n");
        close(fd);
        return 1;
    } else {
        printf("[-] 構造体方式失敗 (errno=%d)\n", errno);
    }

    // 方法2: 生バッファ
    printf("[*] 生バッファで書き込みを試行...\n");
    ret = write_with_raw_buffer(fd, enable);
    if (ret == 0) {
        printf("[+] 生バッファ方式成功\n");
        close(fd);
        return 2;
    } else {
        printf("[-] 生バッファ方式失敗 (errno=%d)\n", errno);
    }

    close(fd);
    return 0;
}

/* ----- メイン ----- */
int main(int argc, char *argv[]) {
    int do_set = 0;
    int set_val = 0;

    if (argc >= 2) {
        if (strcmp(argv[1], "--get") == 0) {
            do_set = 0;
        } else if (strcmp(argv[1], "--set") == 0 && argc >= 3) {
            do_set = 1;
            set_val = atoi(argv[2]);
            if (set_val != 0 && set_val != 1) {
                fprintf(stderr, "値は 0 または 1 を指定してください。\n");
                return 1;
            }
        } else {
            fprintf(stderr, "使用法: %s [--get] または --set 0|1\n", argv[0]);
            return 1;
        }
    }

    // 現在値読み取り
    int cur_val;
    if (dnand_get_flag(&cur_val) == 0) {
        printf("[情報] 現在の FASTBOOT_FLAG = %d\n", cur_val);
    } else {
        printf("[警告] 現在値の読み取りに失敗しました。\n");
    }

    if (do_set) {
        printf("\n[実行] FASTBOOT_FLAG を %d に設定します。\n", set_val);
        int success = try_both_methods(set_val);
        if (success) {
            int new_val;
            if (dnand_get_flag(&new_val) == 0) {
                printf("[検証] 読み取り結果: %d\n", new_val);
                if (new_val == set_val) {
                    printf("[OK] 設定が正しく反映されました。\n");
                } else {
                    printf("[警告] 書き込み後も値が期待通りではありません。\n");
                }
            }
        } else {
            printf("[エラー] 全ての書き込み方法が失敗しました。\n");
            return 1;
        }
    }

    return 0;
}
