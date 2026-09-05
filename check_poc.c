/*
 * set_fastboot_final.c
 * 成功パターン (data_ptr使用、cmd=0x10/0x11、20バイト構造体) に特化
 * 加えて、複数のバリエーションを試行して確実に設定する
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
#define DNAND_IOCTL_WRITE   0x10   // 生の数値 (マクロ不使用)
#define DNAND_IOCTL_READ    0x11
#define DNAND_ID_FASTBOOT_FLAG 29

// 20バイトのパック構造体 (ドライバ期待値)
struct __attribute__((packed)) dnand_req {
    uint32_t id;
    uint32_t value;
    uint64_t data_ptr;
    uint32_t data_len;
};
_Static_assert(sizeof(struct dnand_req) == 20, "struct size must be 20");

static int dnand_open(void) {
    int fd = open(DNAND_DEVICE, O_RDWR);
    if (fd < 0)
        fprintf(stderr, "open %s failed: %s (errno=%d)\n", DNAND_DEVICE, strerror(errno), errno);
    return fd;
}

/* 読み取り */
static int dnand_get_flag(int *val) {
    int fd = dnand_open();
    if (fd < 0) return -1;

    uint32_t buf = 0;
    struct dnand_req req = {
        .id = DNAND_ID_FASTBOOT_FLAG,
        .value = sizeof(buf),       // 読み取りバッファサイズを value にセット (一部ドライバで必要)
        .data_ptr = (uint64_t)&buf,
        .data_len = sizeof(buf)
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

/* 書き込み関数 (バリエーションを試行) */
static int try_write_variation(int fd, int enable, int use_value, int use_ptr, int data_len) {
    struct dnand_req req = {0};
    req.id = DNAND_ID_FASTBOOT_FLAG;
    if (use_value) {
        req.value = enable ? 1 : 0;
    } else {
        req.value = 0;  // value は使わない
    }
    if (use_ptr) {
        uint32_t val = enable ? 1 : 0;
        req.data_ptr = (uint64_t)&val;
        req.data_len = data_len;   // 1, 2, 4 などを試す
    } else {
        req.data_ptr = 0;
        req.data_len = 0;
    }
    return ioctl(fd, DNAND_IOCTL_WRITE, &req);
}

/* 全バリエーションを試行 */
static int try_all_variations(int enable) {
    int fd = dnand_open();
    if (fd < 0) return -1;

    // バリエーション定義: {use_value, use_ptr, data_len}
    int variations[][3] = {
        {0, 1, 1},   // data_ptr=1バイト
        {0, 1, 2},   // data_ptr=2バイト
        {0, 1, 4},   // data_ptr=4バイト (最も確率が高い)
        {1, 1, 4},   // value と data_ptr 両方
        {0, 0, 0},   // value のみ (従来型)
        {1, 0, 0},   // value のみ (enableセット)
    };
    const char *desc[] = {
        "data_ptr=1バイト",
        "data_ptr=2バイト",
        "data_ptr=4バイト (value=0)",
        "value+data_ptr(4)",
        "valueのみ (value=0)",
        "valueのみ (value=1)"
    };

    int success = -1;
    for (int i = 0; i < 6; i++) {
        printf("[*] 試行 %d: %s ... ", i+1, desc[i]);
        int ret = try_write_variation(fd, enable, variations[i][0], variations[i][1], variations[i][2]);
        if (ret == 0) {
            printf("成功\n");
            success = i;
            break;
        } else {
            printf("失敗 (errno=%d)\n", errno);
        }
    }
    close(fd);
    return success;
}

int main(int argc, char *argv[]) {
    int do_set = 0, set_val = 0;

    if (argc >= 2) {
        if (strcmp(argv[1], "--get") == 0) {
            do_set = 0;
        } else if (strcmp(argv[1], "--set") == 0 && argc >= 3) {
            do_set = 1;
            set_val = atoi(argv[2]);
            if (set_val != 0 && set_val != 1) {
                fprintf(stderr, "値は 0 または 1 を指定\n");
                return 1;
            }
        } else {
            fprintf(stderr, "使用法: %s --get または --set 0|1\n", argv[0]);
            return 1;
        }
    }

    int cur;
    if (dnand_get_flag(&cur) == 0) {
        printf("[情報] 現在の FASTBOOT_FLAG = %d\n", cur);
    } else {
        printf("[警告] 現在値の読み取りに失敗\n");
    }

    if (do_set) {
        printf("\n[実行] FASTBOOT_FLAG を %d に設定します\n", set_val);
        int success = try_all_variations(set_val);
        if (success >= 0) {
            int new_val;
            if (dnand_get_flag(&new_val) == 0) {
                printf("[検証] 読み取り結果: %d\n", new_val);
                if (new_val == set_val) {
                    printf("[OK] 設定が正しく反映されました。再起動後に Fastboot モードになります。\n");
                } else {
                    printf("[警告] 書き込み後も値が変わりませんでした。\n");
                }
            }
        } else {
            printf("[エラー] 全ての書き込み試行が失敗しました。\n");
            return 1;
        }
    }
    return 0;
}
