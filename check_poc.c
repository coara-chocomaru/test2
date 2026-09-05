/*
 * set_fastboot_multi.c
 * 複数の書き込みパターンを試して DNAND_ID_FASTBOOT_FLAG (ID=29) を設定する
 * コンパイル: aarch64-linux-android-gcc -static -O2 -o set_fastboot_multi set_fastboot_multi.c
 * 使用法:
 *   ./set_fastboot_multi --get               → 現在の値を読み取る
 *   ./set_fastboot_multi --set 1             → 有効化 (Fastboot起動) を試行
 *   ./set_fastboot_multi --set 0             → 無効化
 *   ./set_fastboot_multi                     → デフォルトで読み取りのみ
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

/* カーネルとの通信構造体 (64bit アーキテクチャ準拠) */
struct dnand_ioctl_req {
    uint32_t id;       /* 0x00 */
    uint32_t value;    /* 0x04 : 書き込み値 または 読み取りバッファサイズ */
    uint64_t data_ptr; /* 0x08 : データバッファポインタ */
    uint32_t data_len; /* 0x10 : バッファサイズ */
};

/* ----- 基本 I/O 関数 ----- */
static int dnand_open(void) {
    int fd = open(DNAND_DEVICE, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "Failed to open %s: %s (errno=%d)\n", DNAND_DEVICE, strerror(errno), errno);
    }
    return fd;
}

/* 現在のフラグ値を読み取る (成功なら 0/1 を返し、*val に格納) */
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

/* ----- 書き込みパターン ----- */

/* パターン1: 従来通り value フィールドに直接 0/1 をセット (data_ptr=0, data_len=0) */
static int write_pattern_value(int fd, int enable) {
    struct dnand_ioctl_req req = {
        .id = DNAND_ID_FASTBOOT_FLAG,
        .value = enable ? 1 : 0,
        .data_ptr = 0,
        .data_len = 0
    };
    return ioctl(fd, DNAND_IOCTL_WRITE, &req);
}

/* パターン2: value=0 にして data_ptr にバッファを指し、data_len でサイズ指定 (一部ドライバが data_ptr を優先する可能性) */
static int write_pattern_data_ptr(int fd, int enable) {
    uint32_t buf = enable ? 1 : 0;
    struct dnand_ioctl_req req = {
        .id = DNAND_ID_FASTBOOT_FLAG,
        .value = 0,
        .data_ptr = (uint64_t)&buf,
        .data_len = sizeof(buf)
    };
    return ioctl(fd, DNAND_IOCTL_WRITE, &req);
}

/* パターン3: value と data_ptr の両方に値をセット (互換性テスト) */
static int write_pattern_both(int fd, int enable) {
    uint32_t buf = enable ? 1 : 0;
    struct dnand_ioctl_req req = {
        .id = DNAND_ID_FASTBOOT_FLAG,
        .value = enable ? 1 : 0,
        .data_ptr = (uint64_t)&buf,
        .data_len = sizeof(buf)
    };
    return ioctl(fd, DNAND_IOCTL_WRITE, &req);
}

/* 全パターンを順に試行し、成功したパターン番号を返す (0=失敗) */
static int try_all_write_patterns(int enable) {
    int fd = dnand_open();
    if (fd < 0) return 0;

    int patterns[] = {1, 2, 3};
    int (*funcs[])(int, int) = {
        write_pattern_value,
        write_pattern_data_ptr,
        write_pattern_both
    };
    const char *names[] = {
        "value direct",
        "data_ptr only",
        "both value and data_ptr"
    };

    int success = 0;
    for (int i = 0; i < 3; i++) {
        printf("[*] パターン %d (%s) を試行中... ", i+1, names[i]);
        int ret = funcs[i](fd, enable);
        if (ret == 0) {
            printf("成功\n");
            success = i+1;
            break;
        } else {
            printf("失敗 (errno=%d)\n", errno);
        }
    }
    close(fd);
    return success;
}

/* ----- メイン関数 ----- */
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

    // 現在値を読み取り
    int cur_val;
    if (dnand_get_flag(&cur_val) == 0) {
        printf("[情報] 現在の FASTBOOT_FLAG = %d\n", cur_val);
    } else {
        printf("[警告] 現在値の読み取りに失敗しました。\n");
    }

    if (do_set) {
        printf("\n[実行] FASTBOOT_FLAG を %d に設定するため、全パターンを試行します。\n", set_val);
        int success = try_all_write_patterns(set_val);
        if (success) {
            printf("\n[成功] パターン %d で書き込みに成功しました。\n", success);
            // 読み取り検証
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
            printf("\n[エラー] 全ての書き込みパターンが失敗しました。\n");
            return 1;
        }
    }

    return 0;
}
