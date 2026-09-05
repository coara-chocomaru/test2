/*
 * set_fastboot_final.c
 * 複数の ioctl コマンド番号と構造体サイズを試行して DNAND_FASTBOOT_FLAG を設定
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <linux/ioctl.h>   // _IOW マクロ用

#define DNAND_DEVICE "/dev/dnand_cdev"
#define DNAND_ID_FASTBOOT_FLAG 29

/* パディングなし構造体 (20バイト) */
struct __attribute__((packed)) dnand_req_20 {
    uint32_t id;
    uint32_t value;
    uint64_t data_ptr;
    uint32_t data_len;
};

/* パディングなし構造体 (16バイト) - data_len を省略 */
struct __attribute__((packed)) dnand_req_16 {
    uint32_t id;
    uint32_t value;
    uint64_t data_ptr;
};

/* コマンド番号の候補 */
#define CMD_0x10       0x10
#define CMD_IOW_D      _IOW('d', 0x10, struct dnand_req_20)
#define CMD_IOW_D_16   _IOW('d', 0x10, struct dnand_req_16)
/* さらに type='D' も試す */
#define CMD_IOW_D_CAPS _IOW('D', 0x10, struct dnand_req_20)

static int dnand_open(void) {
    int fd = open(DNAND_DEVICE, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "Failed to open %s: %s (errno=%d)\n", DNAND_DEVICE, strerror(errno), errno);
    }
    return fd;
}

static int dnand_get_flag(int *val) {
    int fd = dnand_open();
    if (fd < 0) return -1;

    uint32_t read_val = 0;
    struct dnand_req_20 req = {
        .id = DNAND_ID_FASTBOOT_FLAG,
        .value = sizeof(read_val),
        .data_ptr = (uint64_t)&read_val,
        .data_len = sizeof(read_val)
    };
    // 読み取りには CMD_0x10 を使用（アセンブリ準拠）
    int ret = ioctl(fd, CMD_0x10, &req);
    close(fd);
    if (ret < 0) {
        fprintf(stderr, "ioctl READ failed: %s (errno=%d)\n", strerror(errno), errno);
        return -1;
    }
    *val = (int)read_val;
    return 0;
}

/* 各パターンを試行する関数 */
static int try_write(int fd, unsigned long cmd, void *arg, size_t size, const char *desc) {
    printf("[*] 試行: %s (cmd=0x%lx, size=%zu)\n", desc, cmd, size);
    int ret = ioctl(fd, cmd, arg);
    if (ret == 0) {
        printf("[+] 成功\n");
        return 1;
    } else {
        printf("[-] 失敗 (errno=%d)\n", errno);
        return 0;
    }
}

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

    int cur_val;
    if (dnand_get_flag(&cur_val) == 0) {
        printf("[情報] 現在の FASTBOOT_FLAG = %d\n", cur_val);
    } else {
        printf("[警告] 現在値の読み取りに失敗しました。\n");
    }

    if (do_set) {
        printf("\n[実行] FASTBOOT_FLAG を %d に設定します。\n", set_val);
        int fd = dnand_open();
        if (fd < 0) return 1;

        int success = 0;

        // パターン1: 構造体20バイト、cmd=0x10 (アセンブリ準拠)
        {
            struct dnand_req_20 req = {
                .id = DNAND_ID_FASTBOOT_FLAG,
                .value = set_val,
                .data_ptr = 0,
                .data_len = 0
            };
            if (try_write(fd, CMD_0x10, &req, sizeof(req), "20バイト構造体, cmd=0x10")) success = 1;
        }

        // パターン2: 構造体20バイト、cmd=_IOW('d', 0x10, ...)
        if (!success) {
            struct dnand_req_20 req = {
                .id = DNAND_ID_FASTBOOT_FLAG,
                .value = set_val,
                .data_ptr = 0,
                .data_len = 0
            };
            if (try_write(fd, CMD_IOW_D, &req, sizeof(req), "20バイト構造体, cmd=_IOW('d',...)")) success = 1;
        }

        // パターン3: 構造体16バイト、cmd=0x10
        if (!success) {
            struct dnand_req_16 req = {
                .id = DNAND_ID_FASTBOOT_FLAG,
                .value = set_val,
                .data_ptr = 0
            };
            if (try_write(fd, CMD_0x10, &req, sizeof(req), "16バイト構造体, cmd=0x10")) success = 1;
        }

        // パターン4: 構造体16バイト、cmd=_IOW('d', 0x10, 16バイト構造体)
        if (!success) {
            struct dnand_req_16 req = {
                .id = DNAND_ID_FASTBOOT_FLAG,
                .value = set_val,
                .data_ptr = 0
            };
            if (try_write(fd, CMD_IOW_D_16, &req, sizeof(req), "16バイト構造体, cmd=_IOW('d',...) (16)")) success = 1;
        }

        // パターン5: 構造体20バイト、cmd=_IOW('D', 0x10, ...) (大文字D)
        if (!success) {
            struct dnand_req_20 req = {
                .id = DNAND_ID_FASTBOOT_FLAG,
                .value = set_val,
                .data_ptr = 0,
                .data_len = 0
            };
            if (try_write(fd, CMD_IOW_D_CAPS, &req, sizeof(req), "20バイト構造体, cmd=_IOW('D',...)")) success = 1;
        }

        // パターン6: data_ptr にダミーバッファを指定 (20バイト構造体、cmd=0x10)
        if (!success) {
            uint32_t dummy = set_val;
            struct dnand_req_20 req = {
                .id = DNAND_ID_FASTBOOT_FLAG,
                .value = 0,   // value は 0 にして data_ptr を使う
                .data_ptr = (uint64_t)&dummy,
                .data_len = sizeof(dummy)
            };
            if (try_write(fd, CMD_0x10, &req, sizeof(req), "20バイト構造体, data_ptr指定, cmd=0x10")) success = 1;
        }

        close(fd);

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
            printf("[エラー] 全てのパターンが失敗しました。\n");
            return 1;
        }
    }

    return 0;
}
