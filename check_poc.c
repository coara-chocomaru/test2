/*
 * set_fastboot_final_real.c
 * 正しい ID マッピング (ID 12, 9, 29, 34, 35) に基づく最終多角的アプローチ
 * コンパイル: aarch64-linux-android-clang -static -O2 -o set_fastboot_final_real set_fastboot_final_real.c
 * 実行: adb shell su -c "/data/local/tmp/set_fastboot_final_real"
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

/* ===== 正しい ID 定義 (再カウント済み) ===== */
#define ID_FACTORY_CMDLINE      9   // カーネルコマンドライン追記
#define ID_REBOOT_PARM          12  // ★再起動パラメータ文字列
#define ID_FASTBOOT_FLAG        29  // フラグ
#define ID_RESCUE_ENABL_FLG     32  // レスキューモード有効
#define ID_OS_MODE              34  // OS モード
#define ID_RECOVERY_MODE        35  // リカバリモード
#define ID_FBDL_ENABLE          39  // Flash Boot Download (EDL)

// 20バイトパック構造体 (ドライバ期待値)
struct __attribute__((packed)) dnand_req {
    uint32_t id;
    uint32_t value;
    uint64_t data_ptr;
    uint32_t data_len;
};
_Static_assert(sizeof(struct dnand_req) == 20, "struct must be 20 bytes");

static int dnand_open(void) {
    int fd = open(DNAND_DEVICE, O_RDWR);
    if (fd < 0) fprintf(stderr, "open %s failed: %s\n", DNAND_DEVICE, strerror(errno));
    return fd;
}

/* 数値書き込み */
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

/* 文字列書き込み (ID 9, 12 など) */
static int dnand_write_string(int id, const char *str) {
    int fd = dnand_open();
    if (fd < 0) return -1;
    size_t len = strlen(str) + 1;
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

/* /misc パーティション書き込み (複数バリエーションを試す) */
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
    printf("[+] misc に '%s' 書き込み完了\n", data);
    return 0;
}

/* 現在の cmdline を表示 (デバッグ用) */
static void check_cmdline(void) {
    FILE *fp = fopen("/proc/cmdline", "r");
    if (!fp) return;
    char buf[1024];
    if (fgets(buf, sizeof(buf), fp)) {
        printf("[情報] 現在のカーネルコマンドライン:\n  %s\n", buf);
    }
    fclose(fp);
}

int main(void) {
    printf("=== 正しい ID マッピングに基づく Fastboot 移行 多角的総攻撃 ===\n\n");

    // 0. 現在のカーネルコマンドラインを表示
    check_cmdline();
    printf("\n");

    // 1. ID 9 (FACTORY_CMDLINE) に "androidboot.mode=fastboot" を追記 (最強)
    printf("[*] ID 9 (FACTORY_CMDLINE) に androidboot.mode=fastboot を設定...\n");
    dnand_write_string(ID_FACTORY_CMDLINE, "androidboot.mode=fastboot");

    // 2. ID 12 (REBOOT_PARM) に "bootloader" を設定 (真のトリガー)
    printf("[*] ID 12 (REBOOT_PARM) に 'bootloader' を設定...\n");
    dnand_write_string(ID_REBOOT_PARM, "bootloader");

    // 3. ID 29 (FASTBOOT_FLAG) を 1 に
    printf("[*] ID 29 (FASTBOOT_FLAG) を 1 に設定...\n");
    dnand_write_value(ID_FASTBOOT_FLAG, 1);

    // 4. ID 34 (OS_MODE) を 1 (Fastboot を示す可能性) に
    printf("[*] ID 34 (OS_MODE) を 1 に設定...\n");
    dnand_write_value(ID_OS_MODE, 1);

    // 5. ID 35 (RECOVERY_MODE) を 0 にクリア (念のため)
    printf("[*] ID 35 (RECOVERY_MODE) を 0 にクリア...\n");
    dnand_write_value(ID_RECOVERY_MODE, 0);

    // 6. ID 32 (RESCUE_ENABL_FLG) も 1 に (一部デバイスではこれが Fastboot と同義)
    printf("[*] ID 32 (RESCUE_ENABL_FLG) を 1 に設定...\n");
    dnand_write_value(ID_RESCUE_ENABL_FLG, 1);

    // 7. /misc パーティションに "bootloader" と "reboot-bootloader" を連続書き込み
    printf("[*] /misc パーティションに 'bootloader' を書き込み...\n");
    write_misc("bootloader");
    printf("[*] /misc パーティションに 'reboot-bootloader' を書き込み...\n");
    write_misc("reboot-bootloader");

    printf("\n[完了] 全経路への書き込みが完了しました。\n");
    printf("すぐに 'adb shell reboot' または 'reboot' で再起動してください。\n");
    printf("もし再起動後も通常起動する場合、以下のデバッグ情報を提供してください:\n");
    printf("  adb shell cat /proc/cmdline\n");
    printf("  adb shell getprop | grep -i fastboot\n");

    return 0;
}
