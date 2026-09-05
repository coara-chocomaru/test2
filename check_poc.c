/*
 * write_boot_flag.c
 *
 * ユーザー空間から物理メモリ（apps_boot_info + 0x08）に
 * ブートローダーマジック（0x77665500）を直接書き込み、
 * reboot bootloader を実行する。
 *
 * コンパイル: 静的リンク推奨（-static）
 * 実行: /data/local/tmp/write_boot_flag
 *
 * このプログラムはパーティションを一切変更しません。
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/reboot.h>
#include <errno.h>
#include <string.h>
#include <linux/reboot.h>

#define TARGET_PADDR 0x8f69cf80UL   // apps_boot_info + 0x08
#define MAGIC_VALUE  0x77665500UL   // bootloader magic

static void die(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv) {
    int fd;
    void *map_base;
    uint32_t old_val, new_val;

    printf("write_boot_flag: Starting...\n");

    // 1. /dev/mem を開く
    fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (fd < 0) {
        die("open(/dev/mem)");
    }

    printf("write_boot_flag: /dev/mem opened successfully.\n");

    // 2. 物理アドレスをマッピング（4バイト）
    map_base = mmap(NULL, 4, PROT_READ | PROT_WRITE, MAP_SHARED, fd, TARGET_PADDR);
    if (map_base == MAP_FAILED) {
        close(fd);
        die("mmap");
    }

    printf("write_boot_flag: Mapped physical address 0x%lx to virtual %p\n",
           TARGET_PADDR, map_base);

    // 3. 現在の値を読み取り
    old_val = *(volatile uint32_t *)map_base;
    printf("write_boot_flag: Current value at 0x%lx = 0x%08x\n",
           TARGET_PADDR, old_val);

    // 4. マジックを書き込む
    new_val = MAGIC_VALUE;
    *(volatile uint32_t *)map_base = new_val;

    // 5. メモリバリア＆フラッシュ
    __sync_synchronize();   // GCC バリア
    msync(map_base, 4, MS_SYNC);

    // 6. 読み返して確認
    old_val = *(volatile uint32_t *)map_base;
    printf("write_boot_flag: Read-back value = 0x%08x\n", old_val);

    // 7. マッピング解除
    if (munmap(map_base, 4) != 0) {
        perror("munmap");
    }
    close(fd);

    if (old_val != new_val) {
        fprintf(stderr, "write_boot_flag: Write verification FAILED.\n");
        exit(EXIT_FAILURE);
    }

    printf("write_boot_flag: Successfully wrote 0x%08x.\n", new_val);

    // 8. すぐに再起動（bootloader）
    printf("write_boot_flag: Rebooting to bootloader...\n");
    sync();

    // reboot(RB_AUTOBOOT) では bootloader 引数が渡せないので syscall を使う
    // LINUX_REBOOT_MAGIC1=0xfee1dead, LINUX_REBOOT_MAGIC2=0x28121969
    if (reboot(LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2,
               LINUX_REBOOT_CMD_RESTART2, (void *)"bootloader") < 0) {
        die("reboot(RESTART2)");
    }

    // ここには来ない
    return 0;
}
