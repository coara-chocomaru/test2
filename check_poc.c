/*
 * write_boot_flag.c
 * 物理メモリ（apps_boot_info + 0x08）に 0x77665500 を書き込み、
 * システムを bootloader モードで再起動する。
 *
 * コンパイル: aarch64-linux-android-gcc -static -O2 -o write_boot_flag write_boot_flag.c
 * 実行: /data/local/tmp/write_boot_flag (root必要)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/reboot.h>
#include <sys/syscall.h>
#include <linux/reboot.h>
#include <errno.h>
#include <string.h>

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

    // 8. システムを bootloader モードで再起動（syscall を使用）
    printf("write_boot_flag: Rebooting to bootloader...\n");
    sync();

    // カーネルシステムコール reboot(RESTART2) を直接呼び出す
    long ret = syscall(__NR_reboot,
                       LINUX_REBOOT_MAGIC1,
                       LINUX_REBOOT_MAGIC2,
                       LINUX_REBOOT_CMD_RESTART2,
                       "bootloader");
    if (ret != 0) {
        die("syscall(reboot)");
    }

    // ここには来ない
    return 0;
}
