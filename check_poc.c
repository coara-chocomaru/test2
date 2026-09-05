/*
 * boot_flag_writer.c
 *
 * ユーザー空間から可能な限りの方法で apps_boot_info+0x08 に
 * 0x77665500 を書き込み、bootloader 再起動を試みる。
 *
 * コンパイル: aarch64-linux-android-gcc -static -O2 -o boot_flag_writer boot_flag_writer.c
 * 実行: su -c /data/local/tmp/boot_flag_writer
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/reboot.h>
#include <sys/syscall.h>
#include <linux/reboot.h>
#include <time.h>

#define TARGET_PADDR 0x8f69cf80UL
#define MAGIC_VALUE  0x77665500UL

static void msleep(int ms) {
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000 };
    nanosleep(&ts, NULL);
}

static int write_file(const char *path, const char *value) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -errno;
    ssize_t ret = write(fd, value, strlen(value));
    close(fd);
    return (ret == (ssize_t)strlen(value)) ? 0 : -EIO;
}

static int try_devmem(void) {
    int fd, ret = -1;
    void *map;
    uint32_t val = MAGIC_VALUE;
    uint32_t check;
    int i;

    printf("[*] Trying /dev/mem direct write...\n");
    fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (fd < 0) {
        printf("[-] open(/dev/mem) failed: %s\n", strerror(errno));
        return -errno;
    }

    map = mmap(NULL, 4, PROT_READ | PROT_WRITE, MAP_SHARED, fd, TARGET_PADDR);
    if (map == MAP_FAILED) {
        printf("[-] mmap failed: %s\n", strerror(errno));
        close(fd);
        return -errno;
    }

    printf("[+] Mapped 0x%lx to %p\n", TARGET_PADDR, map);

    // 現在の値を読み取り
    uint32_t old = *(volatile uint32_t *)map;
    printf("[*] Current value: 0x%08x\n", old);

    // 書き込み（リトライ）
    for (i = 0; i < 5; i++) {
        *(volatile uint32_t *)map = val;
        __sync_synchronize();
        msync(map, 4, MS_SYNC);
        check = *(volatile uint32_t *)map;
        if (check == val) {
            printf("[+] Write SUCCESS (attempt %d)\n", i+1);
            ret = 0;
            break;
        }
        printf("[*] Readback: 0x%08x (attempt %d)\n", check, i+1);
        msleep(100);
    }

    munmap(map, 4);
    close(fd);
    return ret;
}

static int try_devkmem(void) {
    int fd;
    void *map;
    uint32_t val = MAGIC_VALUE;
    uint32_t check;

    printf("[*] Trying /dev/kmem (if available)...\n");
    fd = open("/dev/kmem", O_RDWR | O_SYNC);
    if (fd < 0) {
        printf("[-] open(/dev/kmem) failed: %s\n", strerror(errno));
        return -errno;
    }

    // kmem では mmap できないことが多いので lseek/write を使う
    if (lseek(fd, TARGET_PADDR, SEEK_SET) == -1) {
        printf("[-] lseek failed: %s\n", strerror(errno));
        close(fd);
        return -errno;
    }
    if (write(fd, &val, sizeof(val)) != sizeof(val)) {
        printf("[-] write failed: %s\n", strerror(errno));
        close(fd);
        return -errno;
    }
    lseek(fd, TARGET_PADDR, SEEK_SET);
    if (read(fd, &check, sizeof(check)) != sizeof(check)) {
        printf("[-] readback failed: %s\n", strerror(errno));
        close(fd);
        return -errno;
    }
    close(fd);
    if (check == val) {
        printf("[+] /dev/kmem write SUCCESS!\n");
        return 0;
    } else {
        printf("[-] /dev/kmem write FAILED (readback: 0x%08x)\n", check);
        return -1;
    }
}

static int try_sysfs(void) {
    printf("[*] Trying /sys/class/reboot/mode ...\n");
    if (write_file("/sys/class/reboot/mode", "bootloader") == 0) {
        printf("[+] /sys/class/reboot/mode success.\n");
        return 0;
    }
    if (write_file("/sys/class/reboot/reboot_mode", "bootloader") == 0) {
        printf("[+] /sys/class/reboot/reboot_mode success.\n");
        return 0;
    }
    printf("[-] sysfs methods failed.\n");
    return -1;
}

static int try_setprop(void) {
    printf("[*] Trying setprop ...\n");
    int ret = system("setprop persist.sys.bootloader 1 2>/dev/null");
    if (ret == 0) {
        printf("[+] setprop success.\n");
        return 0;
    }
    ret = system("setprop sys.bootloader 1 2>/dev/null");
    if (ret == 0) {
        printf("[+] setprop (sys) success.\n");
        return 0;
    }
    printf("[-] setprop failed.\n");
    return -1;
}

static void do_reboot(void) {
    printf("\n[*] Rebooting to bootloader in 3 seconds...\n");
    sleep(3);
    sync();
    long ret = syscall(__NR_reboot,
                       LINUX_REBOOT_MAGIC1,
                       LINUX_REBOOT_MAGIC2,
                       LINUX_REBOOT_CMD_RESTART2,
                       "bootloader");
    if (ret != 0) {
        perror("reboot syscall");
        printf("[!] syscall failed, trying system() fallback...\n");
        system("reboot bootloader");
    }
}

int main(int argc, char **argv) {
    printf("=== Boot Flag Writer (User-space final attempt) ===\n");
    printf("Target: 0x%lx, Magic: 0x%08x\n", TARGET_PADDR, MAGIC_VALUE);
    printf("Note: This binary will try all possible methods.\n\n");

    int success = 0;
    int ret;

    // 1. /dev/mem
    ret = try_devmem();
    if (ret == 0) success = 1;

    // 2. /dev/kmem (fallback)
    if (!success) {
        ret = try_devkmem();
        if (ret == 0) success = 1;
    }

    // 3. sysfs
    if (!success) {
        ret = try_sysfs();
        if (ret == 0) success = 1;
    }

    // 4. setprop
    if (!success) {
        ret = try_setprop();
        if (ret == 0) success = 1;
    }

    if (success) {
        printf("\n[+] At least one method succeeded.\n");
        do_reboot();
    } else {
        printf("\n[!!!] ALL METHODS FAILED.\n");
        printf("[!!!] This device likely has CONFIG_STRICT_DEVMEM enabled.\n");
        printf("[!!!] User-space boot flag injection is IMPOSSIBLE.\n");
        printf("[!!!] You MUST use a kernel module (.ko) or EDL firmware reflash.\n");
        printf("[!!!] Exiting without reboot.\n");
        return EXIT_FAILURE;
    }

    return 0;
}
