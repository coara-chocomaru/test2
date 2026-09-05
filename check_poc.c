/*
 * ultimate_boot_flag.c
 * 
 * ユーザー空間から可能な限りの全手段で bootloader フラグを設定しようとする。
 * 1. /dev/mem 直接書き込み（ほぼ失敗するが一応）
 * 2. /sys/class/reboot/mode
 * 3. setprop (system properties)
 * 
 * コンパイル: aarch64-linux-android-gcc -static -O2 -o ultimate_boot_flag ultimate_boot_flag.c
 * 実行: su -c /data/local/tmp/ultimate_boot_flag
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

#define TARGET_PADDR 0x8f69cf80UL

static void die(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

static int write_file(const char *path, const char *value) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    ssize_t ret = write(fd, value, strlen(value));
    close(fd);
    return (ret == (ssize_t)strlen(value)) ? 0 : -1;
}

static int try_devmem(void) {
    int fd;
    void *map;
    uint32_t val = 0x77665500;
    
    printf("[*] Trying /dev/mem direct write...\n");
    fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (fd < 0) {
        printf("[-] /dev/mem open failed: %s\n", strerror(errno));
        return -1;
    }
    
    map = mmap(NULL, 4, PROT_READ | PROT_WRITE, MAP_SHARED, fd, TARGET_PADDR);
    if (map == MAP_FAILED) {
        printf("[-] mmap failed: %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    
    printf("[*] Writing 0x77665500 to 0x%lx...\n", TARGET_PADDR);
    *(volatile uint32_t *)map = val;
    __sync_synchronize();
    msync(map, 4, MS_SYNC);
    
    uint32_t check = *(volatile uint32_t *)map;
    munmap(map, 4);
    close(fd);
    
    if (check == val) {
        printf("[+] /dev/mem write SUCCESS!\n");
        return 0;
    } else {
        printf("[-] /dev/mem write FAILED (readback: 0x%08x)\n", check);
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
    printf("[*] Rebooting to bootloader via syscall...\n");
    sync();
    long ret = syscall(__NR_reboot,
                       LINUX_REBOOT_MAGIC1,
                       LINUX_REBOOT_MAGIC2,
                       LINUX_REBOOT_CMD_RESTART2,
                       "bootloader");
    if (ret != 0) {
        die("reboot syscall");
    }
}

int main(int argc, char **argv) {
    printf("=== Ultimate Boot Flag Setter ===\n");
    printf("Target address: 0x%lx\n", TARGET_PADDR);
    printf("This binary tries ALL possible user-space methods.\n\n");
    
    int success = 0;
    
    // 1. devmem
    if (try_devmem() == 0) success = 1;
    
    // 2. sysfs
    if (try_sysfs() == 0) success = 1;
    
    // 3. setprop
    if (try_setprop() == 0) success = 1;
    
    if (success) {
        printf("\n[+] At least one method succeeded. Rebooting...\n");
        do_reboot();
    } else {
        printf("\n[!!!] ALL METHODS FAILED.\n");
        printf("[!!!] This device has CONFIG_STRICT_DEVMEM enabled and lacks /sys/class/reboot/mode.\n");
        printf("[!!!] User-space boot flag injection is IMPOSSIBLE on this device.\n");
        printf("[!!!] You MUST use a kernel module (.ko) or EDL firmware reflash.\n");
        return EXIT_FAILURE;
    }
    
    return 0;
}
