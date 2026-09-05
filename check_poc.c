/*
 * write_boot_flag_sysfs.c
 * sysfs または setprop 経由で bootloader フラグを設定する
 *
 * 実行: /data/local/tmp/write_boot_flag_sysfs (root)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/reboot.h>
#include <sys/syscall.h>
#include <linux/reboot.h>

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

int main(int argc, char **argv) {
    int ret;

    printf("write_boot_flag_sysfs: Trying /sys/class/reboot/mode ...\n");
    ret = write_file("/sys/class/reboot/mode", "bootloader");
    if (ret == 0) {
        printf("write_boot_flag_sysfs: Successfully set reboot mode.\n");
        goto do_reboot;
    }

    printf("write_boot_flag_sysfs: Trying /sys/class/reboot/reboot_mode ...\n");
    ret = write_file("/sys/class/reboot/reboot_mode", "bootloader");
    if (ret == 0) {
        printf("write_boot_flag_sysfs: Successfully set reboot mode.\n");
        goto do_reboot;
    }

    // setprop 経由（init が読み取る）
    printf("write_boot_flag_sysfs: Trying setprop ...\n");
    ret = system("setprop persist.sys.bootloader 1");
    if (ret == 0) {
        printf("write_boot_flag_sysfs: setprop done. Rebooting...\n");
        goto do_reboot;
    }

    // 最後の手段: カーネルコマンドラインに追加（一部カーネルで有効）
    printf("write_boot_flag_sysfs: Trying /proc/cmdline override (not possible, skip)\n");

    fprintf(stderr, "write_boot_flag_sysfs: All methods failed.\n");
    exit(EXIT_FAILURE);

do_reboot:
    printf("write_boot_flag_sysfs: Rebooting to bootloader...\n");
    sync();
    syscall(__NR_reboot, LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2,
            LINUX_REBOOT_CMD_RESTART2, "bootloader");
    die("reboot syscall");
    return 0;
}
