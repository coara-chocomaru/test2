/*
 * bruteforce_writer.c
 *
 * ユーザー空間から apps_boot_info 周辺の物理メモリに対して
 * 0x77665500 などのマジックナンバーを総当たりで書き込み、
 * どのアドレス・値が正しいかを特定する。
 *
 * 再起動は行わない（手動で確認するため）
 *
 * コンパイル: aarch64-linux-android-gcc -static -O2 -o bruteforce_writer bruteforce_writer.c
 * 実行: su -c /data/local/tmp/bruteforce_writer
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
#include <sys/stat.h>
#include <dirent.h>

// ターゲットアドレス範囲（中心 0x8f69cf78）
#define BASE_ADDR 0x8f69cf78UL
#define RANGE     0x30      // ±0x30 バイトをスキャン
#define STEP      4         // 4バイト刻み

// 試すマジックナンバー（aboot が認識する可能性のある値）
static const uint32_t magic_values[] = {
    0x77665500,  // bootloader
    0x77665501,  // normal (無視されるかもしれないが念のため)
    0x77665502,  // recovery
    0x77665503,  // rtc
    0x77665508,  // dm-verity corrupted
    0x77665509,  // dm-verity enforcing
    0x7766550a,  // keys clear
    0x6f656d00,  // oem-? (一部)
};
#define NUM_MAGIC (sizeof(magic_values) / sizeof(magic_values[0]))

static int write_mem_direct(off_t paddr, uint32_t value, uint32_t *readback) {
    int fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (fd < 0) {
        // /dev/mem が開けない場合は /dev/kmem を試す
        fd = open("/dev/kmem", O_RDWR | O_SYNC);
        if (fd < 0) return -errno;
        // kmem では lseek/write を使う
        if (lseek(fd, paddr, SEEK_SET) == (off_t)-1) {
            close(fd);
            return -errno;
        }
        if (write(fd, &value, sizeof(value)) != sizeof(value)) {
            close(fd);
            return -errno;
        }
        if (lseek(fd, paddr, SEEK_SET) == (off_t)-1) {
            close(fd);
            return -errno;
        }
        if (read(fd, readback, sizeof(*readback)) != sizeof(*readback)) {
            close(fd);
            return -errno;
        }
        close(fd);
        return 0;
    }

    // /dev/mem 経由の mmap
    void *map = mmap(NULL, 4, PROT_READ | PROT_WRITE, MAP_SHARED, fd, paddr);
    if (map == MAP_FAILED) {
        close(fd);
        return -errno;
    }

    *readback = *(volatile uint32_t *)map;
    *(volatile uint32_t *)map = value;
    __sync_synchronize();
    msync(map, 4, MS_SYNC);
    *readback = *(volatile uint32_t *)map;

    munmap(map, 4);
    close(fd);
    return 0;
}

static int try_sysfs_qpnp_pon(void) {
    // /sys/class/qpnp-pon/ 以下に reboot_reason ファイルがあれば書き込む
    DIR *dir = opendir("/sys/class/qpnp-pon");
    if (!dir) return -1;
    struct dirent *entry;
    int ret = -1;
    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, "qpnp-pon-", 9) == 0) {
            char path[256];
            snprintf(path, sizeof(path), "/sys/class/qpnp-pon/%s/reboot_reason", entry->d_name);
            int fd = open(path, O_WRONLY);
            if (fd >= 0) {
                const char *val = "0x77665500";
                if (write(fd, val, strlen(val)) == (ssize_t)strlen(val)) {
                    printf("[+] Wrote to %s\n", path);
                    ret = 0;
                }
                close(fd);
            }
        }
    }
    closedir(dir);
    return ret;
}

static int try_debugfs_smem(void) {
    // /sys/kernel/debug/msm_smem があれば読み書きを試す（稀）
    int fd = open("/sys/kernel/debug/msm_smem", O_RDWR);
    if (fd < 0) return -1;
    // ここでは単にファイルが存在するかだけ確認
    close(fd);
    return 0; // 本当はパースして apps_boot_info を探すが、複雑なのでパス
}

int main(int argc, char **argv) {
    printf("=== Boot Flag Bruteforce Writer ===\n");
    printf("Scanning address range 0x%lx - 0x%lx\n", BASE_ADDR - RANGE, BASE_ADDR + RANGE);
    printf("Trying %d magic values.\n\n", NUM_MAGIC);

    int found = 0;
    uint32_t readback;

    // アドレス総当たり
    for (off_t addr = BASE_ADDR - RANGE; addr <= BASE_ADDR + RANGE; addr += STEP) {
        for (int mi = 0; mi < NUM_MAGIC; mi++) {
            uint32_t magic = magic_values[mi];
            int ret = write_mem_direct(addr, magic, &readback);
            if (ret == 0) {
                if (readback == magic) {
                    printf("[SUCCESS] Address 0x%lx: wrote 0x%08x, readback matches.\n", addr, magic);
                    found++;
                } else {
                    printf("[INFO] Address 0x%lx: wrote 0x%08x, readback 0x%08x (mismatch)\n", addr, magic, readback);
                }
            } else {
                // エラーの場合はアドレスごとに一度だけ表示
                static off_t last_error_addr = 0;
                if (addr != last_error_addr) {
                    printf("[ERROR] Cannot access 0x%lx: %s\n", addr, strerror(-ret));
                    last_error_addr = addr;
                }
                break; // このアドレスはアクセスできないので次のアドレスへ
            }
        }
    }

    // 追加の sysfs 試行
    printf("\n[*] Trying /sys/class/qpnp-pon/reboot_reason ...\n");
    if (try_sysfs_qpnp_pon() == 0) {
        printf("[+] qpnp-pon write succeeded.\n");
        found++;
    } else {
        printf("[-] qpnp-pon write failed or not available.\n");
    }

    printf("\n[*] Trying /sys/kernel/debug/msm_smem (check only) ...\n");
    if (try_debugfs_smem() == 0) {
        printf("[+] debugfs msm_smem exists (may contain SMEM data).\n");
        printf("[*] You can manually examine it with 'cat /sys/kernel/debug/msm_smem'\n");
    } else {
        printf("[-] debugfs msm_smem not available.\n");
    }

    if (found > 0) {
        printf("\n[RESULT] At least one successful write occurred.\n");
        printf("[*] Now try to reboot to bootloader manually:\n");
        printf("    adb shell su -c 'reboot bootloader'\n");
        printf("[*] If it works, the correct address/value is among the successes above.\n");
    } else {
        printf("\n[RESULT] No successful write detected.\n");
        printf("[*] This means:\n");
        printf("  1. /dev/mem and /dev/kmem are blocked (CONFIG_STRICT_DEVMEM).\n");
        printf("  2. The target physical address range is not mappable.\n");
        printf("  3. The device does not have any sysfs interface for reboot reason.\n");
        printf("\n[CONCLUSION] User-space injection is IMPOSSIBLE on this device.\n");
        printf("You must use a kernel module (.ko) or reflash firmware via EDL.\n");
    }

    return 0;
}
