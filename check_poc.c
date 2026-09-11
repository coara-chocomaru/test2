
/*
 * fastboot_trigger.c  (v6 - inline asm + IMEM direct)
 * =====================================================================
 * Kyocera 端末を fastboot mode へ確実に移行させる最終 PoC
 *
 * 3 つの独立した経路を試行:
 *   (A) inline asm で raw syscall(SYS_reboot, ..., RESTART2, "bootloader")
 *   (B) /dev/mem で IMEM restart_reason に直接 0x77665500 を書いてから
 *       通常 reboot()
 *   (C) 診断のみ (現状把握、書き込みなし)
 *
 * 根拠 (msm-poweroff.c):
 *   msm_restart_prepare("bootloader")
 *     → qpnp_pon_set_restart_reason(PON_RESTART_REASON_BOOTLOADER)
 *     → __raw_writel(0x77665500, restart_reason)   ★ ここが肝
 *
 *   restart_reason は device tree ノード
 *   "qcom,msm-imem-restart_reason" から of_iomap で取得される
 *
 * ビルド (NDK r10e / arm64):
 *   aarch64-linux-android-gcc -O2 -static -no-pie \
 *       -o fastboot_trigger fastboot_trigger.c
 *
 * ビルド (glibc cross):
 *   aarch64-linux-gnu-gcc -O2 -static -no-pie \
 *       -o fastboot_trigger fastboot_trigger.c
 * =====================================================================
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/reboot.h>
#include <linux/reboot.h>

#ifndef __NR_reboot
#define __NR_reboot 142
#endif

#define MAGIC_FASTBOOT  0x77665500u
#define MAGIC_RECOVERY  0x77665502u
#define MAGIC_RTC       0x77665503u
#define MAGIC_NORMAL    0x77665501u

/* ------------------------------------------------------------------ *
 *  (A) inline asm で生 syscall を発行
 *      libc の syscall() を経由しない → int 昇格問題を回避
 * ------------------------------------------------------------------ */
static long raw_syscall4(long nr, long a0, long a1, long a2, long a3)
{
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a0;
    register long x1 __asm__("x1") = a1;
    register long x2 __asm__("x2") = a2;
    register long x3 __asm__("x3") = a3;
    __asm__ volatile("svc 0"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3)
                     : "memory");
    return x0;
}

static int issue_reboot_restart2(const char *reason)
{
    printf("[A] inline asm: svc 0 with syscall %d\n", __NR_reboot);
    printf("    x0 = 0x%08llx  (LINUX_REBOOT_MAGIC1)\n",
           (unsigned long long)LINUX_REBOOT_MAGIC1);
    printf("    x1 = 0x%08llx  (LINUX_REBOOT_MAGIC2)\n",
           (unsigned long long)LINUX_REBOOT_MAGIC2);
    printf("    x2 = 0x%08llx  (LINUX_REBOOT_CMD_RESTART2)\n",
           (unsigned long long)LINUX_REBOOT_CMD_RESTART2);
    printf("    x3 = %p  (\"%s\")\n", (void *)reason, reason);
    fflush(stdout);

    long r = raw_syscall4(__NR_reboot,
                          (long)LINUX_REBOOT_MAGIC1,
                          (long)LINUX_REBOOT_MAGIC2,
                          (long)LINUX_REBOOT_CMD_RESTART2,
                          (long)(intptr_t)reason);
    /* 到達しないはず */
    fprintf(stderr, "[-] syscall returned %ld (errno=%d: %s)\n",
            r, errno, strerror(errno));
    return (int)r;
}

/* ------------------------------------------------------------------ *
 *  (B) device tree から restart_reason 物理アドレスを取得
 * ------------------------------------------------------------------ */
static int dt_get_reg(const char *path, uint32_t *out_base, uint32_t *out_size)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;

    uint8_t buf[32] = {0};
    size_t n = fread(buf, 1, sizeof(buf), fp);
    fclose(fp);

    if (n >= 16) {
        /* 64bit base + 64bit size (big-endian) */
        *out_base = ((uint32_t)buf[4] << 24) |
                    ((uint32_t)buf[5] << 16) |
                    ((uint32_t)buf[6] << 8)  |
                    ((uint32_t)buf[7]);
        *out_size = ((uint32_t)buf[12] << 24) |
                    ((uint32_t)buf[13] << 16) |
                    ((uint32_t)buf[14] << 8)  |
                    ((uint32_t)buf[15]);
        return 0;
    }
    if (n >= 8) {
        /* 32bit base + 32bit size */
        *out_base = ((uint32_t)buf[0] << 24) |
                    ((uint32_t)buf[1] << 16) |
                    ((uint32_t)buf[2] << 8)  |
                    ((uint32_t)buf[3]);
        *out_size = ((uint32_t)buf[4] << 24) |
                    ((uint32_t)buf[5] << 16) |
                    ((uint32_t)buf[6] << 8)  |
                    ((uint32_t)buf[7]);
        return 0;
    }
    return -1;
}

static uint32_t find_restart_reason_addr(void)
{
    const char *paths[] = {
        "/proc/device-tree/qcom,msm-imem-restart_reason/reg",
        "/sys/firmware/devicetree/base/qcom,msm-imem-restart_reason/reg",
        NULL
    };
    uint32_t base = 0, size = 0;
    for (int i = 0; paths[i]; i++) {
        if (dt_get_reg(paths[i], &base, &size) == 0) {
            printf("[B] DT node: %s\n", paths[i]);
            printf("    phys base = 0x%08x  size = 0x%x\n", base, size);
            return base;
        }
    }
    return 0;
}

static void dump_soc_info(void)
{
    FILE *fp = fopen("/proc/device-tree/model", "r");
    if (fp) {
        char model[256] = {0};
        size_t n = fread(model, 1, sizeof(model) - 1, fp);
        fclose(fp);
        if (n > 0) printf("[i] model: %s\n", model);
    }

    const char *nodes[] = {
        "/proc/device-tree/qcom,msm-imem-download_mode",
        "/proc/device-tree/qcom,msm-imem-emergency_download_mode",
        NULL
    };
    for (int i = 0; nodes[i]; i++) {
        uint32_t b = 0, s = 0;
        char path[256];
        snprintf(path, sizeof(path), "%s/reg", nodes[i]);
        if (dt_get_reg(path, &b, &s) == 0)
            printf("[i] %s: 0x%08x size 0x%x\n", nodes[i], b, s);
    }
}

/* ------------------------------------------------------------------ *
 *  (B) /dev/mem 経由で IMEM に直接書き込み
 * ------------------------------------------------------------------ */
static int imem_write_verify(uint32_t phys, uint32_t magic, uint32_t *old_out)
{
    int fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (fd < 0) {
        fprintf(stderr, "[-] open(/dev/mem): %s\n", strerror(errno));
        return -1;
    }
    long pg = sysconf(_SC_PAGESIZE);
    uint32_t aligned = phys & ~(uint32_t)(pg - 1);
    uint32_t delta   = phys - aligned;

    void *m = mmap(NULL, pg, PROT_READ | PROT_WRITE,
                   MAP_SHARED, fd, aligned);
    if (m == MAP_FAILED) {
        fprintf(stderr, "[-] mmap(0x%08x): %s\n", aligned, strerror(errno));
        close(fd);
        return -1;
    }
    volatile uint32_t *p = (volatile uint32_t *)((uint8_t *)m + delta);

    uint32_t old = *p;
    if (old_out) *old_out = old;
    printf("[B] IMEM @ 0x%08x : old = 0x%08x\n", phys, old);

    *p = magic;
    __sync_synchronize();
    usleep(1000);

    uint32_t nv = *p;
    printf("[B] IMEM @ 0x%08x : new = 0x%08x  %s\n",
           phys, nv, (nv == magic) ? "(verified)" : "(MISMATCH!)");

    munmap(m, pg);
    close(fd);
    return (nv == magic) ? 0 : -1;
}

/* ------------------------------------------------------------------ *
 *  診断モード
 * ------------------------------------------------------------------ */
static int cmd_diag(void)
{
    printf("=====================================================\n");
    printf(" Diagnostic mode (no writes, no reboot)\n");
    printf("=====================================================\n\n");

    dump_soc_info();

    uint32_t addr = find_restart_reason_addr();
    if (!addr) {
        fprintf(stderr, "[-] restart_reason DT node not found\n");
        return 1;
    }
    printf("\n[*] restart_reason phys = 0x%08x\n", addr);

    /* 現状値を読む */
    int fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (fd < 0) {
        fprintf(stderr, "[-] open(/dev/mem): %s\n", strerror(errno));
        return 1;
    }
    long pg = sysconf(_SC_PAGESIZE);
    uint32_t aligned = addr & ~(uint32_t)(pg - 1);
    uint32_t delta   = addr - aligned;
    void *m = mmap(NULL, pg, PROT_READ | PROT_WRITE,
                   MAP_SHARED, fd, aligned);
    if (m == MAP_FAILED) {
        fprintf(stderr, "[-] mmap: %s\n", strerror(errno));
        close(fd);
        return 1;
    }
    volatile uint32_t *p = (volatile uint32_t *)((uint8_t *)m + delta);

    printf("\n[*] IMEM region dump (page 0x%08x):\n", aligned);
    for (uint32_t off = 0; off < 0x100; off += 16) {
        printf("  +%04x:", off);
        for (int k = 0; k < 16; k++)
            printf(" %02x",
                   ((volatile uint8_t *)m)[off + k]);
        printf("\n");
    }

    printf("\n[*] current restart_reason value = 0x%08x\n", *p);
    if (*p == MAGIC_FASTBOOT)      printf("    (currently FASTBOOT magic)\n");
    else if (*p == MAGIC_RECOVERY) printf("    (currently RECOVERY magic)\n");
    else if (*p == MAGIC_RTC)      printf("    (currently RTC magic)\n");
    else if (*p == MAGIC_NORMAL)   printf("    (currently NORMAL reboot magic)\n");
    else if (*p == 0)              printf("    (zero)\n");

    munmap(m, pg);
    close(fd);
    return 0;
}

/* ------------------------------------------------------------------ *
 *  (B) IMEM 直接書き込み → 通常 reboot
 * ------------------------------------------------------------------ */
static int cmd_imem(uint32_t magic, int do_reboot)
{
    printf("=====================================================\n");
    printf(" Path B: IMEM direct write + reboot\n");
    printf("=====================================================\n\n");

    dump_soc_info();

    uint32_t addr = find_restart_reason_addr();
    if (!addr) {
        fprintf(stderr, "[-] cannot find restart_reason phys addr\n");
        return 1;
    }

    uint32_t old = 0;
    if (imem_write_verify(addr, magic, &old) < 0) {
        fprintf(stderr, "[-] IMEM write/verify failed\n");
        return 1;
    }

    if (do_reboot) {
        printf("\n[B] sync + regular reboot() (IMEM already set)\n");
        fflush(stdout);
        sync();
        /* 通常 reboot で OK: IMEM にマジックが既に入っている */
        reboot(RB_AUTOBOOT);
        perror("[-] reboot");
        return 1;
    }
    printf("\n[B] --no-reboot: IMEM write only, not rebooting\n");
    return 0;
}

/* ------------------------------------------------------------------ *
 *  usage
 * ------------------------------------------------------------------ */
static void usage(const char *p)
{
    fprintf(stderr,
        "Usage:\n"
        "  %s --diag                # 現状ダンプ (書き込みなし)\n"
        "  %s --syscall [reason]    # Path A: inline asm syscall(RESTART2, reason)\n"
        "  %s --imem [magic]        # Path B: IMEM 直接書き込み + reboot\n"
        "  %s --imem-noreboot [magic]\n"
        "  %s [reason]              # デフォルト: A → 失敗なら B\n"
        "\n"
        "reason:  bootloader (default) | recovery | rtc | edl | oem-XXXX\n"
        "magic:   0x77665500 (default) | 0x77665502 | 0x77665503 | 0x77665501\n",
        p, p, p, p, p);
}

/* ------------------------------------------------------------------ */
int main(int argc, char **argv)
{
    printf("=====================================================\n");
    printf(" Kyocera fastboot trigger (v6)\n");
    printf(" uid=%d euid=%d\n", getuid(), geteuid());
    printf("=====================================================\n\n");

    if (argc < 2) {
        /* デフォルト: A を試す → 失敗なら B */
        printf("[*] default mode: try A (syscall) then B (IMEM)\n\n");
        fflush(stdout);
        issue_reboot_restart2("bootloader");
        /* syscall が戻った = 失敗 */
        fprintf(stderr, "[-] Path A returned. Trying Path B...\n");
        return cmd_imem(MAGIC_FASTBOOT, 1);
    }

    if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
        usage(argv[0]);
        return 0;
    }

    if (!strcmp(argv[1], "--diag"))
        return cmd_diag();

    if (!strcmp(argv[1], "--syscall")) {
        const char *reason = (argc > 2) ? argv[2] : "bootloader";
        printf("[*] Path A: reason = \"%s\"\n\n", reason);
        fflush(stdout);
        return issue_reboot_restart2(reason);
    }

    if (!strcmp(argv[1], "--imem")) {
        uint32_t magic = MAGIC_FASTBOOT;
        if (argc > 2) magic = (uint32_t)strtoul(argv[2], NULL, 0);
        return cmd_imem(magic, 1);
    }

    if (!strcmp(argv[1], "--imem-noreboot")) {
        uint32_t magic = MAGIC_FASTBOOT;
        if (argc > 2) magic = (uint32_t)strtoul(argv[2], NULL, 0);
        return cmd_imem(magic, 0);
    }

    /* 位置引数 = reason 文字列 → Path A */
    printf("[*] Path A: reason = \"%s\"\n\n", argv[1]);
    fflush(stdout);
    return issue_reboot_restart2(argv[1]);
}
