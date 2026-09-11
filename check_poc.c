/*
 * check_poc.c  (v7 - C89 compatible, NDK r10e ready)
 * =====================================================================
 * Kyocera 端末を fastboot mode へ移行させる統合 PoC
 *
 * 4 つのモード:
 *   --diag               現在の SMEM/IMEM 状態をダンプ (書き込みなし)
 *   --syscall [reason]   Path A: inline asm syscall(RESTART2, reason)
 *   --imem [magic]       Path B: IMEM restart_reason に直接書き込み + reboot
 *   --bruteforce         全 IMEM 候補アドレスを試行
 *
 * 根拠 (msm-poweroff.c):
 *   msm_restart_prepare("bootloader")
 *     → __raw_writel(0x77665500, restart_reason)   ★ この値が IMEM に書かれる
 *   restart_reason は device tree ノード
 *   "qcom,msm-imem-restart_reason" から of_iomap で取得
 *
 * ビルド (NDK r10e / arm64):
 *   aarch64-linux-android-gcc -O2 -static -fPIE -pie \
 *       -o check_poc check_poc.c
 *   (C89 モードでもビルド可)
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

/* ==================================================================== *
 *  inline asm による生 syscall (C89 互換)
 * ==================================================================== */
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
    long r;

    printf("[A] inline asm: svc 0 with syscall %d\n", __NR_reboot);
    printf("    x0 = 0x%08lx  (LINUX_REBOOT_MAGIC1)\n",
           (unsigned long)LINUX_REBOOT_MAGIC1);
    printf("    x1 = 0x%08lx  (LINUX_REBOOT_MAGIC2)\n",
           (unsigned long)LINUX_REBOOT_MAGIC2);
    printf("    x2 = 0x%08lx  (LINUX_REBOOT_CMD_RESTART2)\n",
           (unsigned long)LINUX_REBOOT_CMD_RESTART2);
    printf("    x3 = %p  (\"%s\")\n", (void *)reason, reason);
    fflush(stdout);

    r = raw_syscall4((long)__NR_reboot,
                     (long)LINUX_REBOOT_MAGIC1,
                     (long)LINUX_REBOOT_MAGIC2,
                     (long)LINUX_REBOOT_CMD_RESTART2,
                     (long)(intptr_t)reason);

    fprintf(stderr, "[-] syscall returned %ld (errno=%d: %s)\n",
            r, errno, strerror(errno));
    return (int)r;
}

/* ==================================================================== *
 *  device tree から 物理アドレス取得 (C89 互換)
 * ==================================================================== */
static int dt_get_reg(const char *path, uint32_t *out_base, uint32_t *out_size)
{
    FILE *fp;
    uint8_t buf[32];
    size_t n;

    memset(buf, 0, sizeof(buf));

    fp = fopen(path, "rb");
    if (!fp) return -1;

    n = fread(buf, 1, sizeof(buf), fp);
    fclose(fp);

    if (n >= 16) {
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
    const char *paths[3];
    uint32_t base = 0;
    uint32_t size = 0;
    int i;

    paths[0] = "/proc/device-tree/qcom,msm-imem-restart_reason/reg";
    paths[1] = "/sys/firmware/devicetree/base/qcom,msm-imem-restart_reason/reg";
    paths[2] = NULL;

    for (i = 0; paths[i]; i++) {
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
    FILE *fp;
    char model[256];
    size_t n;
    const char *nodes[3];
    int i;

    memset(model, 0, sizeof(model));
    fp = fopen("/proc/device-tree/model", "r");
    if (fp) {
        n = fread(model, 1, sizeof(model) - 1, fp);
        fclose(fp);
        if (n > 0) printf("[i] model: %s\n", model);
    }

    nodes[0] = "/proc/device-tree/qcom,msm-imem-download_mode";
    nodes[1] = "/proc/device-tree/qcom,msm-imem-emergency_download_mode";
    nodes[2] = NULL;

    for (i = 0; nodes[i]; i++) {
        char path[256];
        uint32_t b = 0;
        uint32_t s = 0;
        snprintf(path, sizeof(path), "%s/reg", nodes[i]);
        if (dt_get_reg(path, &b, &s) == 0)
            printf("[i] %s: 0x%08x size 0x%x\n", nodes[i], b, s);
    }
}

/* ==================================================================== *
 *  /dev/mem 経由の読み書き
 * ==================================================================== */
static int mem_read32(uint32_t phys, uint32_t *out)
{
    int fd;
    long pg;
    uint32_t aligned, delta;
    void *m;
    volatile uint32_t *p;

    fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (fd < 0) return -1;

    pg = sysconf(_SC_PAGESIZE);
    aligned = phys & ~(uint32_t)(pg - 1);
    delta = phys - aligned;

    m = mmap(NULL, (size_t)pg, PROT_READ | PROT_WRITE,
             MAP_SHARED, fd, aligned);
    if (m == MAP_FAILED) {
        close(fd);
        return -1;
    }
    p = (volatile uint32_t *)((uint8_t *)m + delta);
    *out = *p;
    munmap(m, (size_t)pg);
    close(fd);
    return 0;
}

static int mem_write32_verify(uint32_t phys, uint32_t val, uint32_t *old_out)
{
    int fd;
    long pg;
    uint32_t aligned, delta;
    void *m;
    volatile uint32_t *p;
    uint32_t old, nv;

    fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (fd < 0) return -1;

    pg = sysconf(_SC_PAGESIZE);
    aligned = phys & ~(uint32_t)(pg - 1);
    delta = phys - aligned;

    m = mmap(NULL, (size_t)pg, PROT_READ | PROT_WRITE,
             MAP_SHARED, fd, aligned);
    if (m == MAP_FAILED) {
        close(fd);
        return -1;
    }
    p = (volatile uint32_t *)((uint8_t *)m + delta);

    old = *p;
    if (old_out) *old_out = old;

    *p = val;
    __sync_synchronize();
    usleep(1000);
    nv = *p;

    munmap(m, (size_t)pg);
    close(fd);

    return (nv == val) ? 0 : -1;
}

/* ==================================================================== *
 *  診断モード
 * ==================================================================== */
static int cmd_diag(void)
{
    uint32_t addr;
    int fd;
    long pg;
    uint32_t aligned, delta;
    void *m;
    uint32_t off;
    int k;

    printf("=====================================================\n");
    printf(" Diagnostic mode (no writes, no reboot)\n");
    printf("=====================================================\n\n");

    dump_soc_info();

    addr = find_restart_reason_addr();
    if (!addr) {
        fprintf(stderr, "[-] restart_reason DT node not found\n");
        return 1;
    }
    printf("\n[*] restart_reason phys = 0x%08x\n", addr);

    fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (fd < 0) {
        fprintf(stderr, "[-] open(/dev/mem): %s\n", strerror(errno));
        return 1;
    }

    pg = sysconf(_SC_PAGESIZE);
    aligned = addr & ~(uint32_t)(pg - 1);
    delta = addr - aligned;

    m = mmap(NULL, (size_t)pg, PROT_READ | PROT_WRITE,
             MAP_SHARED, fd, aligned);
    if (m == MAP_FAILED) {
        fprintf(stderr, "[-] mmap: %s\n", strerror(errno));
        close(fd);
        return 1;
    }

    printf("\n[*] IMEM page dump (0x%08x):\n", aligned);
    for (off = 0; off < 0x100; off += 16) {
        printf("  +%04x:", off);
        for (k = 0; k < 16; k++)
            printf(" %02x", ((volatile uint8_t *)m)[off + k]);
        printf("\n");
    }

    {
        volatile uint32_t *p = (volatile uint32_t *)((uint8_t *)m + delta);
        printf("\n[*] current restart_reason = 0x%08x", *p);
        if (*p == MAGIC_FASTBOOT)      printf("  (FASTBOOT magic)\n");
        else if (*p == MAGIC_RECOVERY) printf("  (RECOVERY magic)\n");
        else if (*p == MAGIC_RTC)      printf("  (RTC magic)\n");
        else if (*p == MAGIC_NORMAL)   printf("  (NORMAL magic)\n");
        else if (*p == 0)              printf("  (zero)\n");
        else                           printf("  (unknown)\n");
    }

    munmap(m, (size_t)pg);
    close(fd);
    return 0;
}

/* ==================================================================== *
 *  Path B: IMEM 直接書き込み + reboot
 * ==================================================================== */
static int cmd_imem(uint32_t magic, int do_reboot)
{
    uint32_t addr;
    uint32_t old = 0;

    printf("=====================================================\n");
    printf(" Path B: IMEM direct write + reboot\n");
    printf("=====================================================\n\n");

    dump_soc_info();

    addr = find_restart_reason_addr();
    if (!addr) {
        fprintf(stderr, "[-] cannot find restart_reason phys addr\n");
        return 1;
    }

    printf("\n[B] writing 0x%08x to phys 0x%08x ...\n", magic, addr);
    if (mem_write32_verify(addr, magic, &old) < 0) {
        fprintf(stderr, "[-] write/verify failed (old=0x%08x)\n", old);
        return 1;
    }
    printf("[B] OK (old = 0x%08x)\n", old);

    if (do_reboot) {
        printf("\n[B] sync + reboot() ...\n");
        fflush(stdout);
        sync();
        reboot(RB_AUTOBOOT);
        perror("[-] reboot");
        return 1;
    }
    printf("\n[B] --no-reboot: IMEM written, not rebooting\n");
    return 0;
}

/* ==================================================================== *
 *  Bruteforce: 候補アドレスを総当たり
 * ==================================================================== */
static const uint32_t brute_candidates[] = {
    0x0FE0065C,  /* MSM8974/8994/8992/8084 */
    0x0860065C,  /* MSM8916/8909/8939/8952/8953/8996 */
    0x0FE00658, 0x0FE00660, 0x0FE00664,
    0x08600658, 0x08600660, 0x08600664,
    0x0FC4280, 0x0FC4284, 0x0FC4288,
    0x0FE00000, 0x08600000
};

static int cmd_bruteforce(int do_reboot)
{
    size_t n;
    size_t i;
    int hits = 0;
    uint32_t old = 0;

    printf("=====================================================\n");
    printf(" IMEM restart_reason bruteforce (magic 0x%08x)\n",
           MAGIC_FASTBOOT);
    printf("=====================================================\n\n");

    n = sizeof(brute_candidates) / sizeof(brute_candidates[0]);

    for (i = 0; i < n; i++) {
        uint32_t addr = brute_candidates[i];
        uint32_t rd = 0;

        printf("[%2u] 0x%08x : ", (unsigned)i, addr);

        if (mem_read32(addr, &rd) < 0) {
            printf("mmap failed\n");
            continue;
        }
        printf("old=0x%08x ", rd);

        /* 既に magic か 0 の場所のみ書き込み (他は破壊回避) */
        if (rd != 0 && rd != MAGIC_FASTBOOT && rd != MAGIC_NORMAL) {
            printf("SKIP\n");
            continue;
        }

        if (mem_write32_verify(addr, MAGIC_FASTBOOT, &old) == 0) {
            printf("OK\n");
            hits++;
        } else {
            printf("FAIL\n");
        }
    }

    printf("\n[*] %d / %u candidates accepted the magic\n",
           hits, (unsigned)n);

    if (hits == 0) {
        fprintf(stderr,
                "[-] no candidate worked.\n"
                "    check DT node manually:\n"
                "      xxd /proc/device-tree/qcom,msm-imem-"
                "restart_reason/reg\n");
        return 1;
    }

    if (do_reboot) {
        printf("\n[*] sync + reboot ...\n");
        fflush(stdout);
        sync();
        reboot(RB_AUTOBOOT);
    } else {
        printf("\n[--no-reboot] run 'adb reboot' manually\n");
    }
    return 0;
}

/* ==================================================================== *
 *  usage / main (C89 互換)
 * ==================================================================== */
static void usage(const char *p)
{
    fprintf(stderr,
        "Usage: %s <mode> [args]\n"
        "\n"
        "Modes:\n"
        "  --diag                    現状ダンプ (書き込みなし、超安全)\n"
        "  --syscall [reason]        Path A: inline asm syscall(RESTART2, reason)\n"
        "  --imem [magic]            Path B: IMEM 直接書き込み + reboot\n"
        "  --imem-noreboot [magic]   Path B: IMEM 書き込みのみ\n"
        "  --bruteforce              全 IMEM 候補を総当たり + reboot\n"
        "  --bruteforce-noreboot     総当たり (書き込みのみ)\n"
        "\n"
        "reason: bootloader (default) | recovery | rtc | edl | oem-XXXX\n"
        "magic:  0x77665500 (default) | 0x77665502 | 0x77665503 | 0x77665501\n"
        "\n"
        "Examples:\n"
        "  %s --diag\n"
        "  %s --syscall bootloader\n"
        "  %s --imem\n"
        "  %s --imem-noreboot 0x77665500\n"
        "  %s --bruteforce\n",
        p, p, p, p, p, p);
}

int main(int argc, char **argv)
{
    int argi;

    printf("=====================================================\n");
    printf(" Kyocera fastboot trigger (v7, C89)\n");
    printf(" uid=%d euid=%d\n", (int)getuid(), (int)geteuid());
    printf("=====================================================\n\n");

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    /* --help */
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

    if (!strcmp(argv[1], "--bruteforce"))
        return cmd_bruteforce(1);

    if (!strcmp(argv[1], "--bruteforce-noreboot"))
        return cmd_bruteforce(0);

    /* 位置引数 = reason 文字列 → Path A */
    printf("[*] Path A: reason = \"%s\"\n\n", argv[1]);
    fflush(stdout);
    (void)argi;
    return issue_reboot_restart2(argv[1]);
}
