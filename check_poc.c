/*
 * fastboot_poc.c  (v5 - 最終版)
 * =====================================================================
 * Kyocera 端末を確実に fastboot mode へ移行させる最小バイナリ
 *
 * 動作原理 (msm-poweroff.c より):
 *   syscall(SYS_reboot, ..., "bootloader")
 *     → kernel_restart("bootloader")
 *     → do_msm_restart() → msm_restart_prepare("bootloader")
 *     → __raw_writel(0x77665500, IMEM_restart_reason)
 *     → PMIC power down → cold reset
 *     → SBL1/ABL が IMEM を読み fastboot mode へ
 *
 * ビルド (NDK r10e / arm64):
 *   aarch64-linux-android-gcc -O2 -static -pie -fPIE \
 *       -o fastboot_poc fastboot_poc.c
 * =====================================================================
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>
#include <linux/reboot.h>

/*
 * Linux の reboot(2) システムコールを直接呼ぶ。
 * glibc/bionic の reboot() ラッパは LINUX_REBOOT_CMD_RESTART2 を
 * サポートしないため、syscall(SYS_reboot, ...) を使う必要がある。
 */
static int do_restart2(const char *reason)
{
    return (int)syscall(SYS_reboot,
                        LINUX_REBOOT_MAGIC1,
                        LINUX_REBOOT_MAGIC2,
                        LINUX_REBOOT_CMD_RESTART2,
                        reason);
}

static void usage(const char *p)
{
    fprintf(stderr,
        "Usage: %s [reason]\n"
        "\n"
        "Reason strings accepted by msm-poweroff.c:\n"
        "  bootloader  -> 0x77665500  FASTBOOT MODE (default)\n"
        "  recovery    -> 0x77665502  RECOVERY MODE\n"
        "  rtc         -> 0x77665503  RTC alarm boot\n"
        "  edl         -> emergency download mode\n"
        "  oem-XXXX    -> 0x6f656dXX  OEM custom reason\n"
        "  (anything else) -> 0x77665501  normal reboot\n"
        "\n"
        "Examples:\n"
        "  %s bootloader\n"
        "  %s recovery\n"
        "  %s oem-12\n",
        p, p, p, p);
}

int main(int argc, char **argv)
{
    const char *reason = "bootloader";

    if (argc > 1) {
        if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
            usage(argv[0]);
            return 0;
        }
        reason = argv[1];
    }

    /* reason の長さチェック (kernel は PAGE_SIZE まで許容するが念のため) */
    size_t len = strlen(reason);
    if (len == 0 || len > 255) {
        fprintf(stderr, "[-] invalid reason length: %zu\n", len);
        return 1;
    }

    printf("=====================================================\n");
    printf(" Kyocera fastboot PoC (v5)\n");
    printf("=====================================================\n");
    printf("[*] reason = \"%s\"\n", reason);

    if (!strcmp(reason, "bootloader"))
        printf("[*] expected IMEM value = 0x77665500 (fastboot)\n");
    else if (!strcmp(reason, "recovery"))
        printf("[*] expected IMEM value = 0x77665502 (recovery)\n");
    else if (!strcmp(reason, "rtc"))
        printf("[*] expected IMEM value = 0x77665503 (rtc)\n");
    else if (!strncmp(reason, "edl", 3))
        printf("[*] emergency dload mode\n");
    else if (!strncmp(reason, "oem-", 4))
        printf("[*] expected IMEM value = 0x6f656dXX (OEM)\n");
    else
        printf("[*] expected IMEM value = 0x77665501 (normal)\n");

    printf("[*] calling syscall(SYS_reboot, ..., RESTART2, \"%s\") ...\n",
           reason);
    printf("[*] the device will now reset — this is expected.\n");
    fflush(stdout);

    sync();

    int r = do_restart2(reason);
    /* ここには到達しないはず */
    fprintf(stderr, "[-] reboot failed: %s (errno=%d)\n",
            strerror(errno), errno);
    return r == 0 ? 0 : 1;
}
