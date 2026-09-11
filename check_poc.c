/*
 * check_poc.c
 * ----------------------------------------------------------------------
 * Native PoC to write the "fastboot flag" (and reboot param) into NAND
 * via /dev/dnand_cdev, reverse-engineered from:
 *
 *   - dnand_diag binary  (asm: fcn.00000a70, fcn.00000ccc, fcn.00000d4c)
 *   - dnand_cdev_driver.c (Kyocera kernel module, GPLv2)
 *   - dnand_k_api.c       (kdnand_id_read / kdnand_id_write)
 *   - dnand_fs.c          (dnand_fs_read / dnand_fs_write)
 *
 * Userspace ioctl struct MUST match kernel's dnand_data_type:
 *   +0x00  uint32_t cid        DNAND ID
 *   +0x04  uint32_t size       payload size (>0, kernel rejects 0)
 *   +0x08  uint32_t offset     offset inside DNAND item
 *   +0x0c  uint32_t reserved   padding
 *   +0x10  void    *pbuf       userspace data buffer
 *
 * Build (Android NDK r10e, arm64-v8a, android-22):
 *   aarch64-linux-android-gcc -O2 -static -pie -fPIE \
 *       -o check_poc check_poc.c
 *
 * Build (glibc cross):
 *   aarch64-linux-gnu-gcc -O2 -static -o check_poc check_poc.c
 * ----------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>

#define DNAND_DEVICE              "/dev/dnand_cdev"

/* ioctl numbers — from dnand_diag:
 *   fcn.00000ccc @ 0xd08: mov w1, 0x11  → write
 *   fcn.00000d4c @ 0xd88: mov w1, 0x10  → read
 */
#define DNAND_CDEV_IOCTL_WRITE    0x11
#define DNAND_CDEV_IOCTL_READ     0x10

/* ------------------------------------------------------------------ *
 * DNAND IDs — extracted in order from dnand_diag .rodata
 * ------------------------------------------------------------------ */
enum dnand_id {
    DNAND_ID_BOOT_FACTORYINIT         = 0x00,
    DNAND_ID_BOOT_CHECKSUMADDR        = 0x01,
    DNAND_ID_BOOT_CHECKSUM            = 0x02,
    DNAND_ID_DIAG_KCLOG               = 0x03,
    DNAND_ID_CHKCODE                  = 0x04,
    DNAND_ID_SDDL_SETFLAG             = 0x05,
    DNAND_ID_FOTA_MAIN                = 0x06,
    DNAND_ID_FOTA_SUB                 = 0x07,
    DNAND_ID_FOTA_LOG                 = 0x08,
    DNAND_ID_FACTORY_CMDLINE          = 0x09,
    DNAND_ID_FACTORY_USB              = 0x0a,
    DNAND_ID_BOOT_WPROTECTENABLE      = 0x0b,
    DNAND_ID_REBOOT_PARM              = 0x0c,
    DNAND_ID_ALL_RESET_STATUS         = 0x0d,
    DNAND_ID_CHG_NV_CHG_CV            = 0x0e,
    DNAND_ID_CHG_NV_VBATT_LVL_CAL_V   = 0x0f,
    DNAND_ID_CHG_NV_VBATT_THR_CAL_V   = 0x10,
    DNAND_ID_FACTORY_OPTIONS          = 0x11,
    DNAND_ID_CHG_PARAM                = 0x12,
    DNAND_ID_BFSS_RESTORE_DATA        = 0x13,
    DNAND_ID_QFPROM_BLOW_PARAM        = 0x14,
    DNAND_ID_QFPROM_ACCESS_FLAG       = 0x15,
    DNAND_ID_PMIC_PARAM               = 0x16,
    DNAND_ID_CHG_CYCLE                = 0x17,
    DNAND_ID_QFPROM_SECBOOT_MODE      = 0x18,
    DNAND_ID_PWON_STATE               = 0x19,
    DNAND_ID_SDDL_PWOFF_FLAG          = 0x1a,
    DNAND_ID_FSCK_OPTION_STATUS       = 0x1b,
    DNAND_ID_GANG_FSCK_FLAG           = 0x1c,
    DNAND_ID_FASTBOOT_FLAG            = 0x1d,   /* ★ target */
    DNAND_ID_IMEI                     = 0x1e,
    DNAND_ID_ROOTED_CHECK             = 0x1f,
    DNAND_ID_RESCUE_ENABL_FLG         = 0x20,
    DNAND_ID_RESCUE_MASS_ENABLE_FLG   = 0x21,
    DNAND_ID_OS_MODE                  = 0x22,
    DNAND_ID_ENUM_MAX                 = 0x23,
};

/* ------------------------------------------------------------------ *
 * Matches kernel's struct dnand_data_type (dnand_cdev_driver.h).
 * Field order verified against dnand_diag asm str offsets:
 *   str w22,[+0x00], str w3,[+0x04], str w21,[+0x08], str x19,[+0x10]
 * ------------------------------------------------------------------ */
struct dnand_data_type {
    uint32_t cid;       /* +0x00  DNAND ID           */
    uint32_t size;      /* +0x04  payload size (>0)  */
    uint32_t offset;    /* +0x08  offset in item     */
    uint32_t reserved;  /* +0x0c  padding            */
    void    *pbuf;      /* +0x10  userspace buffer   */
};

/* ------------------------------------------------------------------ */
static int dnand_call(uint32_t cid, uint32_t offset,
                      void *buf, uint32_t size, int is_write)
{
    if (size == 0) {
        fprintf(stderr, "[-] size must be > 0 (kernel kdnand_id_param_check rejects 0)\n");
        return -1;
    }
    if (cid >= DNAND_ID_ENUM_MAX) {
        fprintf(stderr, "[-] invalid cid: %u\n", cid);
        return -1;
    }
    if (!buf) {
        fprintf(stderr, "[-] null buffer\n");
        return -1;
    }

    int fd = open(DNAND_DEVICE, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "[-] open(%s): %s\n", DNAND_DEVICE, strerror(errno));
        return -1;
    }

    struct dnand_data_type req;
    memset(&req, 0, sizeof(req));
    req.cid      = cid;
    req.size     = size;
    req.offset   = offset;
    req.reserved = 0;
    req.pbuf     = buf;

    unsigned long cmd = is_write ? DNAND_CDEV_IOCTL_WRITE
                                 : DNAND_CDEV_IOCTL_READ;

    int ret = ioctl(fd, cmd, &req);
    if (ret < 0) {
        fprintf(stderr,
                "[-] ioctl(0x%lx) cid=%u(0x%x) offset=%u size=%u: %s\n",
                cmd, cid, cid, offset, size, strerror(errno));
    }
    close(fd);
    return ret;
}

/* ------------------------------------------------------------------ */
static int write_flag_u32(uint32_t cid, uint32_t value)
{
    uint32_t v = value;
    return dnand_call(cid, 0, &v, sizeof(v), 1);
}

static int read_flag_u32(uint32_t cid, uint32_t *out)
{
    if (!out)
        return -1;
    return dnand_call(cid, 0, out, sizeof(*out), 0);
}

/* ------------------------------------------------------------------ */
static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [fastboot_id] [fastboot_val] [reboot_id] [reboot_val]\n"
        "       %s --write <id> <val>\n"
        "       %s --read  <id>\n"
        "Defaults:\n"
        "  fastboot_id  = 0x%02x  DNAND_ID_FASTBOOT_FLAG\n"
        "  fastboot_val = 1\n"
        "  reboot_id    = 0x%02x  DNAND_ID_REBOOT_PARM\n"
        "  reboot_val   = 0x77665500\n",
        prog, prog, prog,
        DNAND_ID_FASTBOOT_FLAG, DNAND_ID_REBOOT_PARM);
}

/* ------------------------------------------------------------------ */
int main(int argc, char **argv)
{
    uint32_t fastboot_id  = DNAND_ID_FASTBOOT_FLAG;   /* 0x1d */
    uint32_t fastboot_val = 1u;
    uint32_t reboot_id    = DNAND_ID_REBOOT_PARM;     /* 0x0c */
    uint32_t reboot_val   = 0x77665500u;

    /* --- Help --- */
    if (argc > 1 &&
        (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
        usage(argv[0]);
        return 0;
    }

    /* --- Simple write mode:  --write <id> <val> --- */
    if (argc == 4 && strcmp(argv[1], "--write") == 0) {
        uint32_t id  = (uint32_t)strtoul(argv[2], NULL, 0);
        uint32_t val = (uint32_t)strtoul(argv[3], NULL, 0);

        printf("[*] write id=0x%x (dec %u) value=0x%08x\n", id, id, val);
        int ret = write_flag_u32(id, val);
        if (ret < 0) {
            fprintf(stderr, "[-] write failed\n");
            return 1;
        }
        printf("[+] write ok\n");
        return 0;
    }

    /* --- Simple read mode:  --read <id> --- */
    if (argc == 3 && strcmp(argv[1], "--read") == 0) {
        uint32_t id = (uint32_t)strtoul(argv[2], NULL, 0);
        uint32_t val = 0;

        printf("[*] read id=0x%x (dec %u)\n", id, id);
        int ret = read_flag_u32(id, &val);
        if (ret < 0) {
            fprintf(stderr, "[-] read failed\n");
            return 1;
        }
        printf("[+] read value=0x%08x (dec %u)\n", val, val);
        return 0;
    }

    /* --- Default: fastboot flag write + verify, then reboot param --- */
    if (argc > 1) fastboot_id  = (uint32_t)strtoul(argv[1], NULL, 0);
    if (argc > 2) fastboot_val = (uint32_t)strtoul(argv[2], NULL, 0);
    if (argc > 3) reboot_id    = (uint32_t)strtoul(argv[3], NULL, 0);
    if (argc > 4) reboot_val   = (uint32_t)strtoul(argv[4], NULL, 0);

    printf("===================================================\n");
    printf(" check_poc — write fastboot flag via /dev/dnand_cdev\n");
    printf("===================================================\n");
    printf("[*] device       : %s\n", DNAND_DEVICE);
    printf("[*] FASTBOOT id  : 0x%02x (%u)\n", fastboot_id, fastboot_id);
    printf("[*] FASTBOOT val : 0x%08x (%u)\n", fastboot_val, fastboot_val);
    printf("[*] REBOOT   id  : 0x%02x (%u)\n", reboot_id, reboot_id);
    printf("[*] REBOOT   val : 0x%08x\n", reboot_val);
    printf("---------------------------------------------------\n");

    /* --- Step 1: write DNAND_ID_FASTBOOT_FLAG --- */
    printf("\n[1] writing DNAND_ID_FASTBOOT_FLAG ...\n");
    int ret = write_flag_u32(fastboot_id, fastboot_val);
    if (ret < 0) {
        fprintf(stderr, "[-] write FASTBOOT_FLAG failed — aborting\n");
        return 1;
    }
    printf("[+] write FASTBOOT_FLAG ok\n");

    /* --- Step 2: read-back verify --- */
    printf("\n[2] verifying DNAND_ID_FASTBOOT_FLAG ...\n");
    uint32_t rb = 0;
    ret = read_flag_u32(fastboot_id, &rb);
    if (ret < 0) {
        fprintf(stderr, "[-] read FASTBOOT_FLAG failed\n");
    } else {
        printf("[+] read FASTBOOT_FLAG = 0x%08x (%u)\n", rb, rb);
        if (rb != fastboot_val) {
            fprintf(stderr,
                    "[!] mismatch: expected 0x%08x, got 0x%08x\n",
                    fastboot_val, rb);
            return 2;
        }
        printf("[+] verify OK\n");
    }

    /* --- Step 3: write DNAND_ID_REBOOT_PARM --- */
    printf("\n[3] writing DNAND_ID_REBOOT_PARM ...\n");
    ret = write_flag_u32(reboot_id, reboot_val);
    if (ret < 0) {
        fprintf(stderr, "[-] write REBOOT_PARM failed\n");
        return 3;
    }
    printf("[+] write REBOOT_PARM ok\n");

    /* --- Step 4: flush and finish --- */
    sync();

    printf("\n===================================================\n");
    printf("[+] DONE.\n");
    printf("    Reboot to enter fastboot mode:\n");
    printf("        adb reboot     (or)   reboot\n");
    printf("    Then on host:\n");
    printf("        fastboot devices\n");
    printf("===================================================\n");
    return 0;
}
