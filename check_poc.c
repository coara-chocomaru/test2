

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>

#define DNAND_DEVICE       "/dev/dnand_cdev"
#define DNAND_IOCTL_WRITE  0x11u
#define DNAND_IOCTL_READ   0x10u

/* ------------------------------------------------------------------
 * DNAND IDs — extracted in-order from dnand_diag .rodata
 * ------------------------------------------------------------------ */
enum dnand_id {
    DNAND_ID_BOOT_FACTORYINIT       = 0x00,
    DNAND_ID_BOOT_CHECKSUMADDR      = 0x01,
    DNAND_ID_BOOT_CHECKSUM          = 0x02,
    DNAND_ID_DIAG_KCLOG             = 0x03,
    DNAND_ID_CHKCODE                = 0x04,
    DNAND_ID_SDDL_SETFLAG           = 0x05,
    DNAND_ID_FOTA_MAIN              = 0x06,
    DNAND_ID_FOTA_SUB               = 0x07,
    DNAND_ID_FOTA_LOG               = 0x08,
    DNAND_ID_FACTORY_CMDLINE        = 0x09,
    DNAND_ID_FACTORY_USB            = 0x0a,
    DNAND_ID_BOOT_WPROTECTENABLE    = 0x0b,
    DNAND_ID_REBOOT_PARM            = 0x0c,
    DNAND_ID_ALL_RESET_STATUS       = 0x0d,
    DNAND_ID_CHG_NV_CHG_CV          = 0x0e,
    DNAND_ID_CHG_NV_VBATT_LVL_CAL_V = 0x0f,
    DNAND_ID_CHG_NV_VBATT_THR_CAL_V = 0x10,
    DNAND_ID_FACTORY_OPTIONS        = 0x11,
    DNAND_ID_CHG_PARAM              = 0x12,
    DNAND_ID_BFSS_RESTORE_DATA      = 0x13,
    DNAND_ID_QFPROM_BLOW_PARAM      = 0x14,
    DNAND_ID_QFPROM_ACCESS_FLAG     = 0x15,
    DNAND_ID_PMIC_PARAM             = 0x16,
    DNAND_ID_CHG_CYCLE              = 0x17,
    DNAND_ID_QFPROM_SECBOOT_MODE    = 0x18,
    DNAND_ID_PWON_STATE             = 0x19,
    DNAND_ID_SDDL_PWOFF_FLAG        = 0x1a,
    DNAND_ID_FSCK_OPTION_STATUS     = 0x1b,
    DNAND_ID_GANG_FSCK_FLAG         = 0x1c,
    DNAND_ID_FASTBOOT_FLAG          = 0x1d,   /* ★ target */
    DNAND_ID_IMEI                   = 0x1e,
    DNAND_ID_ROOTED_CHECK           = 0x1f,
    DNAND_ID_RESCUE_ENABL_FLG       = 0x20,
    DNAND_ID_RESCUE_MASS_ENABLE_FLG = 0x21,
    DNAND_ID_OS_MODE                = 0x22,
    DNAND_ID_ENUM_MAX               = 0x23,
};

/* ------------------------------------------------------------------
 * ioctl request structure — matches var_48h layout in fcn.00000ccc
 * ------------------------------------------------------------------ */
struct dnand_ioctl_req {
    uint32_t id;        /* +0x00 */
    uint32_t length;    /* +0x04 */
    uint32_t value;     /* +0x08 */
    uint32_t _pad;      /* +0x0c */
    void    *data;      /* +0x10 */
};

/* ------------------------------------------------------------------
 * Open /dev/dnand_cdev  (O_RDWR = 2, same as dnand_diag)
 * ------------------------------------------------------------------ */
static int dnand_open(void)
{
    int fd = open(DNAND_DEVICE, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "[-] open(%s) failed: %s\n",
                DNAND_DEVICE, strerror(errno));
    }
    return fd;
}

/* ------------------------------------------------------------------
 * Write path — fcn.00000ccc / ioctl 0x11
 *   arg order to wrapper: (id, value, data, length)
 *   struct field order :  id, length, value, pad, data
 * ------------------------------------------------------------------ */
static int dnand_write(uint32_t id, uint32_t value,
                       void *data, uint32_t length)
{
    int fd = dnand_open();
    if (fd < 0) return -1;

    struct dnand_ioctl_req req;
    memset(&req, 0, sizeof(req));
    req.id     = id;
    req.length = length;
    req.value  = value;
    req.data   = data;

    int ret = ioctl(fd, DNAND_IOCTL_WRITE, &req);
    if (ret < 0) {
        fprintf(stderr,
                "[-] ioctl(0x%02x) id=%u(0x%x) value=0x%x len=%u failed: %s\n",
                DNAND_IOCTL_WRITE, id, id, value, length, strerror(errno));
    }
    close(fd);
    return ret;
}

/* ------------------------------------------------------------------
 * Read path — fcn.00000d4c / ioctl 0x10
 * ------------------------------------------------------------------ */
static int dnand_read(uint32_t id, uint32_t *out_value,
                      void *data, uint32_t length)
{
    int fd = dnand_open();
    if (fd < 0) return -1;

    struct dnand_ioctl_req req;
    memset(&req, 0, sizeof(req));
    req.id     = id;
    req.length = length;
    req.value  = 0;
    req.data   = data;

    int ret = ioctl(fd, DNAND_IOCTL_READ, &req);
    if (ret < 0) {
        fprintf(stderr,
                "[-] ioctl(0x%02x) id=%u(0x%x) len=%u failed: %s\n",
                DNAND_IOCTL_READ, id, id, length, strerror(errno));
    } else if (out_value) {
        *out_value = req.value;
    }
    close(fd);
    return ret;
}

/* ------------------------------------------------------------------ */
static void usage(const char *argv0)
{
    fprintf(stderr,
        "Usage: %s [fastboot_id] [fastboot_val] [reboot_id] [reboot_val]\n"
        "\n"
        "  Defaults (from dnand_diag .rodata enum order):\n"
        "    fastboot_id  = %u  (0x%02x)  DNAND_ID_FASTBOOT_FLAG\n"
        "    fastboot_val = 1\n"
        "    reboot_id    = %u  (0x%02x)  DNAND_ID_REBOOT_PARM\n"
        "    reboot_val   = 0x77665500\n"
        "\n"
        "  Examples:\n"
        "    %s                      # use defaults\n"
        "    %s 0x1d 1 0x0c 0x77665500\n"
        "    %s 29 1                 # only change fastboot flag\n",
        argv0,
        DNAND_ID_FASTBOOT_FLAG, DNAND_ID_FASTBOOT_FLAG,
        DNAND_ID_REBOOT_PARM,   DNAND_ID_REBOOT_PARM,
        argv0, argv0, argv0);
}

/* ------------------------------------------------------------------ */
int main(int argc, char **argv)
{
    uint32_t fastboot_id  = DNAND_ID_FASTBOOT_FLAG;   /* 0x1d */
    uint32_t fastboot_val = 1;
    uint32_t reboot_id    = DNAND_ID_REBOOT_PARM;     /* 0x0c */
    uint32_t reboot_val   = 0x77665500u;              /* Qualcomm bootloader magic */

    if (argc > 1 && (strcmp(argv[1], "-h") == 0 ||
                     strcmp(argv[1], "--help") == 0)) {
        usage(argv[0]);
        return 0;
    }
    if (argc > 1) fastboot_id  = (uint32_t)strtoul(argv[1], NULL, 0);
    if (argc > 2) fastboot_val = (uint32_t)strtoul(argv[2], NULL, 0);
    if (argc > 3) reboot_id    = (uint32_t)strtoul(argv[3], NULL, 0);
    if (argc > 4) reboot_val   = (uint32_t)strtoul(argv[4], NULL, 0);

    printf("===================================================\n");
    printf(" dnand_fastboot — write fastboot flag to NAND\n");
    printf("===================================================\n");
    printf("[*] device       : %s\n", DNAND_DEVICE);
    printf("[*] FASTBOOT id  : %u (0x%x)\n", fastboot_id, fastboot_id);
    printf("[*] FASTBOOT val : %u (0x%x)\n", fastboot_val, fastboot_val);
    printf("[*] REBOOT   id  : %u (0x%x)\n", reboot_id, reboot_id);
    printf("[*] REBOOT   val : 0x%08x\n", reboot_val);
    printf("---------------------------------------------------\n");

    /* Zeroed 0x400-byte scratch buffer — matches the memset()
     * of the response buffer in dnand_diag fcn.00000a70 @ 0xbe0.
     * length is 0 for flag writes, so the kernel ignores it,
     * but a valid pointer avoids any NULL-deref surprise. */
    uint8_t buf[0x400];
    memset(buf, 0, sizeof(buf));

    /* ---------- Step 1: write DNAND_ID_FASTBOOT_FLAG = val ---------- */
    printf("\n[1] writing DNAND_ID_FASTBOOT_FLAG ...\n");
    int ret = dnand_write(fastboot_id, fastboot_val, buf, 0);
    if (ret < 0) {
        fprintf(stderr, "[-] write FASTBOOT_FLAG failed — aborting\n");
        return 1;
    }
    printf("[+] write FASTBOOT_FLAG ok (ret=%d)\n", ret);

    /* ---------- Step 2: read-back verify ---------- */
    printf("\n[2] verifying DNAND_ID_FASTBOOT_FLAG ...\n");
    uint32_t v = 0;
    ret = dnand_read(fastboot_id, &v, buf, 0);
    if (ret < 0) {
        fprintf(stderr, "[-] read FASTBOOT_FLAG failed\n");
    } else {
        printf("[+] read  FASTBOOT_FLAG = %u (0x%x)\n", v, v);
        if (v != fastboot_val) {
            fprintf(stderr,
                    "[!] mismatch: expected %u, got %u\n",
                    fastboot_val, v);
            return 2;
        }
        printf("[+] verify OK\n");
    }

    /* ---------- Step 3: write DNAND_ID_REBOOT_PARM ---------- */
    printf("\n[3] writing DNAND_ID_REBOOT_PARM ...\n");
    ret = dnand_write(reboot_id, reboot_val, buf, 0);
    if (ret < 0) {
        fprintf(stderr, "[-] write REBOOT_PARM failed\n");
        return 3;
    }
    printf("[+] write REBOOT_PARM ok (ret=%d)\n", ret);

    /* ---------- Step 4: flush and finish ---------- */
    sync();

    printf("\n===================================================\n");
    printf("[+] DONE.\n");
    printf("    Reboot the device to enter fastboot mode:\n");
    printf("        adb reboot   (or)   reboot\n");
    printf("    Then verify on host:\n");
    printf("        fastboot devices\n");
    printf("===================================================\n");
    return 0;
}
