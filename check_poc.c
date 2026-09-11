

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>

#define DNAND_DEVICE              "/dev/dnand_cdev"

/* ioctl numbers, from dnand_diag fcn.00000ccc (0xd08) and fcn.00000d4c (0xd88) */
#define DNAND_CDEV_IOCTL_WRITE    0x11
#define DNAND_CDEV_IOCTL_READ     0x10

/* ------------------------------------------------------------------ *
 * DNAND IDs (in-order from dnand_diag .rodata; must match kernel enum)
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
    DNAND_ID_FASTBOOT_FLAG            = 0x1d,
    DNAND_ID_IMEI                     = 0x1e,
    DNAND_ID_ROOTED_CHECK             = 0x1f,
    DNAND_ID_RESCUE_ENABL_FLG         = 0x20,
    DNAND_ID_RESCUE_MASS_ENABLE_FLG   = 0x21,
    DNAND_ID_OS_MODE                  = 0x22,
    DNAND_ID_ENUM_MAX                 = 0x23,
};

/* ------------------------------------------------------------------ *
 * Must match kernel's dnand_data_type layout exactly.
 * ------------------------------------------------------------------ */
struct dnand_data_type {
    uint32_t cid;       /* +0x00 */
    uint32_t size;      /* +0x04 */
    uint32_t offset;    /* +0x08 */
    uint32_t reserved;  /* +0x0c */
    void    *pbuf;      /* +0x10 */
};

/* ------------------------------------------------------------------ */

static int dnand_call(uint32_t cid, uint32_t offset,
                      void *buf, uint32_t size, int is_write)
{
    /* Kernel rejects size == 0 in kdnand_id_param_check() */
    if (size == 0) {
        fprintf(stderr, "[-] size must be > 0 (kernel rejects size==0)\n");
        return -1;
    }
    /* Kernel rejects cid >= DNAND_ID_ENUM_MAX */
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
        fprintf(stderr, "[-] open(%s): %s\n",
                DNAND_DEVICE, strerror(errno));
        return -1;
    }

    struct dnand_data_type req;
    memset(&req, 0, sizeof(req));
    req.cid    = cid;
    req.size   = size;
    req.offset = offset;
    req.pbuf   = buf;

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

/* ------------------------------------------------------------------ *
 * 汎用フラグ読み書き
 * ------------------------------------------------------------------ */
static int write_flag_u32(uint32_t cid, uint32_t value)
{
    return dnand_call(cid, 0, &value, sizeof(value), 1);
}

static int read_flag_u32(uint32_t cid, uint32_t *out)
{
    return dnand_call(cid, 0, out, sizeof(*out), 0);
}

/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    uint32_t fastboot_val = 1;
    uint32_t reboot_val   = 0x77665500;  /* Qualcomm bootloader magic */

    if (argc > 1 &&
