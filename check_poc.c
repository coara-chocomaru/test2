#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/reboot.h>

#define DNAND_DEVICE        "/dev/dnand_cdev"
#define DNAND_IOCTL_WRITE   0x10
#define DNAND_IOCTL_READ    0x11
#define DNAND_ID_FASTBOOT   29

struct __attribute__((__packed__)) dnand_ioctl_args {
    uint32_t    id;   
    uint32_t    value;
    uint64_t    data_ptr;
    uint32_t    len;
};

static int dnand_id_write(int id, uint32_t value)
{
    int fd = open(DNAND_DEVICE, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "open(%s): %s\n", DNAND_DEVICE, strerror(errno));
        return -1;
    }

    uint32_t buf = value;

    struct dnand_ioctl_args args = {
        .id       = (uint32_t)id,
        .value    = value,
        .data_ptr = (uint64_t)(uintptr_t)&buf,
        .len      = (uint32_t)sizeof(buf),
    };

    errno = 0;
    int ret = ioctl(fd, DNAND_IOCTL_WRITE, &args);
    int saved_errno = errno;

    if (close(fd) != 0 && ret == 0) {
        saved_errno = errno;
        ret = -1;
    }

    if (ret < 0) {
        fprintf(stderr,
                "ioctl(0x%x, id=%d, value=%u): %s\n",
                DNAND_IOCTL_WRITE, id, value, strerror(saved_errno));
        errno = saved_errno;
    }
    return ret;
}

int main(void)
{
    if (getuid() != 0) {
        fprintf(stderr, "Root privileges required.\n");
        return EXIT_FAILURE;
    }

    if (dnand_id_write(DNAND_ID_FASTBOOT, 1) != 0) {
        fprintf(stderr, "Failed to write DNAND fastboot flag.\n");
        return EXIT_FAILURE;
    }
    fprintf(stderr, "DNAND fastboot flag set.\n");

    sync();

    fprintf(stderr, "Rebooting to bootloader...\n");
    fflush(stdout);
    fflush(stderr);

    int sys_ret = system("reboot bootloader");
    if (sys_ret == 0) {
    }

    fprintf(stderr, "system(reboot bootloader) failed, "
                    "falling back to reboot(RB_AUTOBOOT)...\n");
    sync();
    reboot(RB_AUTOBOOT);

    perror("reboot(RB_AUTOBOOT)");
    return EXIT_FAILURE;
}
