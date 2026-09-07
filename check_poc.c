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
#define DNAND_ID_FASTBOOT   29

struct __attribute__((__packed__)) dnand_ioctl_args {
    uint32_t    id;
    uint32_t    value;
    uint64_t    data_ptr;
    uint32_t    len;
};

static int dnand_id_write(int id, uint32_t value) {
    int fd = open(DNAND_DEVICE, O_RDWR);
    if (fd < 0)
        return -1;

    struct dnand_ioctl_args args = {
        .id       = (uint32_t)id,
        .value    = value,
        .data_ptr = 0,
        .len      = 0
    };

    int ret = ioctl(fd, DNAND_IOCTL_WRITE, &args);
    close(fd);
    return ret;
}

int main(void) {
    if (getuid() != 0) {
        fprintf(stderr, "Root privileges required.\n");
        return EXIT_FAILURE;
    }

    if (dnand_id_write(DNAND_ID_FASTBOOT, 1) != 0) {
        perror("Failed to write DNAND");
        return EXIT_FAILURE;
    }

    printf("Fastboot flag set. Rebooting...\n");
    fflush(stdout);
    sync();

    if (reboot(RB_AUTOBOOT) != 0)
        system("reboot bootloader");

    return EXIT_SUCCESS;
}
