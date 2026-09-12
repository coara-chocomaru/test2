#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <stdint.h>

#define MAP_MASK (getpagesize() - 1)

static void usage(const char *prog)
{
    fprintf(stderr, "usage: %s <address> <width:8|16|32> [value]\n", prog);
    fprintf(stderr, "  read : %s 0x8600065c 32\n", prog);
    fprintf(stderr, "  write: %s 0x8600065c 32 0x77665500\n", prog);
    exit(1);
}

int main(int argc, char **argv)
{
    off_t target;
    int width;
    unsigned long writeval = 0;
    int do_write = 0;
    int fd;
    void *map_base, *virt_addr;
    unsigned long page_size;
    unsigned long page_mask;

    if (argc < 3 || argc > 4) {
        usage(argv[0]);
    }

    target = strtoul(argv[1], NULL, 0);
    width = atoi(argv[2]);

    if (width != 8 && width != 16 && width != 32) {
        fprintf(stderr, "invalid width: %d (must be 8, 16 or 32)\n", width);
        return 1;
    }

    if (argc == 4) {
        do_write = 1;
        writeval = strtoul(argv[3], NULL, 0);
    }

    page_size = getpagesize();
    page_mask = page_size - 1;

    fd = open("/dev/mem", O_RDWR | O_SYNC);
    if (fd < 0) {
        fprintf(stderr, "open(/dev/mem) failed: %s (errno=%d)\n", strerror(errno), errno);
        return 1;
    }

    map_base = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                     fd, (off_t)(target & ~page_mask));
    if (map_base == MAP_FAILED) {
        fprintf(stderr, "mmap failed at 0x%lx: %s (errno=%d)\n",
                (unsigned long)(target & ~page_mask), strerror(errno), errno);
        close(fd);
        return 1;
    }

    virt_addr = (char *)map_base + (target & page_mask);

    if (do_write) {
        switch (width) {
        case 8:
            *(volatile uint8_t *)virt_addr = (uint8_t)writeval;
            break;
        case 16:
            *(volatile uint16_t *)virt_addr = (uint16_t)writeval;
            break;
        case 32:
            *(volatile uint32_t *)virt_addr = (uint32_t)writeval;
            break;
        }
    }

    switch (width) {
    case 8:
        printf("addr 0x%lx: 0x%02x\n", (unsigned long)target,
               *(volatile uint8_t *)virt_addr);
        break;
    case 16:
        printf("addr 0x%lx: 0x%04x\n", (unsigned long)target,
               *(volatile uint16_t *)virt_addr);
        break;
    case 32:
        printf("addr 0x%lx: 0x%08x\n", (unsigned long)target,
               *(volatile uint32_t *)virt_addr);
        break;
    }

    munmap(map_base, page_size);
    close(fd);
    return 0;
}
