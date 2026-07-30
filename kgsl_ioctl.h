#ifndef KGSL_IOCTL_H
#define KGSL_IOCTL_H

#define KGSL_GPUOBJ_ALLOC                    0xC0406E01
#define KGSL_GPUOBJ_FREE                     0xC0086E02
#define KGSL_GPUOBJ_IMPORT                   0xC0406E03
#define KGSL_GPU_DRAWOBJ                     0xC0106E05
#define KGSL_GPU_DRAWOBJ_SYNC                0xC0206E06
#define KGSL_CREATE_CONTEXT                  0xC0086E07
#define KGSL_DESTROY_CONTEXT                 0xC0086E08

#define IOCTL_KGSL_GPUOBJ_ALLOC              _IOWR('K', 0x01, struct kgsl_gpuobj_info)
#define IOCTL_KGSL_GPUOBJ_FREE               _IOW('K', 0x02, uint32_t)
#define IOCTL_KGSL_GPUOBJ_IMPORT             _IOWR('K', 0x03, struct kgsl_gpuobj_import)
#define IOCTL_KGSL_GPU_DRAWOBJ               _IOW('K', 0x05, void *)
#define IOCTL_KGSL_GPU_DRAWOBJ_SYNC          _IOW('K', 0x06, struct kgsl_drawobj_sync)
#define IOCTL_KGSL_CREATE_CONTEXT            _IOWR('K', 0x07, struct kgsl_context)
#define IOCTL_KGSL_DESTROY_CONTEXT           _IOW('K', 0x08, uint32_t)

#define KGSL_DRAWOBJ_TYPE_CMD                0x1
#define KGSL_CMD_FLAG_INTERNAL_ISSUE         0x100
#define KGSL_CMD_SYNCPOINT_TYPE_TIMESTAMP    0x1
#define KGSL_SYNC_HANDLE_IGNORE              0xFFFFFFFF
#define KGSL_SYNC_ID_IGNORE                  0xFFFFFFFF
#define KGSL_CMD_TIMESTAMP_MAX               0xFFFFFFFF
#define KGSL_DRAWOBJ_CMD_LIST_TYPE_IB        0x1

#define KGSL_USER_MEM_TYPE_ADDR              0x1
#define KGSL_GPUOBJ_IMPORT_WRITE             0x1

struct kgsl_gpuobj_info {
    uint64_t gpuaddr;
    uint64_t size;
    uint32_t id;
    uint32_t flags;
    uint64_t priv;
    uint32_t pad;
};

struct kgsl_gpuobj_import {
    uint32_t type;
    uint32_t flags;
    uint64_t useraddr;
    uint64_t len;
    uint32_t id;
    uint32_t pad;
};

struct kgsl_context {
    uint32_t flags;
    uint32_t id;
    uint32_t pad;
};

struct kgsl_drawobj_sync {
    uint32_t context_id;
    uint32_t timestamp;
    uint32_t type;
    uint32_t handle;
    uint32_t id;
};

struct kgsl_drawobj {
    uint32_t type;
    uint32_t flags;
    uint32_t context_id;
    uint32_t timestamp;
};

struct kgsl_drawobj_cmd {
    uint32_t type;
    uint32_t flags;
    uint32_t context_id;
    uint32_t timestamp;
    uint32_t cmdlist_count;
    uint32_t cmdlist_offset;
    uint32_t synclist_count;
    uint32_t synclist_offset;
    uint32_t privdata;
    uint32_t priority;
};

struct kgsl_drawobj_cmdlist {
    uint64_t gpuaddr;
    uint64_t size;
    uint32_t type;
    uint32_t flags;
};

struct kgsl_drawobj_synclist {
    uint64_t gpuaddr;
    uint64_t size;
    uint32_t type;
    uint32_t flags;
};

#endif
