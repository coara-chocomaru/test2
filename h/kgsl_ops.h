#ifndef KGSL_OPS_H
#define KGSL_OPS_H

#include <stdint.h>
#include <stddef.h>

int gpuobj_alloc(int fd, uint64_t size, uint64_t flags);
void *gpuobj_mmap(int fd, size_t size, unsigned int id);
int gpuobj_info(int fd, unsigned int id, uint64_t *gpuaddr, uint64_t *flags);
void gpuobj_free(int fd, unsigned int id);
unsigned int create_context(int fd);
int wait_timestamp(int fd, unsigned int ctx_id, unsigned int target);
int submit_ib(int fd, unsigned int ctx_id, uint64_t ib_gpuaddr,
    size_t ib_bytes, unsigned int ib_id, unsigned int *out_ts);

uint32_t cp_type7(uint32_t opcode, uint32_t cnt);
void split64(uint64_t addr, uint32_t *lo, uint32_t *hi);

#endif