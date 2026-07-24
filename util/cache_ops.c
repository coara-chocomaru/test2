#include "cache_ops.h"
#include "common.h"
#include <signal.h>

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

void flush_dc_civac_range(void *start, size_t len) {
    if (dc_civac_works != 1) return;
    char *p = (char*)((uintptr_t)start & ~63);
    char *end = (char*)((uintptr_t)start + len);
    for (; p < end; p += 64) try_dc_civac(p);
}