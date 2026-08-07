#include <stdint.h>
#include <stddef.h>

uint32_t pm4_parity_asm(uint32_t v) {
    uint32_t res;
    __asm__ volatile (
        "eor    %0, %1, %1, lsr #4\n"
        "eor    %0, %0, %0, lsr #8\n"
        "eor    %0, %0, %0, lsr #12\n"
        "eor    %0, %0, %0, lsr #16\n"
        "eor    %0, %0, %0, lsr #20\n"
        "eor    %0, %0, %0, lsr #24\n"
        "eor    %0, %0, %0, lsr #28\n"
        "and    %0, %0, #0xf\n"
        "mov    %0, #0x9669\n"
        "lsr    %0, %0, %0\n"
        "and    %0, %0, #1\n"
        : "=r"(res)
        : "r"(v)
        : "cc"
    );
    return res;
}

uint32_t cp_type7_asm(uint32_t opcode, uint32_t cnt) {
    uint32_t header;
    __asm__ volatile (
        "orr    %0, %1, %2, lsl #16\n"
        "orr    %0, %0, %3, lsl #0\n"
        "orr    %0, %0, #0x70000000\n"
        : "=r"(header)
        : "r"((cnt & 0x3fff) | (pm4_parity_asm(cnt) << 15)),
          "r"(opcode & 0x7f),
          "r"(pm4_parity_asm(opcode) << 23)
        : "cc"
    );
    return header;
}

void split64_asm(uint64_t addr, uint32_t *lo, uint32_t *hi) {
    __asm__ volatile (
        "str    %1, [%0]\n"
        "lsr    %1, %1, #32\n"
        "str    %1, [%2, #4]\n"
        :
        : "r"(lo), "r"(addr), "r"(hi)
        : "memory"
    );
}

void dc_civac_asm(void *addr) {
    __asm__ volatile (
        "dc     civac, %0\n"
        :
        : "r"(addr)
        : "memory"
    );
}

void dsb_sy_asm(void) {
    __asm__ volatile (
        "dsb    sy\n"
        :
        :
        : "memory"
    );
}

void flush_dc_civac_range_asm(void *start, size_t len) {
    char *p = (char *)((uintptr_t)start & ~63);
    char *end = (char *)((uintptr_t)start + len);
    while (p < end) {
        dc_civac_asm(p);
        p += 64;
    }
    dsb_sy_asm();
}
