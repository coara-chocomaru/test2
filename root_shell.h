#ifndef ROOT_SHELL_H
#define ROOT_SHELL_H

#include <stdint.h>
#include <stddef.h>

uint32_t pm4_parity_asm(uint32_t v);
uint32_t cp_type7_asm(uint32_t opcode, uint32_t cnt);
void split64_asm(uint64_t addr, uint32_t *lo, uint32_t *hi);
void dc_civac_asm(void *addr);
void dsb_sy_asm(void);
void flush_dc_civac_range_asm(void *start, size_t len);

#endif
