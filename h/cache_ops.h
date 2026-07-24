#ifndef CACHE_OPS_H
#define CACHE_OPS_H

#include <stddef.h>

void flush_dc_civac_range(void *start, size_t len);

#endif