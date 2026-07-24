#ifndef KASLR_H
#define KASLR_H

#include <stdint.h>

uint64_t detect_kaslr(uint64_t *init_cred_out, uint64_t *selinux_state_out, uint64_t *enforcing_out);

#endif