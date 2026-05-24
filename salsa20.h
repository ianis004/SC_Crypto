#ifndef SALSA20_H
#define SALSA20_H
#include <stdint.h>
void salsa20_init(uint8_t key[32], uint64_t nonce, uint32_t counter);
void salsa20_keystream(uint8_t out[64]);
#endif