#ifndef CHACHA20_H
#define CHACHA20_H
#include <stdint.h>

void chacha20_init(uint8_t key[32], uint64_t nonce, uint32_t counter);
void chacha20_keystream(uint8_t out[64]);

#endif