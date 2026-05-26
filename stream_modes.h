#ifndef STREAM_MODES_H
#define STREAM_MODES_H

#include <stdint.h>

void stream_ctr_crypt(const uint8_t *plaintext, size_t plen,
                     const uint8_t *key, uint64_t nonce, uint32_t counter,
                     const char *algo, uint8_t *ciphertext);

#endif