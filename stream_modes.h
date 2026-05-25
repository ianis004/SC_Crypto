#ifndef STREAM_MODES_H
#define STREAM_MODES_H

#include <stdint.h>

/**
 * CTR mode encryption/decryption for Salsa20 and ChaCha20
 * (Salsa20 and ChaCha20 are symmetric in CTR mode - same operation for enc/dec)
 * 
 * @param plaintext Input plaintext/ciphertext
 * @param plen      Length of input data
 * @param key       32-byte key
 * @param nonce     64-bit nonce
 * @param counter   32-bit starting counter value
 * @param algo      "salsa20" or "chacha20"
 * @param ciphertext Output buffer (at least plen bytes)
 */
void stream_ctr_crypt(const uint8_t *plaintext, size_t plen,
                     const uint8_t *key, uint64_t nonce, uint32_t counter,
                     const char *algo, uint8_t *ciphertext);

#endif