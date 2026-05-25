#include "stream_modes.h"
#include "salsa20.h"
#include "chacha20.h"
#include <string.h>

void stream_ctr_crypt(const uint8_t *plaintext, size_t plen,
                     const uint8_t *key, uint64_t nonce, uint32_t counter,
                     const char *algo, uint8_t *ciphertext) {
    uint8_t keystream[64];
    size_t bytes_processed = 0;
    uint32_t current_counter = counter;
    
    while (bytes_processed < plen) {
        size_t remaining = plen - bytes_processed;
        size_t to_process = (remaining > 64) ? 64 : remaining;

        if (strcmp(algo, "salsa20") == 0) {
            salsa20_init((uint8_t*)key, nonce, current_counter);
            salsa20_keystream(keystream);
        } else if (strcmp(algo, "chacha20") == 0) {
            chacha20_init((uint8_t*)key, nonce, current_counter);
            chacha20_keystream(keystream);
        } else {
            return;
        }

        for (size_t i = 0; i < to_process; i++) {
            ciphertext[bytes_processed + i] = plaintext[bytes_processed + i] ^ keystream[i];
        }
        
        bytes_processed += to_process;
        current_counter++;
    }
}