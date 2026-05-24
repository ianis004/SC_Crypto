#include "salsa20.h"
#include <string.h>

static uint32_t state[16];

static uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

void salsa20_init(uint8_t key[32], uint64_t nonce, uint32_t counter) {
    uint32_t k[8];
    for(int i = 0; i < 8; i++) {
        k[i] = (uint32_t)key[4*i] |
               ((uint32_t)key[4*i+1] << 8) |
               ((uint32_t)key[4*i+2] << 16) |
               ((uint32_t)key[4*i+3] << 24);
    }

    uint32_t n[2] = { (uint32_t)nonce, (uint32_t)(nonce >> 32) };

    state[0] = 0x61707865;
    state[1] = k[0];
    state[2] = k[1];
    state[3] = k[2];
    state[4] = k[3];
    state[5] = 0x3320646e;
    state[6] = n[0];
    state[7] = n[1];
    state[8] = counter;
    state[9] = 0x79622d32;
    state[10] = k[4];
    state[11] = k[5];
    state[12] = k[6];
    state[13] = k[7];
    state[14] = 0x6b206574;
    state[15] = 0x1e33926e;
}

static void salsa20_quarter(uint32_t *y, int a, int b, int c, int d) {
    y[b] ^= rotl32(y[a] + y[d], 7);
    y[c] ^= rotl32(y[b] + y[a], 9);
    y[d] ^= rotl32(y[c] + y[b], 13);
    y[a] ^= rotl32(y[d] + y[c], 18);
}

void salsa20_keystream(uint8_t out[64]) {
    uint32_t x[16];
    memcpy(x, state, sizeof(x));

    for(int i = 0; i < 10; i++) {

        salsa20_quarter(x, 0, 4, 8, 12);
        salsa20_quarter(x, 5, 9, 13, 1);
        salsa20_quarter(x, 10, 14, 2, 6);
        salsa20_quarter(x, 15, 3, 7, 11);


        salsa20_quarter(x, 0, 1, 2, 3);
        salsa20_quarter(x, 5, 6, 7, 4);
        salsa20_quarter(x, 10, 11, 8, 9);
        salsa20_quarter(x, 15, 12, 13, 14);
    }

    for(int i = 0; i < 16; i++) {
        x[i] += state[i];
    }

    for(int i = 0; i < 16; i++) {
        out[4*i]     = x[i] & 0xFF;
        out[4*i + 1] = (x[i] >> 8) & 0xFF;
        out[4*i + 2] = (x[i] >> 16) & 0xFF;
        out[4*i + 3] = (x[i] >> 24) & 0xFF;
    }

    state[8]++;
    if(state[8] == 0) {
        state[9]++;
    }
}