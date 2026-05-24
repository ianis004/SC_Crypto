#include "chacha20.h"
#include <string.h>

static uint32_t state[16];

static uint32_t rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

void chacha20_init(uint8_t key[32], uint64_t nonce, uint32_t counter) {
    uint32_t k[8];
    for(int i=0;i<8;i++) k[i] = (uint32_t)key[4*i] | ((uint32_t)key[4*i+1]<<8) | ((uint32_t)key[4*i+2]<<16) | ((uint32_t)key[4*i+3]<<24);
    uint32_t n[2] = { (uint32_t)nonce, (uint32_t)(nonce >> 32) };
    state[0]=0x61707865; state[1]=0x3320646e; state[2]=0x79622d36; state[3]=0x6b206574;
    state[4]=k[0]; state[5]=k[1]; state[6]=k[2]; state[7]=k[3];
    state[8]=k[4]; state[9]=k[5]; state[10]=k[6]; state[11]=k[7];
    state[12]=counter; state[13]=0x00000000; state[14]=n[0]; state[15]=n[1];
}

static void chacha20_quarter(uint32_t *y, int a, int b, int c, int d) {
    y[a] += y[b]; y[d] = rotl32(y[d] ^ y[a], 16);
    y[c] += y[d]; y[b] = rotl32(y[b] ^ y[c], 12);
    y[a] += y[b]; y[d] = rotl32(y[d] ^ y[a], 8);
    y[c] += y[d]; y[b] = rotl32(y[b] ^ y[c], 7);
}

void chacha20_keystream(uint8_t out[64]) {
    uint32_t x[16]; memcpy(x, state, sizeof(x));
    for(int i=0;i<10;i++) {
        chacha20_quarter(x, 0,4,8,12); chacha20_quarter(x,1,5,9,13);
        chacha20_quarter(x,2,6,10,14); chacha20_quarter(x,3,7,11,15);
        chacha20_quarter(x,0,5,10,15); chacha20_quarter(x,1,6,11,12);
        chacha20_quarter(x,2,7,8,13); chacha20_quarter(x,3,4,9,14);
    }
    for(int i=0;i<16;i++) x[i] += state[i];
    for(int i=0;i<16;i++) {
        out[4*i] = x[i] & 0xFF;
        out[4*i+1] = (x[i] >> 8) & 0xFF;
        out[4*i+2] = (x[i] >> 16) & 0xFF;
        out[4*i+3] = (x[i] >> 24) & 0xFF;
    }
    state[12]++;
}