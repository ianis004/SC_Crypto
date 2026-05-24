#include "bignr.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define LIMB_BITS 64

void bn_init(BigInt *a) {
    memset(a->limbs, 0, sizeof(a->limbs));
    a->len = 1;
}

static int bn_set_bit(BigInt *a, int bit, int val) {
    int limb = bit / LIMB_BITS;
    int idx = bit % LIMB_BITS;
    if (val) a->limbs[limb] |= (1ULL << idx);
    else a->limbs[limb] &= ~(1ULL << idx);
    return 0;
}

void bn_from_bytes(BigInt *a, const uint8_t *data, int len) {
    bn_init(a);
    int nlimbs = (len + 7) / 8;
    a->len = nlimbs > BN_MAX_LIMBS ? BN_MAX_LIMBS : nlimbs;
    memset(a->limbs, 0, sizeof(uint64_t) * a->len);
    for (int i = 0; i < len; i++) {
        int byte_idx = len - 1 - i;
        int limb = byte_idx / 8;
        int shift = (byte_idx % 8) * 8;
        if (limb < a->len) a->limbs[limb] |= ((uint64_t)data[i]) << shift;
    }
}

void bn_to_bytes(const BigInt *a, uint8_t *out) {
    for (int i = 0; i < BN_MAX_LIMBS; i++) out[i] = 0;
    for (int i = 0; i < a->len; i++) {
        for (int j = 0; j < 8; j++) {
            out[(a->len - 1 - i) * 8 + j] = (a->limbs[i] >> (j * 8)) & 0xFF;
        }
    }
}

int bn_cmp(const BigInt *a, const BigInt *b) {
    if (a->len > b->len) return 1;
    if (a->len < b->len) return -1;
    for (int i = a->len - 1; i >= 0; i--) {
        if (a->limbs[i] > b->limbs[i]) return 1;
        if (a->limbs[i] < b->limbs[i]) return -1;
    }
    return 0;
}

int bn_is_zero(const BigInt *a) {
    for (int i = 0; i < a->len; i++) if (a->limbs[i]) return 0;
    return 1;
}

void bn_add(const BigInt *a, const BigInt *b, BigInt *res) {
    bn_init(res);
    int max = a->len > b->len ? a->len : b->len;
    uint64_t carry = 0;
    for (int i = 0; i < max; i++) {
        uint64_t s = (i < a->len ? a->limbs[i] : 0) + (i < b->len ? b->limbs[i] : 0) + carry;
        res->limbs[i] = s;
        carry = (s < (i < a->len ? a->limbs[i] : 0));
    }
    if (carry) { res->limbs[max] = carry; res->len = max + 1; }
    else res->len = max;
}

void bn_sub(const BigInt *a, const BigInt *b, BigInt *res) {
    bn_init(res);
    uint64_t borrow = 0;
    int max = a->len;
    for (int i = 0; i < max; i++) {
        uint64_t x = a->limbs[i];
        uint64_t y = i < b->len ? b->limbs[i] : 0;
        uint64_t diff = x - y - borrow;
        borrow = (x < y + borrow);
        res->limbs[i] = diff;
    }
    res->len = max;
    while (res->len > 1 && res->limbs[res->len - 1] == 0) res->len--;
}

void bn_mul(const BigInt *a, const BigInt *b, BigInt *res) {
    bn_init(res);
    res->len = a->len + b->len;
    memset(res->limbs, 0, sizeof(uint64_t) * res->len);
    for (int i = 0; i < a->len; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < b->len; j++) {
            unsigned __int128 prod = (unsigned __int128)a->limbs[i] * b->limbs[j] + res->limbs[i+j] + carry;
            res->limbs[i+j] = (uint64_t)prod;
            carry = (uint64_t)(prod >> 64);
        }
        res->limbs[i + b->len] = carry;
    }
    while (res->len > 1 && res->limbs[res->len - 1] == 0) res->len--;
}

void bn_mod(const BigInt *a, const BigInt *m, BigInt *res) {
    bn_init(res);
    if (bn_is_zero(m)) return;
    if (bn_cmp(a, m) < 0) { memcpy(res, a, sizeof(BigInt)); return; }
    BigInt tmp, q, r;
    bn_init(&tmp); bn_init(&q); bn_init(&r);
    memcpy(&tmp, a, sizeof(BigInt));
    while (bn_cmp(&tmp, m) >= 0) {
        bn_sub(&tmp, m, &r);
        memcpy(&tmp, &r, sizeof(BigInt));
    }
    memcpy(res, &tmp, sizeof(BigInt));
}

void bn_powmod(const BigInt *base, const BigInt *exp, const BigInt *mod, BigInt *res) {
    bn_init(res);
    res->limbs[0] = 1; res->len = 1;
    BigInt b, e;
    memcpy(&b, base, sizeof(BigInt));
    memcpy(&e, exp, sizeof(BigInt));
    while (!bn_is_zero(&e)) {
        if (e.limbs[0] & 1) {
            BigInt t; bn_init(&t);
            bn_mul(res, &b, &t); bn_mod(&t, mod, res);
        }
        bn_mul(&b, &b, &b); bn_mod(&b, mod, &b);
        for (int i = 0; i < e.len; i++) {
            e.limbs[i] >>= 1;
            if (i+1 < e.len) e.limbs[i] |= (e.limbs[i+1] & 1) << 63;
        }
        if (e.len > 1 && e.limbs[e.len-1] == 0) e.len--;
    }
}

int bn_gcd(const BigInt *a, const BigInt *b, BigInt *res) {
    BigInt ta, tb, tmp;
    memcpy(&ta, a, sizeof(BigInt)); memcpy(&tb, b, sizeof(BigInt));
    while (!bn_is_zero(&tb)) {
        bn_mod(&ta, &tb, &tmp);
        memcpy(&ta, &tb, sizeof(BigInt));
        memcpy(&tb, &tmp, sizeof(BigInt));
    }
    memcpy(res, &ta, sizeof(BigInt));
    return !bn_is_zero(res);
}

int bn_egcd(const BigInt *a, const BigInt *b, BigInt *x, BigInt *y) {
    BigInt old_r = *a, r = *b;
    BigInt old_s = {0}, s = {1}, old_t = {1}, t = {0};
    old_s.len = 1; s.len = 1; old_t.len = 1; t.len = 1;
    while (!bn_is_zero(&r)) {
        BigInt q, tmp;
        bn_init(&q); bn_init(&tmp);
        memcpy(&tmp, &old_r, sizeof(BigInt));
        while (bn_cmp(&tmp, &r) >= 0) { bn_sub(&tmp, &r, &q); memcpy(&tmp, &q, sizeof(BigInt)); q.limbs[0]++; if(q.limbs[0]==0)q.len=2;}
        BigInt new_r, new_s, new_t;
        bn_mul(&r, &q, &new_r); bn_sub(&old_r, &new_r, &tmp); memcpy(&new_r, &tmp, sizeof(BigInt));
        bn_mul(&s, &q, &new_s); bn_sub(&old_s, &new_s, &tmp); memcpy(&new_s, &tmp, sizeof(BigInt));
        bn_mul(&t, &q, &new_t); bn_sub(&old_t, &new_t, &tmp); memcpy(&new_t, &tmp, sizeof(BigInt));
        memcpy(&old_r, &r, sizeof(BigInt)); memcpy(&r, &new_r, sizeof(BigInt));
        memcpy(&old_s, &s, sizeof(BigInt)); memcpy(&s, &new_s, sizeof(BigInt));
        memcpy(&old_t, &t, sizeof(BigInt)); memcpy(&t, &new_t, sizeof(BigInt));
    }
    memcpy(x, &old_s, sizeof(BigInt)); memcpy(y, &old_t, sizeof(BigInt));
    return 1;
}

int bn_modinv(const BigInt *a, const BigInt *m, BigInt *res) {
    BigInt x, y;
    bn_egcd(a, m, &x, &y);
    bn_mod(&x, m, res);
    return 1;
}

int bn_rand_prime(BigInt *p, int bits) {
    srand(time(NULL));
    bn_init(p);
    p->len = (bits + 63) / 64;
    for (int i = 0; i < p->len; i++) p->limbs[i] = ((uint64_t)rand() << 32) | rand();
    p->limbs[p->len - 1] |= (1ULL << (bits - 1) % 64);
    p->limbs[0] |= 1;
    return 1;
}