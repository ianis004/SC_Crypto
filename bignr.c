#include "bignr.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static uint64_t rand64(void) {
    // rand() may return only 15 bits (RAND_MAX=32767 on MSVC).
    // 5 calls × 15 bits = 75 bits, enough to fill 64.
    uint64_t r = 0;
    for (int i = 0; i < 5; i++)
        r = (r << 15) | ((uint64_t)(rand() & 0x7FFF));
    return r;
}

#define LIMB_BITS 64

// Miller-Rabin primality test line 276

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

static int bn_get_bit(const BigInt *a, int bit) {
    int limb = bit / LIMB_BITS;
    int idx = bit % LIMB_BITS;
    if (limb >= a->len) return 0;
    return (a->limbs[limb] >> idx) & 1;
}

static int bn_bitlen(const BigInt *a) {
    if (a->len == 0 || bn_is_zero(a)) return 0;

    // Find the true top limb
    int actual_len = a->len;
    while (actual_len > 1 && a->limbs[actual_len - 1] == 0) actual_len--;

    int bits = (actual_len - 1) * LIMB_BITS;
    uint64_t top = a->limbs[actual_len - 1];

    for (int i = 63; i >= 0; i--) {
        if (top & (1ULL << i)) return bits + i + 1;
    }
    return bits;
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

    // FIX: Normalize the length by trimming leading zero limbs
    while (a->len > 1 && a->limbs[a->len - 1] == 0) {
        a->len--;
    }
}

void bn_to_bytes(const BigInt *a, uint8_t *out) {
    memset(out, 0, 128);
    for (int i = 0; i < 128; i++) {
        int byte_idx = 128 - 1 - i;
        int limb = byte_idx / 8;
        int shift = (byte_idx % 8) * 8;
        if (limb < a->len) {
            out[i] = (a->limbs[limb] >> shift) & 0xFF;
        }
    }
}

int bn_cmp(const BigInt *a, const BigInt *b) {
    // Dynamically calculate actual lengths ignoring trailing zeros
    int len_a = a->len;
    while (len_a > 1 && a->limbs[len_a - 1] == 0) len_a--;

    int len_b = b->len;
    // FIX: Changed b_len to len_b
    while (len_b > 1 && b->limbs[len_b - 1] == 0) len_b--;

    if (len_a > len_b) return 1;
    if (len_a < len_b) return -1;

    for (int i = len_a - 1; i >= 0; i--) {
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
        unsigned __int128 s = (unsigned __int128)(i < a->len ? a->limbs[i] : 0) +
                              (i < b->len ? b->limbs[i] : 0) + carry;
        res->limbs[i] = (uint64_t)s;
        carry = (uint64_t)(s >> 64);
    }
    if (carry && max < BN_MAX_LIMBS) {
        res->limbs[max] = carry;
        res->len = max + 1;
    } else {
        res->len = max;
    }
}

void bn_sub(const BigInt *a, const BigInt *b, BigInt *res) {
    bn_init(res);
    uint64_t borrow = 0;
    int max = a->len;
    for (int i = 0; i < max; i++) {
        uint64_t x = a->limbs[i];
        uint64_t y = i < b->len ? b->limbs[i] : 0;
        unsigned __int128 diff = (unsigned __int128)x - y - borrow;
        res->limbs[i] = (uint64_t)diff;
        borrow = (diff >> 127) & 1;
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
    if (bn_cmp(a, m) < 0) {
        memcpy(res, a, sizeof(BigInt));
        return;
    }

    memcpy(res, a, sizeof(BigInt));

    int m_bits = bn_bitlen(m);
    int a_bits = bn_bitlen(res);

    for (int i = a_bits - m_bits; i >= 0; i--) {
        BigInt temp, shifted;
        bn_init(&temp);
        bn_init(&shifted);

        int limb_shift = i / LIMB_BITS;
        int bit_shift = i % LIMB_BITS;

        // Securely shift limbs ensuring we don't breach BN_MAX_LIMBS
        for (int j = m->len - 1; j >= 0; j--) {
            if (j + limb_shift < BN_MAX_LIMBS) {
                shifted.limbs[j + limb_shift] = m->limbs[j];
            }
        }
        // Explicitly set length and cap it safely
        shifted.len = m->len + limb_shift;
        if (shifted.len > BN_MAX_LIMBS) shifted.len = BN_MAX_LIMBS;

        // Securely shift bits
        if (bit_shift > 0) {
            uint64_t carry = 0;
            for (int j = 0; j < shifted.len; j++) {
                uint64_t next_carry = shifted.limbs[j] >> (LIMB_BITS - bit_shift);
                shifted.limbs[j] = (shifted.limbs[j] << bit_shift) | carry;
                carry = next_carry;
            }
            if (carry && shifted.len < BN_MAX_LIMBS) {
                shifted.limbs[shifted.len++] = carry;
            }
        }

        if (bn_cmp(res, &shifted) >= 0) {
            bn_sub(res, &shifted, &temp);
            memcpy(res, &temp, sizeof(BigInt));
        }
    }
}

void bn_powmod(const BigInt *base, const BigInt *exp, const BigInt *mod, BigInt *res) {
    bn_init(res);
    res->limbs[0] = 1;
    res->len = 1;

    BigInt b, e, temp;
    memcpy(&b, base, sizeof(BigInt));
    memcpy(&e, exp, sizeof(BigInt));

    while (!bn_is_zero(&e)) {
        if (e.limbs[0] & 1) {
            bn_mul(res, &b, &temp);
            bn_mod(&temp, mod, res);
        }
        memcpy(&temp, &b, sizeof(BigInt));
        bn_mul(&temp, &temp, &b);
        bn_mod(&b, mod, &temp);
        memcpy(&b, &temp, sizeof(BigInt));

        for (int i = 0; i < e.len; i++) {
            e.limbs[i] >>= 1;
            if (i+1 < e.len) e.limbs[i] |= (e.limbs[i+1] & 1) << 63;
        }
        if (e.len > 1 && e.limbs[e.len-1] == 0) e.len--;
    }
}

int bn_gcd(const BigInt *a, const BigInt *b, BigInt *res) {
    BigInt ta, tb, tmp;
    memcpy(&ta, a, sizeof(BigInt));
    memcpy(&tb, b, sizeof(BigInt));

    while (!bn_is_zero(&tb)) {
        bn_mod(&ta, &tb, &tmp);
        memcpy(&ta, &tb, sizeof(BigInt));
        memcpy(&tb, &tmp, sizeof(BigInt));
    }
    memcpy(res, &ta, sizeof(BigInt));
    return !bn_is_zero(res);
}

// 1. New High-Speed Bit-Shift Division Helper
// 1. New High-Speed Bit-Shift Division Helper
void bn_divmod(const BigInt *a, const BigInt *m, BigInt *num_q, BigInt *num_r) {
    bn_init(num_q);
    bn_init(num_r);
    if (bn_is_zero(m)) return;

    if (bn_cmp(a, m) < 0) {
        memcpy(num_r, a, sizeof(BigInt));
        return;
    }

    memcpy(num_r, a, sizeof(BigInt));

    int m_bits = bn_bitlen(m);
    int a_bits = bn_bitlen(num_r);

    for (int i = a_bits - m_bits; i >= 0; i--) {
        BigInt temp, shifted;
        bn_init(&temp);

        // --- YOUR NEW SAFE SHIFT CODE GOES HERE ---
        bn_init(&shifted);
        int limb_shift = i / LIMB_BITS;
        int bit_shift = i % LIMB_BITS;

        for (int j = m->len - 1; j >= 0; j--) {
            if (j + limb_shift < BN_MAX_LIMBS) {
                shifted.limbs[j + limb_shift] = m->limbs[j];
            }
        }
        shifted.len = m->len + limb_shift;
        if (shifted.len > BN_MAX_LIMBS) shifted.len = BN_MAX_LIMBS;
        // ------------------------------------------

        // Securely shift remaining bits
        if (bit_shift > 0) {
            uint64_t carry = 0;
            for (int j = 0; j < shifted.len; j++) {
                uint64_t next_carry = shifted.limbs[j] >> (LIMB_BITS - bit_shift);
                shifted.limbs[j] = (shifted.limbs[j] << bit_shift) | carry;
                carry = next_carry;
            }
            if (carry && shifted.len < BN_MAX_LIMBS) {
                shifted.limbs[shifted.len++] = carry;
            }
        }

        if (bn_cmp(num_r, &shifted) >= 0) {
            bn_sub(num_r, &shifted, &temp);
            memcpy(num_r, &temp, sizeof(BigInt));

            int q_limb = i / LIMB_BITS;
            int q_bit = i % LIMB_BITS;
            num_q->limbs[q_limb] |= (1ULL << q_bit);
            if (q_limb >= num_q->len) {
                num_q->len = q_limb + 1;
            }
        }
    }
    while (num_q->len > 1 && num_q->limbs[num_q->len - 1] == 0) num_q->len--;
}
// 2. Clear out your old bn_egcd function completely, we can do modular inverse directly and safely here:
int bn_modinv(const BigInt *a, const BigInt *m, BigInt *res) {
    BigInt old_r, r, x0, x1;
    memcpy(&old_r, a, sizeof(BigInt));
    memcpy(&r, m, sizeof(BigInt));

    bn_init(&x0); x0.limbs[0] = 1; x0.len = 1;
    bn_init(&x1);

    int x0_sign = 1; // 1 means positive, 0 means negative
    int x1_sign = 1;

    while (!bn_is_zero(&r)) {
        BigInt q, new_r;
        bn_divmod(&old_r, &r, &q, &new_r);

        BigInt q_x1, new_x;
        bn_init(&q_x1);
        bn_init(&new_x);
        bn_mul(&q, &x1, &q_x1);

        int new_x_sign;
        if (x0_sign == x1_sign) {
            if (bn_cmp(&x0, &q_x1) >= 0) {
                bn_sub(&x0, &q_x1, &new_x);
                new_x_sign = x0_sign;
            } else {
                bn_sub(&q_x1, &x0, &new_x);
                new_x_sign = !x0_sign;
            }
        } else {
            bn_add(&x0, &q_x1, &new_x);
            new_x_sign = x0_sign;
        }

        memcpy(&old_r, &r, sizeof(BigInt));
        memcpy(&r, &new_r, sizeof(BigInt));

        memcpy(&x0, &x1, sizeof(BigInt));
        x0_sign = x1_sign;

        memcpy(&x1, &new_x, sizeof(BigInt));
        x1_sign = new_x_sign;
    }

    BigInt one;
    bn_init(&one); one.limbs[0] = 1; one.len = 1;
    if (bn_cmp(&old_r, &one) != 0) {
        return 0; // Not invertible
    }

    if (x0_sign == 0) {
        bn_sub(m, &x0, res);
    } else {
        bn_mod(&x0, m, res);
    }
    return 1;
}

static int bn_miller_rabin(const BigInt *n, int rounds) {
    if (bn_is_zero(n)) return 0;

    if ((n->limbs[0] & 1) == 0) return n->limbs[0] == 2;

    uint32_t small_primes[] = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37};
    for (int i = 0; i < 12; i++) {
        BigInt p, r;
        bn_init(&p);
        bn_init(&r);
        p.limbs[0] = small_primes[i];
        p.len = 1;
        if (bn_cmp(n, &p) == 0) return 1;
        bn_mod(n, &p, &r);
        if (bn_is_zero(&r)) return 0;
    }

    BigInt n_minus_1, d;
    memcpy(&n_minus_1, n, sizeof(BigInt));
    n_minus_1.limbs[0]--;

    memcpy(&d, &n_minus_1, sizeof(BigInt));
    int r = 0;
    while ((d.limbs[0] & 1) == 0) {
        for (int i = 0; i < d.len; i++) {
            d.limbs[i] >>= 1;
            if (i + 1 < d.len) d.limbs[i] |= (d.limbs[i+1] & 1) << 63;
        }
        r++;
    }

    for (int _ = 0; _ < rounds; _++) {
        BigInt a, x, temp;
        bn_init(&a);
        bn_init(&x);
        bn_init(&temp);

        a.limbs[0] = 2 + (rand64() % 65536);
        a.len = 1;

        bn_powmod(&a, &d, n, &x);

        BigInt one_cmp;
        bn_init(&one_cmp);
        one_cmp.limbs[0] = 1; one_cmp.len = 1;
        if (bn_cmp(&x, &one_cmp) == 0) continue;
        if (bn_cmp(&x, &n_minus_1) == 0) continue;

        int composite = 1;
        for (int i = 0; i < r - 1; i++) {
            bn_mul(&x, &x, &temp);
            bn_mod(&temp, n, &x);
            if (bn_cmp(&x, &n_minus_1) == 0) {
                composite = 0;
                break;
            }
        }

        if (composite) return 0;
    }

    return 1;
}

int bn_rand_prime(BigInt *p, int bits) {
    srand(time(NULL) ^ (rand() << 16));

    for (int attempts = 0; attempts < 100; attempts++) {
        bn_init(p);
        p->len = (bits + 63) / 64;

        for (int i = 0; i < p->len; i++) {
            p->limbs[i] = rand64();
        }

        p->limbs[p->len - 1] |= (1ULL << (bits - 1) % 64);
        p->limbs[0] |= 1;

        if (bn_miller_rabin(p, 40)) {
            return 1;
        }
    }

    return 0;
}