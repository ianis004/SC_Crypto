#include "rsa.h"
#include "bignr.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void rsa_genkey(int bits, uint8_t *pub, uint8_t *priv, uint8_t *n_out) {
    BigInt p, q, n, phi, e, d;
    BigInt p_minus_1, q_minus_1;

    bn_init(&p); bn_init(&q); bn_init(&n); bn_init(&phi);
    bn_init(&e); bn_init(&d);
    bn_init(&p_minus_1); bn_init(&q_minus_1);

    // 1. Force clear the output arrays so there is zero stack garbage
    memset(n_out, 0, 128);
    memset(pub, 0, 128);
    memset(priv, 0, 128);

    bn_rand_prime(&p, bits/2);
    bn_rand_prime(&q, bits/2);
    while (bn_cmp(&p, &q) == 0) bn_rand_prime(&q, bits/2);

    bn_mul(&p, &q, &n);

    BigInt one;
    bn_init(&one);
    one.limbs[0] = 1;
    one.len = 1;

    bn_sub(&p, &one, &p_minus_1);
    bn_sub(&q, &one, &q_minus_1);
    bn_mul(&p_minus_1, &q_minus_1, &phi);

    e.limbs[0] = 65537;
    e.len = 1;

    // 2. Ideally, check if modinv succeeds (returns 1 or non-zero in most libraries)
    bn_modinv(&e, &phi, &d);

    // 3. Safe to export now that buffers are zero-initialized
    bn_to_bytes(&n, n_out);
    bn_to_bytes(&e, pub);
    bn_to_bytes(&d, priv);
}

void rsa_encrypt(const uint8_t *msg, int mlen, const uint8_t *n, const uint8_t *e,
                 uint8_t *out, int olen) {
    BigInt m, exp, mod, res;

    bn_init(&m); bn_init(&exp); bn_init(&mod); bn_init(&res);
    memset(out, 0, olen); // Clear output buffer

    bn_from_bytes(&m, msg, mlen);
    bn_from_bytes(&mod, n, 128);
    bn_from_bytes(&exp, e, 128); // This works perfectly now that e is zero-padded!

    bn_powmod(&m, &exp, &mod, &res);

    bn_to_bytes(&res, out);
}

void rsa_decrypt(const uint8_t *ct, int clen, const uint8_t *n, const uint8_t *d,
                 uint8_t *out, int olen) {
    BigInt c, exp, mod, res;

    bn_init(&c); bn_init(&exp); bn_init(&mod); bn_init(&res);
    memset(out, 0, olen); // Clear output buffer

    bn_from_bytes(&c, ct, clen);
    bn_from_bytes(&mod, n, 128);
    bn_from_bytes(&exp, d, 128);

    bn_powmod(&c, &exp, &mod, &res);

    bn_to_bytes(&res, out);
}