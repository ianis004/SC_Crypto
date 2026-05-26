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

    bn_modinv(&e, &phi, &d);

    bn_to_bytes(&n, n_out);
    bn_to_bytes(&e, pub);
    bn_to_bytes(&d, priv);
}

void rsa_encrypt(const uint8_t *msg, int mlen, const uint8_t *n, const uint8_t *e,
                 uint8_t *out, int olen) {
    BigInt m, exp, mod, res;

    bn_init(&m); bn_init(&exp); bn_init(&mod); bn_init(&res);
    memset(out, 0, olen);

    /*
     * Plaintext layout (127 bytes, big-endian via bn_from_bytes):
     *   padded[0]         = mlen   (length prefix, becomes MSB of the 127-byte number)
     *   padded[1..mlen]   = msg
     *   padded[mlen+1..126] = 0x00 (zero padding)
     *
     * After bn_to_bytes on decrypt the 128-byte output is:
     *   temp[0] = 0x00  (leading zero — m < 2^(127*8) < n, so the 128th byte is always 0)
     *   temp[1] = mlen
     *   temp[2..mlen+1] = msg
     */
    uint8_t padded[128];
    memset(padded, 0, 128);
    padded[0] = (uint8_t)mlen;
    if (mlen > 0)
        memcpy(&padded[1], msg, mlen);

    bn_from_bytes(&m, padded, 127);   /* 127 bytes keeps m < 2^1016 < n */
    bn_from_bytes(&mod, n, 128);
    bn_init(&exp);
    exp.limbs[0] = 65537;
    exp.len = 1;

    bn_powmod(&m, &exp, &mod, &res);
    bn_to_bytes(&res, out);
}

void rsa_decrypt(const uint8_t *ct, int clen, const uint8_t *n, const uint8_t *d,
                 uint8_t *out, int olen) {
    BigInt c, exp, mod, res;

    bn_init(&c); bn_init(&exp); bn_init(&mod); bn_init(&res);
    memset(out, 0, olen);

    bn_from_bytes(&c, ct, clen);
    bn_from_bytes(&mod, n, 128);
    bn_from_bytes(&exp, d, 128);

    bn_powmod(&c, &exp, &mod, &res);

    uint8_t temp[128];
    memset(temp, 0, 128);
    bn_to_bytes(&res, temp);

    /*
     * bn_to_bytes always produces 128 big-endian bytes.
     * Because m was encoded from 127 bytes, m < 2^(127*8), so:
     *   temp[0] = 0x00  (the 128th byte is always zero)
     *   temp[1] = mlen  (was padded[0] in rsa_encrypt)
     *   temp[2..] = original message bytes
     *
     * main.c treats out[0] as the length byte, so copy temp[1..127] → out[0..126].
     */
    int copy_len = (olen > 127) ? 127 : olen;
    memcpy(out, &temp[1], copy_len);
}