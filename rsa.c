#include "rsa.h"
#include "bignr.h"
#include <stdio.h>
#include <stdlib.h>

void rsa_genkey(int bits, uint8_t *pub, uint8_t *priv, uint8_t *n_out) {
    BigInt p, q, n, phi, e, d;
    bn_init(&p); bn_init(&q); bn_init(&n); bn_init(&phi);
    bn_init(&e); bn_init(&d);
    
    bn_rand_prime(&p, bits/2);
    bn_rand_prime(&q, bits/2);
    while (bn_cmp(&p, &q) == 0) bn_rand_prime(&q, bits/2);
    
    bn_mul(&p, &q, &n);
    bn_sub(&p, &(BigInt){.limbs={1}, .len=1}, &p); // p-1
    bn_sub(&q, &(BigInt){.limbs={1}, .len=1}, &q); // q-1
    bn_mul(&p, &q, &phi);
    
    e.limbs[0] = 65537; e.len = 1;
    bn_modinv(&e, &phi, &d);
    
    bn_to_bytes(&n, n_out);
    bn_to_bytes(&e, pub);
    bn_to_bytes(&d, priv);
}

void rsa_encrypt(const uint8_t *msg, int mlen, const uint8_t *n, const uint8_t *e, uint8_t *out, int olen) {
    BigInt m, exp, mod, res;
    bn_from_bytes(&m, msg, mlen);
    bn_from_bytes(&mod, n, 128);
    bn_from_bytes(&exp, e, 128);
    bn_powmod(&m, &exp, &mod, &res);
    bn_to_bytes(&res, out);
}

void rsa_decrypt(const uint8_t *ct, int clen, const uint8_t *n, const uint8_t *d, uint8_t *out, int olen) {
    BigInt c, exp, mod, res;
    bn_from_bytes(&c, ct, clen);
    bn_from_bytes(&mod, n, 128);
    bn_from_bytes(&exp, d, 128);
    bn_powmod(&c, &exp, &mod, &res);
    bn_to_bytes(&res, out);
}