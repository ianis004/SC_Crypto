#ifndef RSA_H
#define RSA_H

#include <stdint.h>

void rsa_genkey(int bits, uint8_t *pub, uint8_t *priv, uint8_t *n_out);

void rsa_encrypt(const uint8_t *msg, int mlen, const uint8_t *n, const uint8_t *e,
                 uint8_t *out, int olen);

void rsa_decrypt(const uint8_t *ct, int clen, const uint8_t *n, const uint8_t *d,
                 uint8_t *out, int olen);

#endif