#ifndef BIGNR_H
#define BIGNR_H
#include <stdint.h>
#include <string.h>

#define BN_MAX_LIMBS 32

typedef struct {
    uint64_t limbs[BN_MAX_LIMBS];
    int len;
} BigInt;

void bn_init(BigInt *a);
void bn_from_bytes(BigInt *a, const uint8_t *data, int len);
void bn_to_bytes(const BigInt *a, uint8_t *out);
void bn_add(const BigInt *a, const BigInt *b, BigInt *res);
void bn_sub(const BigInt *a, const BigInt *b, BigInt *res);
void bn_mul(const BigInt *a, const BigInt *b, BigInt *res);
void bn_mod(const BigInt *a, const BigInt *m, BigInt *res);
void bn_powmod(const BigInt *base, const BigInt *exp, const BigInt *mod, BigInt *res);
int bn_cmp(const BigInt *a, const BigInt *b);
int bn_is_zero(const BigInt *a);
int bn_rand_prime(BigInt *p, int bits);
int bn_gcd(const BigInt *a, const BigInt *b, BigInt *res);
int bn_modinv(const BigInt *a, const BigInt *m, BigInt *res);

#endif