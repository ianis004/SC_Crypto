#ifndef RSA_H
#define RSA_H

#include <stdint.h>

/**
 * Generate a 1024-bit RSA key pair
 * @param bits   Key size in bits (use 1024)
 * @param pub    Output buffer for public exponent e (128 bytes)
 * @param priv   Output buffer for private exponent d (128 bytes)
 * @param n_out  Output buffer for modulus n (128 bytes)
 */
void rsa_genkey(int bits, uint8_t *pub, uint8_t *priv, uint8_t *n_out);

/**
 * RSA Encryption (raw, no padding)
 * @param msg   Plaintext block (max 127 bytes for 1024-bit)
 * @param mlen  Length of plaintext
 * @param n     Modulus (128 bytes)
 * @param e     Public exponent (128 bytes)
 * @param out   Ciphertext buffer (128 bytes)
 * @param olen  Output buffer size
 */
void rsa_encrypt(const uint8_t *msg, int mlen, const uint8_t *n, const uint8_t *e, uint8_t *out, int olen);

/**
 * RSA Decryption (raw, no padding)
 * @param ct    Ciphertext block (128 bytes)
 * @param clen  Length of ciphertext
 * @param n     Modulus (128 bytes)
 * @param d     Private exponent (128 bytes)
 * @param out   Plaintext buffer (128 bytes)
 * @param olen  Output buffer size
 */
void rsa_decrypt(const uint8_t *ct, int clen, const uint8_t *n, const uint8_t *d, uint8_t *out, int olen);

#endif