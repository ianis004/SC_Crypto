#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "salsa20.h"
#include "chacha20.h"
#include "rsa.h"

#define CHUNK_SIZE (1024 * 1024)

int main(int argc, char *argv[]) {
    char mode = 0;
    const char *infile = NULL, *keyfile = NULL, *outfile = NULL, *algo = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-e") == 0 || strcmp(argv[i], "-d") == 0) {
            mode = argv[i][1];
            if (i + 1 < argc) infile = argv[++i];
        } else if (strcmp(argv[i], "-k") == 0) {
            if (i + 1 < argc) keyfile = argv[++i];
        } else if (strcmp(argv[i], "-o") == 0) {
            if (i + 1 < argc) outfile = argv[++i];
        } else if (strcmp(argv[i], "-a") == 0) {
            if (i + 1 < argc) algo = argv[++i];
        }
    }

    if (mode == 0 || infile == NULL || keyfile == NULL || outfile == NULL || algo == NULL) {
        fprintf(stderr, "Missing arguments\n");
        fprintf(stderr, "Usage: crypto -e|-d <input> -k <keyfile> -o <output> -a <algorithm>\n");
        return 1;
    }

    FILE *fin = fopen(infile, "rb");
    FILE *fout = fopen(outfile, "wb");
    FILE *fkey = fopen(keyfile, "rb");
    if (!fin || !fout || !fkey) {
        perror("File open error");
        return 1;
    }

    if (strcmp(algo, "salsa20") == 0 || strcmp(algo, "chacha20") == 0) {
        uint8_t key[32];
        if (fread(key, 1, 32, fkey) != 32) {
            fprintf(stderr, "Invalid key file (must be exactly 32 bytes)\n");
            return 1;
        }
        uint64_t nonce = 0x0102030405060708ULL;
        uint8_t buf[CHUNK_SIZE], ks[64];
        uint32_t block_ctr = 0;
        size_t n;

        while ((n = fread(buf, 1, CHUNK_SIZE, fin)) > 0) {
            for (size_t i = 0; i < n; i++) {
                if (i % 64 == 0) {
                    if (strcmp(algo, "salsa20") == 0) salsa20_init(key, nonce, block_ctr);
                    else chacha20_init(key, nonce, block_ctr);

                    if (strcmp(algo, "salsa20") == 0) salsa20_keystream(ks);
                    else chacha20_keystream(ks);

                    block_ctr++;
                }
                buf[i] ^= ks[i % 64];
            }
            fwrite(buf, 1, n, fout);
        }
    } else if (strcmp(algo, "rsa") == 0) {
        uint8_t n[128], e[128], d[128];
        if (fread(n, 1, 128, fkey) != 128 ||
            fread(e, 1, 128, fkey) != 128 ||
            fread(d, 1, 128, fkey) != 128) {
            fprintf(stderr, "Invalid RSA key file (must be 384 bytes: n, e, d)\n");
            return 1;
        }
        uint8_t block[127], out[128];
        size_t nread;
        while ((nread = fread(block, 1, 127, fin)) > 0) {
            if (mode == 'e') rsa_encrypt(block, (int)nread, n, e, out, 128);
            else rsa_decrypt(block, (int)nread, n, d, out, 128);
            fwrite(out, 1, 128, fout);
        }
    } else {
        fprintf(stderr, "Unknown algorithm: %s\n", algo);
        return 1;
    }

    fclose(fin); fclose(fout); fclose(fkey);
    printf("Done. %s %s -> %s\n", mode == 'e' ? "Encrypted" : "Decrypted", infile, outfile);
    return 0;
}

// check if code works ".\cmake-build-debug\Latino_encrypt.exe -e plaintext.txt -k key.bin -o output.enc -a salsa20"
// run code :