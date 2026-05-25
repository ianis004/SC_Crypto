#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "salsa20.h"
#include "chacha20.h"
#include "stream_modes.h"
#include "rsa.h"

#define CHUNK_SIZE (1024 * 1024)

int main(int argc, char *argv[]) {
    char mode = 0;
    const char *infile = NULL, *keyfile = NULL, *outfile = NULL, *algo = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-e") == 0 || strcmp(argv[i], "-d") == 0) {
            mode = argv[i][1];
            if (i + 1 < argc) infile = argv[++i];
        } else if (strcmp(argv[i], "-g") == 0) {
            mode = 'g';
        } else if (strcmp(argv[i], "-k") == 0) {
            if (i + 1 < argc) keyfile = argv[++i];
        } else if (strcmp(argv[i], "-o") == 0) {
            if (i + 1 < argc) outfile = argv[++i];
        } else if (strcmp(argv[i], "-a") == 0) {
            if (i + 1 < argc) algo = argv[++i];
        }
    }

    if (mode == 0 || algo == NULL || keyfile == NULL || (mode != 'g' && (infile == NULL || outfile == NULL))) {
        fprintf(stderr, "Missing arguments\n");
        fprintf(stderr, "Usage for Enc/Dec: crypto -e|-d <input> -o <output> -k <keyfile> -a <algorithm>\n");
        fprintf(stderr, "Usage for RSA Keygen: crypto -g -k <output_keyfile> -a rsa\n");
        return 1;
    }

    if (mode == 'g') {
        if (strcmp(algo, "rsa") != 0) {
            fprintf(stderr, "Key generation is only supported for rsa algorithm in this mode.\n");
            return 1;
        }
        uint8_t e[128], d[128], n[128];
        printf("Generating 1024-bit RSA key pair\n");
        rsa_genkey(1024, e, d, n);
        FILE *fkey_out = fopen(keyfile, "wb");
        if (!fkey_out) {
            perror("Failed to create key file");
            return 1;
        }
        fwrite(n, 1, 128, fkey_out);
        fwrite(e, 1, 128, fkey_out);
        fwrite(d, 1, 128, fkey_out);
        fclose(fkey_out);

        printf("Combined RSA key saved to: %s (384 bytes)\n", keyfile);
        return 0;
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
            fclose(fin);
            fclose(fout);
            fclose(fkey);
            return 1;
        }

        uint64_t nonce = 0x0102030405060708ULL;
        uint8_t buf[CHUNK_SIZE], outbuf[CHUNK_SIZE];
        uint32_t block_ctr = 0;
        size_t n;

        while ((n = fread(buf, 1, CHUNK_SIZE, fin)) > 0) {
            stream_ctr_crypt(buf, n, key, nonce, block_ctr, algo, outbuf);
            fwrite(outbuf, 1, n, fout);
            block_ctr += (n + 63) / 64;
        }
    } else if (strcmp(algo, "rsa") == 0) {
        uint8_t n[128], e[128], d[128];
        if (fread(n, 1, 128, fkey) != 128 ||
            fread(e, 1, 128, fkey) != 128 ||
            fread(d, 1, 128, fkey) != 128) {
            fprintf(stderr, "Invalid RSA key file (must be 384 bytes)\n");
            fclose(fin);
            fclose(fout);
            fclose(fkey);
            return 1;
        }

        uint8_t block[128], out[128];
        size_t nread;

        if (mode == 'e') {
            while ((nread = fread(block, 1, 127, fin)) > 0) {
                rsa_encrypt(block, (int)nread, n, e, out, 128);
                fwrite(out, 1, 128, fout);
            }
        } else {
            // RSA decryption: read 128 bytes, decrypt, write actual message length
            while ((nread = fread(block, 1, 128, fin)) > 0) {
                uint8_t decrypted[128];
                rsa_decrypt(block, (int)nread, n, d, decrypted, 128);

                // First byte contains the original message length
                uint8_t msg_len = decrypted[0];
                if (msg_len > 126) msg_len = 126;  // Safety check

                // Write only the actual message bytes
                fwrite(decrypted + 1, 1, msg_len, fout);
            }
        }
    } else {
        fprintf(stderr, "Unknown algorithm: %s\n", algo);
        fclose(fin);
        fclose(fout);
        fclose(fkey);
        return 1;
    }

    fclose(fin);
    fclose(fout);
    fclose(fkey);
    printf("Done. %s %s -> %s using %s\n",
           mode == 'e' ? "Encrypted" : "Decrypted", infile, outfile, algo);
    return 0;
}

// Generate key: $bytes = [byte[]]::new(32); [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes); [System.IO.File]::WriteAllBytes("key.bin", $bytes)
// Encrypt: .\cmake-build-debug\Latino_encrypt.exe -e plaintext.txt -k key.bin -o output.enc -a salsa20
// Decrypt: .\cmake-build-debug\Latino_encrypt.exe -d output.enc -k key.bin -o decrypted.txt -a salsa20
//
// Generate RSA keys and encrypt/decrypt with:
// .\cmake-build-debug\Latino_encrypt.exe -g -k rsa_key.bin -a rsa
// .\cmake-build-debug\Latino_encrypt.exe -e plaintext.txt -k rsa_key.bin -o output.enc -a rsa
// .\cmake-build-debug\Latino_encrypt.exe -d output.enc -k rsa_key.bin -o decrypted.txt -a rsa
// Compare the texts : Compare-Object (Get-Content .\plaintext.txt) (Get-Content .\decrypted.txt)
//if this returns nothing yu are good