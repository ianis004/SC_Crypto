#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
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
        printf("Generating 1024-bit RSA key\n");
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
        if(fin) fclose(fin);
        if(fout) fclose(fout);
        if(fkey) fclose(fkey);
        return 1;
    }

    if (strcmp(algo, "salsa20") == 0 || strcmp(algo, "chacha20") == 0) {
        uint8_t key[32];
        if (fread(key, 1, 32, fkey) != 32) {
            fprintf(stderr, "Invalid key file (must be exactly 32 bytes)\n");
            fclose(fin); fclose(fout); fclose(fkey);
            return 1;
        }

        uint64_t nonce = 0x0102030405060708ULL;
        uint32_t block_ctr = 0;
        size_t nread;

        uint8_t *buf = malloc(CHUNK_SIZE);
        uint8_t *outbuf = malloc(CHUNK_SIZE);
        if (!buf || !outbuf) {
            fprintf(stderr, "Memory allocation failed\n");
            return 1;
        }

        while ((nread = fread(buf, 1, CHUNK_SIZE, fin)) > 0) {
            stream_ctr_crypt(buf, nread, key, nonce, block_ctr, algo, outbuf);
            fwrite(outbuf, 1, nread, fout);
            block_ctr += (nread + 63) / 64;
        }

        free(buf);
        free(outbuf);

    } else if (strcmp(algo, "rsa") == 0) {
        uint8_t n[128], e[128], d[128];
        if (fread(n, 1, 128, fkey) != 128 || fread(e, 1, 128, fkey) != 128 || fread(d, 1, 128, fkey) != 128) {
            fprintf(stderr, "Invalid RSA key file (must be 384 bytes)\n");
            fclose(fin); fclose(fout); fclose(fkey);
            return 1;
        }

        uint8_t block[128], out[128];
        size_t nread;

        if (mode == 'e') {
            while ((nread = fread(block, 1, 126, fin)) > 0) {
                rsa_encrypt(block, (int)nread, n, e, out, 128);
                fwrite(out, 1, 128, fout);
            }
        } else {
            while ((nread = fread(block, 1, 128, fin)) > 0) {
                uint8_t decrypted[128];
                memset(decrypted, 0, 128);
                rsa_decrypt(block, (int)nread, n, d, decrypted, 128);

                int original_len = decrypted[0];
                if (original_len < 0 || original_len > 126) original_len = 127;

                if (original_len > 0) fwrite(&decrypted[1], 1, original_len, fout);
            }
        }

    } else if (strcmp(algo, "hybrid") == 0) {
        uint8_t n[128], e[128], d[128];
        if (fread(n, 1, 128, fkey) != 128 || fread(e, 1, 128, fkey) != 128 || fread(d, 1, 128, fkey) != 128) {
            fprintf(stderr, "Invalid RSA key file for hybrid mode (must be 384 bytes)\n");
            fclose(fin); fclose(fout); fclose(fkey);
            return 1;
        }

        uint64_t nonce = 0x0102030405060708ULL;
        uint32_t block_ctr = 0;
        size_t nread;

        uint8_t *buf = malloc(CHUNK_SIZE);
        uint8_t *outbuf = malloc(CHUNK_SIZE);
        if (!buf || !outbuf) {
            fprintf(stderr, "Memory allocation failed\n");
            return 1;
        }

        if (mode == 'e') {
            uint8_t session_key[32];
            srand((unsigned int)time(NULL));
            for (int i = 0; i < 32; i++) session_key[i] = rand() & 0xFF;

            uint8_t encrypted_key[128];
            rsa_encrypt(session_key, 32, n, e, encrypted_key, 128);
            fwrite(encrypted_key, 1, 128, fout);

            while ((nread = fread(buf, 1, CHUNK_SIZE, fin)) > 0) {
                stream_ctr_crypt(buf, nread, session_key, nonce, block_ctr, "salsa20", outbuf);
                fwrite(outbuf, 1, nread, fout);
                block_ctr += (nread + 63) / 64;
            }
        } else {
            uint8_t encrypted_key[128];
            if (fread(encrypted_key, 1, 128, fin) != 128) {
                fprintf(stderr, "File too small or missing header\n");
                free(buf); free(outbuf); fclose(fin); fclose(fout); fclose(fkey);
                return 1;
            }
            uint8_t decrypted_key_buffer[128];
            memset(decrypted_key_buffer, 0, 128);
            rsa_decrypt(encrypted_key, 128, n, d, decrypted_key_buffer, 128);

            uint8_t session_key[32];
            memcpy(session_key, &decrypted_key_buffer[1], 32);

            while ((nread = fread(buf, 1, CHUNK_SIZE, fin)) > 0) {
                stream_ctr_crypt(buf, nread, session_key, nonce, block_ctr, "salsa20", outbuf);
                fwrite(outbuf, 1, nread, fout);
                block_ctr += (nread + 63) / 64;
            }

        }

        free(buf);
        free(outbuf);

    } else {
        fprintf(stderr, "Unknown algorithm: %s\n", algo);
        fclose(fin); fclose(fout); fclose(fkey);
        return 1;
    }

    fclose(fin);
    fclose(fout);
    fclose(fkey);
    printf("%s %s -> %s using %s\n", mode == 'e' ? "Encrypted" : "Decrypted", infile, outfile, algo);
    return 0;
}

// Generate key: $by[byte[]]::new(32); [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes); [System.IO.File]::WriteAllBytes("key.bin", $bytes)tes =
// Encrypt: .\cmake-build-debug\Latino_encrypt.exe -e plaintext.txt -k key.bin -o output.enc -a salsa20
// Decrypt: .\cmake-build-debug\Latino_encrypt.exe -d output.enc -k key.bin -o decrypted.txt -a salsa20
//
// Generate RSA keys and encrypt/decrypt with:
// .\cmake-build-debug\Latino_encrypt -g -k rsa_key.bin -a rsa
// .\cmake-build-debug\Latino_encrypt -e plaintext.txt -k rsa_key.bin -o output.enc -a rsa
// .\cmake-build-debug\Latino_encrypt -d output.enc -k rsa_key.bin -o decrypted.txt -a rsa
// Compare the texts : Compare-Object (Get-Content .\plaintext.txt) (Get-Content .\decrypted.txt)
// 5mb test
// .\cmake-build-debug\Latino_encrypt.exe -g -k rsa_key.bin -a rsa
// Measure-Command { .\cmake-build-debug\Latino_encrypt.exe -e test_5mb.bin -k rsa_key.bin -o test_5mb_rsa.enc -a rsa }
// Measure-Command { .\cmake-build-debug\Latino_encrypt.exe -d test_5mb_rsa.enc -k rsa_key.bin -o test_5mb_rsa.dec -a rsa }
// Get-FileHash .\test_5mb.bin, .\test_5mb_rsa.dec
// .\cmake-build-debug\Latino_encrypt -e test_5mb.bin -k rsa_key.bin -o test_5mb_rsa.enc -a hybrid
// .\cmake-build-debug\Latino_encrypt -d test_5mb_rsa.enc  -k rsa_key.bin -o test_5mb_rsa.dec -a hybrid

//4gb test
// Measure-Command { .\cmake-build-debug\Latino_encrypt.exe -e test_4gb.bin -k key.bin -o test_4gb.enc -a chacha20 }
// Measure-Command { .\cmake-build-debug\Latino_encrypt.exe -d test_4gb.enc -k key.bin -o test_4gb.dec -a chacha20 }
// Get-FileHash .\test_4gb.bin, .\test_4gb.dec
