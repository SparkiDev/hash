/*
 * Copyright (c) 2016 Sean Parkinson (sparkinson@iprimus.com.au)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdlib.h>
#include <stdint.h>

/** The length of the SHA3-224 digest output. */
#define HASH_SHA3_224_LEN	28
/** The length of the SHA3-256 digest output. */
#define HASH_SHA3_256_LEN	32
/** The length of the SHA3-384 digest output. */
#define HASH_SHA3_384_LEN	48
/** The length of the SHA3-512 digest output. */
#define HASH_SHA3_512_LEN	64

/** The SHA-3 hash algorithm data. */
typedef struct hash_sha3_t
{
    /** State data that is processed for each block. */
    uint64_t s[25];
    /** Unprocessed message data. */
    uint8_t t[200];
    /** Index into unprocessed data to place next message byte. */
    uint8_t i;
} HASH_SHA3;

int hash_sha3_init(HASH_SHA3 *ctx);
int hash_sha3_224_mac_init(HASH_SHA3 *ctx, const uint8_t *key, size_t len);
int hash_sha3_224_update(HASH_SHA3 *ctx, const uint8_t *data, size_t len);
int hash_sha3_224_final(unsigned char *md, HASH_SHA3 *ctx);
int hash_sha3_256_mac_init(HASH_SHA3 *ctx, const uint8_t *key, size_t len);
int hash_sha3_256_update(HASH_SHA3 *ctx, const uint8_t *data, size_t len);
int hash_sha3_256_final(unsigned char *md, HASH_SHA3 *ctx);
int hash_sha3_384_mac_init(HASH_SHA3 *ctx, const uint8_t *key, size_t len);
int hash_sha3_384_update(HASH_SHA3 *ctx, const uint8_t *data, size_t len);
int hash_sha3_384_final(unsigned char *md, HASH_SHA3 *ctx);
int hash_sha3_512_mac_init(HASH_SHA3 *ctx, const uint8_t *key, size_t len);
int hash_sha3_512_update(HASH_SHA3 *ctx, const uint8_t *data, size_t len);
int hash_sha3_512_final(unsigned char *md, HASH_SHA3 *ctx);

int hash_shake128(uint8_t *h, uint64_t l, const uint8_t *m, uint64_t n);
int hash_shake256(uint8_t *h, uint64_t l, const uint8_t *m, uint64_t n);
int hash_sha3_224(uint8_t *h, const uint8_t *m, uint64_t n);
int hash_sha3_256(uint8_t *h, const uint8_t *m, uint64_t n);
int hash_sha3_384(uint8_t *h, const uint8_t *m, uint64_t n);
int hash_sha3_512(uint8_t *h, const uint8_t *m, uint64_t n);

