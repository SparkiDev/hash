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

/** The length of the BLAKE2b-224 digest output. */
#define HASH_BLAKE2B_224_LEN	28
/** The length of the BLAKE2b-256 digest output. */
#define HASH_BLAKE2B_256_LEN	32
/** The length of the BLAKE2b-384 digest output. */
#define HASH_BLAKE2B_384_LEN	48
/** The length of the BLAKE2b-512 digest output. */
#define HASH_BLAKE2B_512_LEN	64

/** Data structure for BLAKE2b */
typedef struct hash_blake2b_st
{
    /** Cached message data. */
    uint8_t b[128];
    /** Chained state. */
    uint64_t h[8];
    /** Number of bytes seen. */
    uint64_t n[2];
    /** Current index in cache. */
    uint8_t i;
} HASH_BLAKE2B;

int hash_blake2b_224_init(HASH_BLAKE2B *ctx);
int hash_blake2b_256_init(HASH_BLAKE2B *ctx);
int hash_blake2b_384_init(HASH_BLAKE2B *ctx);
int hash_blake2b_512_init(HASH_BLAKE2B *ctx);
int hash_blake2b_224_mac_init(HASH_BLAKE2B *ctx, const void *key, size_t len);
int hash_blake2b_256_mac_init(HASH_BLAKE2B *ctx, const void *key, size_t len);
int hash_blake2b_384_mac_init(HASH_BLAKE2B *ctx, const void *key, size_t len);
int hash_blake2b_512_mac_init(HASH_BLAKE2B *ctx, const void *key, size_t len);
int hash_blake2b_update(HASH_BLAKE2B *ctx, const void *in, size_t len);
int hash_blake2b_224_final(void *out, HASH_BLAKE2B *ctx);
int hash_blake2b_256_final(void *out, HASH_BLAKE2B *ctx);
int hash_blake2b_384_final(void *out, HASH_BLAKE2B *ctx);
int hash_blake2b_512_final(void *out, HASH_BLAKE2B *ctx);

