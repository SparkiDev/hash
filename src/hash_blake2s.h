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

#include <stdint.h>
#include <stdlib.h>

/** Data structure for BLAKE2s */
typedef struct hash_blake2s_st
{
    /** Cached message data. */
    uint8_t b[64];
    /** Chained state. */
    uint32_t h[8];
    /** Number of bytes seen. */
    uint32_t n[2];
    /** Current index in cache. */
    uint8_t i;
} HASH_BLAKE2S;

int hash_blake2s_224_init(HASH_BLAKE2S *ctx);
int hash_blake2s_256_init(HASH_BLAKE2S *ctx);
int hash_blake2s_224_mac_init(HASH_BLAKE2S *ctx, const void *key, size_t len);
int hash_blake2s_256_mac_init(HASH_BLAKE2S *ctx, const void *key, size_t len);
int hash_blake2s_update(HASH_BLAKE2S *ctx, const void *in, size_t len);
int hash_blake2s_224_final(void *out, HASH_BLAKE2S *ctx);
int hash_blake2s_256_final(void *out, HASH_BLAKE2S *ctx);

