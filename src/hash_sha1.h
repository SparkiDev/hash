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

/**
 * Rotate left 32-bit integer.
 *
 * @param [in] n  The number to rotate.
 * @param [in] s  The number of bits to shift right.
 * @return  Rotated number.
 */
#define ROTL32(n, s)	(((n) << s) | ((n) >> (32 - s)))

/** The data structure for performing SHA-1 and related hashing. */
typedef struct hash_sha1_st
{
    /** The 5 32-bit h values. */
    uint32_t h[5];
    /** One block of message data. */
    uint8_t m[64];
    /** Offset to start putting in new message bytes. */
    uint8_t o;
    /** Length of data in bytes of message. */
    uint64_t len;
} HASH_SHA1;

int hash_sha1_init(HASH_SHA1 *ctx);
int hash_sha1_update(HASH_SHA1 *ctx, const void *data, size_t len);
int hash_sha1_final(unsigned char *md, HASH_SHA1 *ctx);

