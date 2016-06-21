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
 * Rotate right 32-bit integer.
 *
 * @param [in] n  The number to rotate.
 * @param [in] s  The number of bits to shift right.
 * @return  Rotated number.
 */
#define ROTR_32(n, s)	(((n) >> s) | ((n) << (32 - s)))
/**
 * Rotate right 64-bit integer.
 *
 * @param [in] n  The number to rotate.
 * @param [in] s  The number of bits to shift right.
 * @return  Rotated number.
 */
#define ROTR_64(n, s)	(((n) >> s) | ((n) << (64 - s)))
/**
 * Shift right integer.
 *
 * @param [in] n  The number to shift.
 * @param [in] s  The number of bits to shift right.
 * @return  Rotated number.
 */
#define SHFTR(n, s)	((n) >> s)

/** The data structure for performing SHA-256 and related hashing. */
typedef struct hash_sha256_st
{
    /** The 8 32-bit h values. */
    uint32_t h[8];
    /** One block of message data. */
    uint8_t m[64];
    /** Offset to start putting in new message bytes. */
    uint8_t o;
    /** Length of data in bytes of message. */
    uint64_t len;
} HASH_SHA256;

/** The data structure for performing SHA-512 and related hashing. */
typedef struct hash_sha512_st
{
    /** The 8 64-bit h values. */
    uint64_t h[8];
    /** One block of message data. */
    uint8_t m[128];
    /** Offset to start putting in new message bytes. */
    uint8_t o;
    /** Low 54 bits of the length of data in bytes of message. */
    uint64_t len_lo;
    /** High 54 bits of the length of data in bytes of message. */
    uint64_t len_hi;
} HASH_SHA512;

int hash_sha224_init(HASH_SHA256 *ctx);
#define hash_sha224_update hash_sha256_update
int hash_sha224_final(unsigned char *md, HASH_SHA256 *ctx);

int hash_sha256_init(HASH_SHA256 *ctx);
int hash_sha256_update(HASH_SHA256 *ctx, const void *data, size_t len);
int hash_sha256_final(unsigned char *md, HASH_SHA256 *ctx);

int hash_sha384_init(HASH_SHA512 *ctx);
#define hash_sha384_update hash_sha512_update
int hash_sha384_final(unsigned char *md, HASH_SHA512 *ctx);

int hash_sha512_init(HASH_SHA512 *ctx);
int hash_sha512_update(HASH_SHA512 *ctx, const void *data, size_t len);
int hash_sha512_final(unsigned char *md, HASH_SHA512 *ctx);

int hash_sha512_224_init(HASH_SHA512 *ctx);
#define hash_sha512_224_update hash_sha512_update
int hash_sha512_224_final(unsigned char *md, HASH_SHA512 *ctx);

int hash_sha512_256_init(HASH_SHA512 *ctx);
#define hash_sha512_256_update hash_sha512_update
int hash_sha512_256_final(unsigned char *md, HASH_SHA512 *ctx);

