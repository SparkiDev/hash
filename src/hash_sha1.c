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
#include <string.h>
#include "hash_sha1.h"


/** The first constant k to use with SHA-1 block operation. */
#define HASH_SHA1_K_0	0x5A827999
/** The second constant k to use with SHA-1 block operation. */
#define HASH_SHA1_K_1	0x6ED9EBA1
/** The third constant k to use with SHA-1 block operation. */
#define HASH_SHA1_K_2	0x8F1BBCDC
/** The fourth constant k to use with SHA-1 block operation. */
#define HASH_SHA1_K_3	0xCA62C1D6

/**
 * Boolean function operation for loop iterations 0-19.
 *
 * @param [in] b  The second working state value.
 * @param [in] c  The third working state value.
 * @param [in] d  The fourth working state value.
 * @return  The boolean operation result.
 */
#define F00_19(b, c, d)	(((b) & (c)) | ((~(b)) & d))
/**
 * Boolean function operation for loop iterations 20-39.
 *
 * @param [in] b  The second working state value.
 * @param [in] c  The third working state value.
 * @param [in] d  The fourth working state value.
 * @return  The boolean operation result.
 */
#define F20_39(b, c, d)	((b) ^ (c) ^ (d))
/**
 * Boolean function operation for loop iterations 40-59.
 *
 * @param [in] b  The second working state value.
 * @param [in] c  The third working state value.
 * @param [in] d  The fourth working state value.
 * @return  The boolean operation result.
 */
#define F40_59(b, c, d)	(((b) & (c)) | ((b) & (d)) | ((c) & (d)))
/**
 * Boolean function operation for loop iterations 60-79.
 *
 * @param [in] b  The second working state value.
 * @param [in] c  The third working state value.
 * @param [in] d  The fourth working state value.
 * @return  The boolean operation result.
 */
#define F60_79(b, c, d)	((b) ^ (c) ^ (d))

#ifdef SHA3_NO_BSWAP
/**
 * Convert 4 bytes of big-endian into a 32-bit number.
 *
 * @param [out] r  The 32-bit number.
 * @param [in]  a  The array of bytes.
 * @param [in]  c  Count of 32-bit numbers into the array.
 */
#define M32(r, a, c)			\
   r = ((((uint32_t)a[c*4+0]) << 24) |	\
        (((uint32_t)a[c*4+1]) << 16) |	\
        (((uint32_t)a[c*4+2]) <<  8) |	\
        (((uint32_t)a[c*4+3]) <<  0))
#else
/**
 * Convert 4 bytes of big-endian into a 32-bit number.
 *
 * @param [out] r  The 32-bit number.
 * @param [in]  a  The array of bytes.
 * @param [in]  c  Count of 32-bit numbers into the array.
 */
#define M32(r, a, c)			\
    do					\
    {					\
        register uint32_t t;		\
        t = ((const uint32_t *)a)[c];	\
        asm volatile ("bswap %0"	\
                      :			\
                      : "r" (t));	\
        r = t;				\
    }					\
    while (0)
#endif

/**
 * Process one block of data (512 bits) for SHA-1.
 *
 * @param [in] ctx  The SHA1 context object.
 * @param [in] m    The message data to digest.
 */
static void hash_sha1_block(HASH_SHA1 *ctx, const uint8_t *m)
{
    uint8_t i;
    uint32_t *h = ctx->h;
    uint32_t w[77];
    uint32_t t[6];

    t[0] = h[0];
    t[1] = h[1];
    t[2] = h[2];
    t[3] = h[3];
    t[4] = h[4];

    for (i=0; i<16; i++)
    {
        M32(w[i], m, i);
        t[5] = t[4] + HASH_SHA1_K_0 + ROTL32(t[0], 5) + w[i] +
            F00_19(t[1], t[2], t[3]);
        t[4] = t[3];
        t[3] = t[2];
        t[2] = ROTL32(t[1], 30);
        t[1] = t[0];
        t[0] = t[5];
    }
    for (; i<20; i++)
    {
        w[i] = ROTL32(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
        t[5] = t[4] + HASH_SHA1_K_0 + ROTL32(t[0], 5) + w[i] +
            F00_19(t[1], t[2], t[3]);
        t[4] = t[3];
        t[3] = t[2];
        t[2] = ROTL32(t[1], 30);
        t[1] = t[0];
        t[0] = t[5];
    }
    for (; i<40; i++)
    {
        w[i] = ROTL32(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
        t[5] = t[4] + HASH_SHA1_K_1 + ROTL32(t[0], 5) + w[i] +
            F20_39(t[1], t[2], t[3]);
        t[4] = t[3];
        t[3] = t[2];
        t[2] = ROTL32(t[1], 30);
        t[1] = t[0];
        t[0] = t[5];
    }
    for (; i<60; i++)
    {
        w[i] = ROTL32(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
        t[5] = t[4] + HASH_SHA1_K_2 + ROTL32(t[0], 5) + w[i] +
            F40_59(t[1], t[2], t[3]);
        t[4] = t[3];
        t[3] = t[2];
        t[2] = ROTL32(t[1], 30);
        t[1] = t[0];
        t[0] = t[5];
    }
    for (; i<77; i++)
    {
        w[i] = ROTL32(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
        t[5] = t[4] + HASH_SHA1_K_3 + ROTL32(t[0], 5) + w[i] +
            F60_79(t[1], t[2], t[3]);
        t[4] = t[3];
        t[3] = t[2];
        t[2] = ROTL32(t[1], 30);
        t[1] = t[0];
        t[0] = t[5];
    }
    for (; i<80; i++)
    {
        t[5] = ROTL32(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
        t[5] += t[4] + HASH_SHA1_K_3 + ROTL32(t[0], 5) +
            F60_79(t[1], t[2], t[3]);
        t[4] = t[3];
        t[3] = t[2];
        t[2] = ROTL32(t[1], 30);
        t[1] = t[0];
        t[0] = t[5];
    }

    h[0] += t[0];
    h[1] += t[1];
    h[2] += t[2];
    h[3] += t[3];
    h[4] += t[4];
}

/**
 * Process the unused message bytes.
 * Append 0x80 to add 1 bit after message.
 * Put the length in the last 64 bits of a block of 512 bits even if we have
 * to make a new block.
 *
 * @param [in] ctx  The SHA1 context object.
 */
static void hash_sha1_fin(HASH_SHA1 *ctx)
{
    uint8_t i;
    uint8_t *m = ctx->m;
    uint8_t o = ctx->o;
    uint64_t len = ctx->len * 8;

    m[o++] = 0x80;

    if (o > 56)
    {
        memset(&m[o], 0, 64 - o);
        hash_sha1_block(ctx, m);
        o = 0;
    }
    memset(&m[o], 0, 56-o);
    for (i=0; i<8; i++)
        m[56+i] = len >> ((7-i)*8);
    hash_sha1_block(ctx, m);
}

/** The initial h0 value for SHA-1. */
#define SHA1_H0		0x67452301
/** The initial h1 value for SHA-1. */
#define SHA1_H1		0xEFCDAB89
/** The initial h2 value for SHA-1. */
#define SHA1_H2		0x98BADCFE
/** The initial h3 value for SHA-1. */
#define SHA1_H3		0x10325476
/** The initial h4 value for SHA-1. */
#define SHA1_H4		0xC3D2E1F0

/**
 * Initialize the hash object calculating a SHA-1 digest.
 *
 * @param [in] ctx  The SHA1 context object.
 * @return  1 to indicate success.
 */
int hash_sha1_init(HASH_SHA1 *ctx)
{
    ctx->h[0] = SHA1_H0;
    ctx->h[1] = SHA1_H1;
    ctx->h[2] = SHA1_H2;
    ctx->h[3] = SHA1_H3;
    ctx->h[4] = SHA1_H4;

    ctx->o = 0;
    ctx->len = 0;

    return 1;
}

/**
 * Update the message digest with more data.
 *
 * @param [in] ctx   The SHA1 context object.
 * @param [in] data  The data to digest.
 * @param [in] len   The length of the data to digest.
 * @return  1 to indicate success.
 */
int hash_sha1_update(HASH_SHA1 *ctx, const void *data, size_t len)
{
    size_t i;
    size_t l;
    uint8_t *m = ctx->m;
    uint8_t o = ctx->o;
    const uint8_t *d = data;
    uint8_t *t;

    ctx->len += len;

    if (o > 0)
    {
        l = 64 - o;
        if (len < l) l = len;
    
        t = &m[o];
        for (i=0; i<l; i++)
            t[i] = d[i];
        d += l;
        len -= l;
        o += l;

        if (o == 64)
        {
            hash_sha1_block(ctx, m);
            o = 0;
        }
    }
    while (len >= 64)
    {
        hash_sha1_block(ctx, d);
        d += 64;
        len -= 64;
    }
    for (i=0; i<len; i++)
        m[i] = d[i];
    ctx->o = o + len;

    return 1;
}

/**
 * Finalize the message digest for SHA-1.
 * Output 160 bits or 20 bytes.
 *
 * @param [in] md   The message digest buffer.
 * @param [in] ctx  The SHA1 context object.
 * @return  1 to indicate success.
 */
int hash_sha1_final(unsigned char *md, HASH_SHA1 *ctx)
{
    uint8_t i, j;
    uint32_t *h = ctx->h;

    hash_sha1_fin(ctx);

    for (i=0; i<5; i++)
        for (j=0; j<4; j++)
            md[i*4+j] = h[i] >> ((3-j)*8);

    return 1;
}

