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

/** The constants k to use with SHA-1 block operation. */
static const uint32_t hash_sha1_k[] =
{
    0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6
};

#define F00(a, b, c, d, e)	(((b) & (c)) | ((~(b)) & d))
#define F20(a, b, c, d, e)	((b) ^ (c) ^ (d))
#define F40(a, b, c, d, e)	(((b) & (c)) | ((b) & (d)) | ((c) & (d)))
#define F60(a, b, c, d, e)	((b) ^ (c) ^ (d))
/**
 * Process one block of data (512 bits) for SHA-1.
 *
 * @param [in] ctx  The SHA1 context object.
 * @param [in] m    The message data to digest.
 */
static void hash_sha1_block(HASH_SHA1 *ctx, const uint8_t *m)
{
    unsigned char i, j;
    uint32_t *h = ctx->h;
    uint32_t w[16];
    uint32_t t[5];
    uint32_t k;
    uint32_t f;
    uint32_t temp;

    for (i=0; i<5; i++)
        t[i] = h[i];
    for (i=0; i<16; i++)
    {
        w[i] = 0;
        for (j=0; j<4; j++)
            w[i] |= ((uint32_t)m[i*4+j]) << ((3-j)*8);
    }

    for (i=0; i<80; i++)
    {
        j = i & 15;
        if (i >= 16)
            w[j] = ROTL32(w[(16+j-3)&15] ^
                          w[(16+j-8)&15] ^
                          w[(16+j-14)&15] ^ w[j], 1);

        if (i < 20)
        {
            f = F00(t[0], t[1], t[2], t[3], t[4]);
            k = hash_sha1_k[0];
        }
        else if (i < 40)
        {
            f = F20(t[0], t[1], t[2], t[3], t[4]);
            k = hash_sha1_k[1];
        }
        else if (i < 60)
        {
            f = F40(t[0], t[1], t[2], t[3], t[4]);
            k = hash_sha1_k[2];
        }
        else
        {
            f = F60(t[0], t[1], t[2], t[3], t[4]);
            k = hash_sha1_k[3];
        }

        temp = ROTL32(t[0], 5) + f + t[4] + k + w[j];
        t[4] = t[3];
        t[3] = t[2];
        t[2] = ROTL32(t[1], 30);
        t[1] = t[0];
        t[0] = temp;
    }

    for (i=0; i<5; i++)
        h[i] += t[i];
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

