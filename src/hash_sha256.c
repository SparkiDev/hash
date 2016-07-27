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
#include "hash_sha2.h"
#include "hmac.h"

/** The size of a block that is processed. */
#define BLOCK_SIZE      64

/** The constants k to use with SHA-256 block operation (and SHA-224). */
static const uint32_t hash_sha256_k[] =
{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define W(i,o)	w[(i+(16-o)) & 15]
#define MIX_W(w, i)							\
    W(i,7) +								\
    (ROTR32(W(i,15),7) ^ ROTR32(W(i,15),18) ^ SHFTR(W(i,15),3)) +	\
    (ROTR32(W(i,2),17) ^ ROTR32(W(i,2),19) ^ SHFTR(W(i,2),10))

#define S1(n)		(ROTR32(n, 6) ^ ROTR32(n, 11) ^ ROTR32(n, 25))
#define S0(n)		(ROTR32(n, 2) ^ ROTR32(n, 13) ^ ROTR32(n, 22))
#ifdef HASH_SHA2_SPEC
#define CH(a,b,c)	((a & b) ^ ((~a) & c))
#define MAJ(a,b,c)    ((a & b) ^ (a & c) ^ (b & c))
#else
#define CH(a,b,c)	(c ^ (a & (b ^ c)))
#define MAJ(a,b,c)    ((a & b) ^ (a & c) ^ (b & c))
#endif

#define T(o,j)	(t[(o-j)&7])
#define MIX_T(t, i, j)							\
do									\
{									\
    uint32_t s1, ch, t1, s0, maj, t2;					\
									\
    s1 = S1(T(4,j));							\
    ch = CH(T(4,j), T(5,j), T(6,j));					\
    t1 = T(7,j) + s1 + ch + hash_sha256_k[i+j] + w[j];			\
    s0 = S0(T(0,j));							\
    maj = MAJ(T(0,j), T(1,j), T(2,j));					\
    t2 = s0 + maj;							\
									\
    T(3,j) += t1;							\
    T(7,j) = t1 + t2;							\
}									\
while (0)

/**
 * Process one block of data (512 bits) for SHA-256.
 *
 * @param [in] ctx  The SHA256 context object.
 * @param [in] m    The message data to digest.
 */
static void hash_sha256_block(HASH_SHA256 *ctx, const uint8_t *m)
{
    unsigned char i, j;
    uint32_t *h = ctx->h;
    uint32_t w[16];
    uint32_t t[8];

    for (i=0; i<8; i++)
        t[i] = h[i];
    for (i=0; i<16; i++)
    {
        w[i] = 0;
        for (j=0; j<4; j++)
            w[i] |= ((uint32_t)m[i*4+j]) << ((3-j)*8);
    }

    for (i=0; i<BLOCK_SIZE; i+=16)
    {
        if (i >= 16)
        {
            w[0] += MIX_W(w, 0);
            w[1] += MIX_W(w, 1);
            w[2] += MIX_W(w, 2);
            w[3] += MIX_W(w, 3);
            w[4] += MIX_W(w, 4);
            w[5] += MIX_W(w, 5);
            w[6] += MIX_W(w, 6);
            w[7] += MIX_W(w, 7);
            w[8] += MIX_W(w, 8);
            w[9] += MIX_W(w, 9);
            w[10] += MIX_W(w, 10);
            w[11] += MIX_W(w, 11);
            w[12] += MIX_W(w, 12);
            w[13] += MIX_W(w, 13);
            w[14] += MIX_W(w, 14);
            w[15] += MIX_W(w, 15);
        }

        MIX_T(t, i, 0);
        MIX_T(t, i, 1);
        MIX_T(t, i, 2);
        MIX_T(t, i, 3);
        MIX_T(t, i, 4);
        MIX_T(t, i, 5);
        MIX_T(t, i, 6);
        MIX_T(t, i, 7);
        MIX_T(t, i, 8);
        MIX_T(t, i, 9);
        MIX_T(t, i, 10);
        MIX_T(t, i, 11);
        MIX_T(t, i, 12);
        MIX_T(t, i, 13);
        MIX_T(t, i, 14);
        MIX_T(t, i, 15);
    }

    for (i=0; i<8; i++)
        h[i] += t[i];
}

/**
 * Process the unused message bytes.
 * Append 0x80 to add 1 bit after message.
 * Put the length in the last 64 bits of a block of 512 bits even if we have
 * to make a new block.
 *
 * @param [in] ctx  The SHA256 context object.
 */
static void hash_sha256_fin(HASH_SHA256 *ctx)
{
    uint8_t i;
    uint8_t *m = ctx->m;
    uint8_t o = ctx->o;
    uint64_t len = ctx->len * 8;

    m[o++] = 0x80;

    if (o > 56)
    {
        memset(&m[o], 0, BLOCK_SIZE - o);
        hash_sha256_block(ctx, m);
        o = 0;
    }
    memset(&m[o], 0, 56-o);
    for (i=0; i<8; i++)
        m[56+i] = len >> ((7-i)*8);
    hash_sha256_block(ctx, m);
}

/** The initial h0 value for SHA-224. */
#define SHA224_H0	0xc1059ed8
/** The initial h1 value for SHA-224. */
#define SHA224_H1	0x367cd507
/** The initial h2 value for SHA-224. */
#define SHA224_H2	0x3070dd17
/** The initial h3 value for SHA-224. */
#define SHA224_H3	0xf70e5939
/** The initial h4 value for SHA-224. */
#define SHA224_H4	0xffc00b31
/** The initial h5 value for SHA-224. */
#define SHA224_H5	0x68581511
/** The initial h6 value for SHA-224. */
#define SHA224_H6	0x64f98fa7
/** The initial h7 value for SHA-224. */
#define SHA224_H7	0xbefa4fa4

/**
 * Initialize the hash object calculating a SHA-224 digest.
 *
 * @param [in] ctx  The SHA256 context object.
 * @return  1 to indicate success.
 */
int hash_sha224_init(HASH_SHA256 *ctx)
{
    ctx->h[0] = SHA224_H0;
    ctx->h[1] = SHA224_H1;
    ctx->h[2] = SHA224_H2;
    ctx->h[3] = SHA224_H3;
    ctx->h[4] = SHA224_H4;
    ctx->h[5] = SHA224_H5;
    ctx->h[6] = SHA224_H6;
    ctx->h[7] = SHA224_H7;

    ctx->o = 0;
    ctx->len = 0;

    return 1;
}

/**
 * Finalize the message digest for SHA-224.
 * Output 224 bits or 28 bytes.
 *
 * @param [in] md   The message digest buffer.
 * @param [in] ctx  The SHA256 context object.
 * @return  1 to indicate success.
 */
int hash_sha224_final(unsigned char *md, HASH_SHA256 *ctx)
{
    uint8_t i, j;
    uint32_t *h = ctx->h;

    hash_sha256_fin(ctx);

    for (i=0; i<7; i++)
        for (j=0; j<4; j++)
            md[i*4+j] = h[i] >> ((3-j)*8);

    return 1;
}

/** The initial h0 value for SHA-256. */
#define SHA256_H0	0x6a09e667
/** The initial h1 value for SHA-256. */
#define SHA256_H1	0xbb67ae85
/** The initial h2 value for SHA-256. */
#define SHA256_H2	0x3c6ef372
/** The initial h3 value for SHA-256. */
#define SHA256_H3	0xa54ff53a
/** The initial h4 value for SHA-256. */
#define SHA256_H4	0x510e527f
/** The initial h5 value for SHA-256. */
#define SHA256_H5	0x9b05688c
/** The initial h6 value for SHA-256. */
#define SHA256_H6	0x1f83d9ab
/** The initial h7 value for SHA-256. */
#define SHA256_H7	0x5be0cd19

/**
 * Initialize the hash object calculating a SHA-256 digest.
 *
 * @param [in] ctx  The SHA256 context object.
 * @return  1 to indicate success.
 */
int hash_sha256_init(HASH_SHA256 *ctx)
{
    ctx->h[0] = SHA256_H0;
    ctx->h[1] = SHA256_H1;
    ctx->h[2] = SHA256_H2;
    ctx->h[3] = SHA256_H3;
    ctx->h[4] = SHA256_H4;
    ctx->h[5] = SHA256_H5;
    ctx->h[6] = SHA256_H6;
    ctx->h[7] = SHA256_H7;

    ctx->o = 0;
    ctx->len = 0;

    return 1;
}

/**
 * Update the message digest with more data.
 *
 * @param [in] ctx   The SHA256 context object.
 * @param [in] data  The data to digest.
 * @param [in] len   The length of the data to digest.
 * @return  1 to indicate success.
 */
int hash_sha256_update(HASH_SHA256 *ctx, const void *data, size_t len)
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
        l = BLOCK_SIZE - o;
        if (len < l) l = len;

        t = &m[o];
        for (i=0; i<l; i++)
            t[i] = d[i];
        d += l;
        len -= l;
        o += l;

        if (o == BLOCK_SIZE)
        {
            hash_sha256_block(ctx, m);
            o = 0;
        }
    }
    while (len >= BLOCK_SIZE)
    {
        hash_sha256_block(ctx, d);
        d += BLOCK_SIZE;
        len -= BLOCK_SIZE;
    }
    for (i=0; i<len; i++)
        m[i] = d[i];
    ctx->o = o + len;

    return 1;
}

/**
 * Finalize the message digest for SHA-256.
 * Output 256 bits or 32 bytes.
 *
 * @param [in] md   The message digest buffer.
 * @param [in] ctx  The SHA256 context object.
 * @return  1 to indicate success.
 */
int hash_sha256_final(unsigned char *md, HASH_SHA256 *ctx)
{
    uint8_t i, j;
    uint32_t *h = ctx->h;

    hash_sha256_fin(ctx);

    for (i=0; i<8; i++)
        for (j=0; j<4; j++)
            md[i*4+j] = h[i] >> ((3-j)*8);

    return 1;
}

/**
 * Initialize the HMAC-SHA-224 operation with a key.
 *
 * @param [in] ctx  The SHA256 context objects.
 * @param [in] key  The key data.
 * @param [in] len  The length of the key data.
 * @return  1 to indicate success.
 */
int hmac_sha224_init(HASH_SHA256 *ctx, const void *key, size_t len)
{
    HMAC_INIT(ctx, key, len, HASH_SHA224_LEN, hash_sha224_init,
        hash_sha224_update, hash_sha224_final);
    return 1;
}

/**
 * Finalize the HMAC-SHA-224 operation.
 * Output 224 bits or 28 bytes.
 *
 * @param [in] md   The MAC data buffer.
 * @param [in] ctx  The SHA256 context objects.
 * @return  1 to indicate success.
 */
int hmac_sha224_final(unsigned char *md, HASH_SHA256 *ctx)
{
    HMAC_FINAL(md, ctx, HASH_SHA224_LEN, hash_sha224_update, hash_sha224_final);
    return 1;
}

/**
 * Initialize the HMAC-SHA-256 operation with a key.
 *
 * @param [in] ctx  The SHA256 context objects.
 * @param [in] key  The key data.
 * @param [in] len  The length of the key data.
 * @return  1 to indicate success.
 */
int hmac_sha256_init(HASH_SHA256 *ctx, const void *key, size_t len)
{
    HMAC_INIT(ctx, key, len, HASH_SHA256_LEN, hash_sha256_init,
        hash_sha256_update, hash_sha256_final);
    return 1;
}

/**
 * Finalize the HMAC-SHA-256 operation.
 * Output 256 bits or 32 bytes.
 *
 * @param [in] md   The MAC data buffer.
 * @param [in] ctx  The SHA256 context objects.
 * @return  1 to indicate success.
 */
int hmac_sha256_final(unsigned char *md, HASH_SHA256 *ctx)
{
    HMAC_FINAL(md, ctx, HASH_SHA256_LEN, hash_sha256_update, hash_sha256_final);
    return 1;
}

