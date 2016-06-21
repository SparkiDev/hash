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

/* This code is based on:
 *   RFC 7693 - The BLAKE2 Cryptographic Hash and Message Authentication Code
 *              (MAC)
 */

#include <string.h>
#include "hash_blake2s.h"
#include "hash_blake_sigma.h"

static void blake2s_update(HASH_BLAKE2S *ctx, const void *in, size_t inlen);

/**
 * Rotate right 32-bit x by y bits.
 *
 * @param [in] x  The number to rotate.
 * @param [in] y  The number of bits to rotate.
 * @return  The rotated result.
 */
#define ROTR32(x, y)  (((x) >> (y)) | ((x) << (32 - (y))))

#ifdef HASH_BENDIAN
/**
 * Convert a byte array to a number.
 * There are 32-bits of little-endian bytes in the array.
 *
 * @param [out] n  The number.
 * @param [in]  p  The byte array.
 */
#define BA2N_32_LE(n, p)		\
    n = ((((uint32_t)(p)[0]) <<  0) |	\
         (((uint32_t)(p)[1]) <<  8) |	\
         (((uint32_t)(p)[2]) << 16) |	\
         (((uint32_t)(p)[3]) << 24))
#else
/**
 * Convert a byte array to a number.
 * There are 32-bits of little-endian bytes in the array.
 *
 * @param [out] n  The number.
 * @param [in]  p  The byte array.
 */
#define BA2N_32_LE(n, p) 			                   \
    do { uint32_t *p32 = (uint32_t *)p; n = *p32; } while (0)
#endif

/**
 * Perform the G function to mix the state.
 * 32-bit version.
 *
 * @param [in] s  The state.
 * @param [in] a  Index into state.
 * @param [in] b  Index into state.
 * @param [in] c  Index into state.
 * @param [in] d  Index into state.
 * @param [in] x  A number from the message data.
 * @param [in] y  A number from the message data.
 */
#define MIX_G(s, a, b, c, d, x, y)	\
do					\
{					\
    s[a] += s[b] + x;			\
    s[d]  = ROTR32(s[d] ^ s[a], 16);	\
    s[c] += s[d];			\
    s[b]  = ROTR32(s[b] ^ s[c], 12);	\
    s[a] += s[b] + y;			\
    s[d]  = ROTR32(s[d] ^ s[a], 8);	\
    s[c] += s[d];			\
    s[b]  = ROTR32(s[b] ^ s[c], 7);	\
}					\
while (0)

/** Initialization vector. 32-bit version. */
static const uint32_t blake2s_iv[8] =
{
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

/**
 * Compression function.
 * 32-bit version.
 *
 * @param [in] ctx  The BLAKE2s hash context.
 * @param [in] b    The message data to compress.
 * @param [in] last  0 indicates this is not the last block of the message.<br>
 *                   -1 indicates this is the last block of the message.
 */
static void blake2s_compress(HASH_BLAKE2S *ctx, const uint8_t *b, int last)
{
    int i;
    uint32_t s[16];
    uint32_t d[16];

    /* Even when little-endian - holds data locally. */
    for (i = 0; i < 16; i++)
        BA2N_32_LE(d[i], &b[4 * i]);

    /* Init working state. */
    for (i = 0; i < 8; i++)
        s[i] = ctx->h[i];
    for (i = 0; i < 8; i++)
        s[i + 8] = blake2s_iv[i];

    s[12] ^= ctx->n[0];
    s[13] ^= ctx->n[1];
    s[14] ^= last;

    MIX_G_I(s, d, 0);
    MIX_G_I(s, d, 1);
    MIX_G_I(s, d, 2);
    MIX_G_I(s, d, 3);
    MIX_G_I(s, d, 4);
    MIX_G_I(s, d, 5);
    MIX_G_I(s, d, 6);
    MIX_G_I(s, d, 7);
    MIX_G_I(s, d, 8);
    MIX_G_I(s, d, 9);

    for( i = 0; i < 8; ++i )
        ctx->h[i] ^= s[i] ^ s[i + 8];
}

/**
 * Initialize a MAC operation.
 *
 * @param [in] ctx     The BLAKE2s hash context.
 * @param [in] outlen  The length of the digest output.
 * @param [in] key     The key data.
 * @param [in] keylen  The length of the key data.
 * @return  1 when the key length is too big.<br>
 *          0 otherwise.
 */
static int blake2s_mac_init(HASH_BLAKE2S *ctx, size_t outlen, const void *key,
    size_t keylen)
{
    size_t i;

    if (keylen > 32)
        return 1;

    for (i=0; i<8; i++)
        ctx->h[i] = blake2s_iv[i];
    ctx->h[0] ^= 0x01010000 ^ (keylen << 8) ^ outlen;

    ctx->n[0] = 0;
    ctx->n[1] = 0;
    ctx->i = 0;

    for (i = keylen; i < 64; i++)
        ctx->b[i] = 0;
    blake2s_update(ctx, key, keylen);
    ctx->i = 64;

    return 0;
}

/**
 * Initialize a digest operation.
 *
 * @param [in] ctx     The BLAKE2s hash context.
 * @param [in] outlen  The length of the digest output.
 */
static void blake2s_init(HASH_BLAKE2S *ctx, size_t outlen)
{
    size_t i;

    for (i=0; i<8; i++)
        ctx->h[i] = blake2s_iv[i];
    ctx->h[0] ^= 0x01010000 ^ outlen;

    ctx->n[0] = 0;
    ctx->n[1] = 0;
    ctx->i = 0;
}

/**
 * Update the operation with message data.
 *
 * @param [in] ctx  The BLAKE2s hash context.
 * @param [in] in   The message data.
 * @param [in] len  The length of the message data.
 */
static void blake2s_update(HASH_BLAKE2S *ctx, const void *in, size_t len)
{
    size_t i;
    uint8_t l;
    uint8_t *t;
    const uint8_t *data = in;

    /* Fill up the rest of the cache first. */
    if (ctx->i > 0)
    {
        l = 64 - ctx->i;
        if (l > len) l = len;

        t = &ctx->b[ctx->i];
        for (i=0; i<l; i++)
            t[i] = data[i];
        data += l;
        len -= l;
        ctx->i += l;

        /* Last block is handled differently. */
        if ((ctx->i == 64) && (len > 0))
        {
            ctx->n[0] += 64;
            if (ctx->n[0] < 64)
                ctx->n[1]++;
            blake2s_compress(ctx, ctx->b, 0);
            ctx->i = 0;
        }
    }
    while (len > 64)
    {
        ctx->n[0] += 64;
        if (ctx->n[0] < 64)
            ctx->n[1]++;
        blake2s_compress(ctx, data, 0);
        data += 64;
        len -= 64;
    }
    /* Cache the rest of the data. */
    for (i=0; i<len; i++)
        ctx->b[i] = data[i];
    ctx->i += len;
}

/**
 * Finalize the digest/MAX and generate output.
 *
 * @param [in] ctx     The BLAKE2s hash context.
 * @param [in] out     The digest/MAC ouput.
 * @param [in] outlen  The length of the digest/MAC output.
 */
static void blake2s_final(HASH_BLAKE2S *ctx, void *out, size_t outlen)
{
    size_t i;

    /* Calculate total count of message data bytes. */
    ctx->n[0] += ctx->i;
    if (ctx->n[0] < ctx->i)
        ctx->n[1]++;

    /* Final block of message data. */
    for (i=ctx->i; i<64; i++)
        ctx->b[i] = 0;
    blake2s_compress(ctx, ctx->b, -1);

    /* Little-endian output. */
#ifdef HASH_BENDIAN
    for (i = 0; i < outlen; i++)
        ((uint8_t *) out)[i] = (ctx->h[i >> 2] >> (8 * (i & 3))) & 0xFF;
#else
    memcpy(out, ctx->h, outlen);
#endif
}

/**
 * Initialize a MAC operation for BLAKE2s with 224-bit output.
 *
 * @param [in] ctx     The BLAKE2s hash context.
 * @param [in] key     The key data.
 * @param [in] keylen  The length of the key data.
 * @return  1 when the key length is too big.<br>
 *          0 otherwise.
 */
int hash_blake2s_224_mac_init(HASH_BLAKE2S *ctx, const void *key, size_t len)
{
    return blake2s_mac_init(ctx, 28, key, len);
}
/**
 * Initialize a MAC operation for BLAKE2s with 256-bit output.
 *
 * @param [in] ctx     The BLAKE2s hash context.
 * @param [in] key     The key data.
 * @param [in] keylen  The length of the key data.
 * @return  1 when the key length is too big.<br>
 *          0 otherwise.
 */
int hash_blake2s_256_mac_init(HASH_BLAKE2S *ctx, const void *key, size_t len)
{
    return blake2s_mac_init(ctx, 32, key, len);
}

/**
 * Initialize a digest operation for BLAKE2s with 224-bit output.
 *
 * @param [in] ctx     The BLAKE2s hash context.
 * @return  0 to indicate success.
 */
int hash_blake2s_224_init(HASH_BLAKE2S *ctx)
{
    blake2s_init(ctx, 28);
    return 0;
}
/**
 * Initialize a digest operation for BLAKE2s with 256-bit output.
 *
 * @param [in] ctx     The BLAKE2s hash context.
 * @return  0 to indicate success.
 */
int hash_blake2s_256_init(HASH_BLAKE2S *ctx)
{
    blake2s_init(ctx, 32);
    return 0;
}

/**
 * Update the operation with message data.
 *
 * @param [in] ctx  The BLAKE2s hash context.
 * @param [in] in   The message data.
 * @param [in] len  The length of the message data.
 * @return  0 to indicate success.
 */
int hash_blake2s_update(HASH_BLAKE2S *ctx, const void *in, size_t inlen)
{
    blake2s_update(ctx, in, inlen);
    return 0;
}

/**
 * Finalize the digest/MAX and generate output of 224 bits.
 *
 * @param [in] ctx     The BLAKE2s hash context.
 * @param [in] out     The digest/MAC ouput.
 * @param [in] outlen  The length of the digest/MAC output.
 * @return  0 to indicate success.
 */
int hash_blake2s_224_final(void *out, HASH_BLAKE2S *ctx)
{
    blake2s_final(ctx, out, 28);
    return 0;
}
/**
 * Finalize the digest/MAX and generate output of 256 bits.
 *
 * @param [in] ctx     The BLAKE2s hash context.
 * @param [in] out     The digest/MAC ouput.
 * @param [in] outlen  The length of the digest/MAC output.
 * @return  0 to indicate success.
 */
int hash_blake2s_256_final(void *out, HASH_BLAKE2S *ctx)
{
    blake2s_final(ctx, out, 32);
    return 0;
}

