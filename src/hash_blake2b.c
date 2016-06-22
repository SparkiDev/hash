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
#include "hash_blake2b.h"
#include "hash_blake_sigma.h"

static void blake2b_update(HASH_BLAKE2B *ctx, const void *in, size_t len);

/**
 * Rotate right 64-bit a by n bits.
 *
 * @param [in] a  The number to rotate.
 * @param [in] n  The number of bits to rotate.
 * @return  The rotated result.
 */
#define ROTR64(a, n)  (((a) >> (n)) | ((a) << (64 - (n))))

#ifdef HASH_BENDIAN
/**
 * Convert a byte array to a number.
 * There are 64-bits of little-endian bytes in the array.
 *
 * @param [out] n  The number.
 * @param [in]  p  The byte array.
 */
#define BA2N_64_LE(n, p)		\
    n = ((((uint64_t)(p)[0]) <<  0) |	\
         (((uint64_t)(p)[1]) <<  8) |	\
         (((uint64_t)(p)[2]) << 16) |	\
         (((uint64_t)(p)[3]) << 24) |	\
         (((uint64_t)(p)[4]) << 32) |	\
         (((uint64_t)(p)[5]) << 40) |	\
         (((uint64_t)(p)[6]) << 48) |	\
         (((uint64_t)(p)[7]) << 56))
#else
/**
 * Convert a byte array to a number.
 * There are 64-bits of little-endian bytes in the array.
 *
 * @param [out] n  The number.
 * @param [in]  p  The byte array.
 */
#define BA2N_64_LE(n, p)					\
    do { uint64_t *p64 = (uint64_t *)p; n = *p64; } while (0)
#endif

/**
 * Perform the G function to mix the state.
 * 64-bit version.
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
    s[d]  = ROTR64(s[d] ^ s[a], 32);	\
    s[c] += s[d];			\
    s[b]  = ROTR64(s[b] ^ s[c], 24);	\
    s[a] += s[b] + y;			\
    s[d]  = ROTR64(s[d] ^ s[a], 16);	\
    s[c] += s[d];			\
    s[b]  = ROTR64(s[b] ^ s[c], 63);	\
}					\
while (0)

/** Initialization vector. 64-bit version. */
static const uint64_t blake2b_iv[8] =
{
    0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
    0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179
};

/**
 * Compression function.
 * 64-bit version.
 *
 * @param [in] ctx  The BLAKE2b hash context.
 * @param [in] b    The message data to compress.
 * @param [in] last  0 indicates this is not the last block of the message.<br>
 *                   -1 indicates this is the last block of the message.
 */
static void blake2b_compress(HASH_BLAKE2B *ctx, const uint8_t *b, int last)
{
    int i;
    uint64_t s[16];
    uint64_t d[16];

    /* Init working state. */
    for (i=0; i<8; i++)
        s[i] = ctx->h[i];
    for (i=0; i<8; i++)
        s[i+8] = blake2b_iv[i];

    s[12] ^= ctx->n[0];
    s[13] ^= ctx->n[1];
    s[14] ^= last;

    /* Even when little-endian - holds data locally. */
    for (i=0; i<16; i++)
        BA2N_64_LE(d[i], &b[i*8]);

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
    MIX_G_I(s, d, 10);
    MIX_G_I(s, d, 11);

    for (i=0; i<8; i++)
        ctx->h[i] ^= s[i] ^ s[i+8];
}

/**
 * Initialize a MAC operation.
 *
 * @param [in] ctx     The BLAKE2b hash context.
 * @param [in] outlen  The length of the digest output.
 * @param [in] key     The key data.
 * @param [in] keylen  The length of the key data.
 * @return  1 when the key length is too big.<br>
 *          0 otherwise.
 */
static int blake2b_mac_init(HASH_BLAKE2B *ctx, size_t outlen, const void *key,
    size_t keylen)
{
    size_t i;

    if (keylen > 64)
        return 0;

    for (i=0; i<8; i++)
        ctx->h[i] = blake2b_iv[i];
    ctx->h[0] ^= 0x01010000 ^ (keylen << 8) ^ outlen;

    ctx->n[0] = 0;
    ctx->n[1] = 0;
    ctx->i = 0;

    for (i=keylen; i<128; i++)
        ctx->b[i] = 0;
    blake2b_update(ctx, key, keylen);
    ctx->i = 128;

    return 1;
}

/**
 * Initialize a digest operation.
 *
 * @param [in] ctx     The BLAKE2b hash context.
 * @param [in] outlen  The length of the digest output.
 */
static void blake2b_init(HASH_BLAKE2B *ctx, size_t outlen)
{
    size_t i;

    for (i=0; i<8; i++)
        ctx->h[i] = blake2b_iv[i];
    ctx->h[0] ^= 0x01010000 ^ outlen;

    ctx->n[0] = 0;
    ctx->n[1] = 0;
    ctx->i = 0;
}


/**
 * Update the operation with message data.
 *
 * @param [in] ctx  The BLAKE2b hash context.
 * @param [in] in   The message data.
 * @param [in] len  The length of the message data.
 */
static void blake2b_update(HASH_BLAKE2B *ctx, const void *in, size_t len)
{
    size_t i;
    uint8_t l;
    uint8_t *t;
    const uint8_t *data = in;

    /* Fill up the rest of the cache first. */
    if (ctx->i > 0)
    {
        l = 128 - ctx->i;
        if (l > len) l = len;

        t = &ctx->b[ctx->i];
        for (i=0; i<l; i++)
            t[i] = data[i];
        data += l;
        len -= l;
        ctx->i += l;

        /* Last block is handled differently. */
        if ((ctx->i == 128) && (len > 0))
        {
            ctx->n[0] += 128;
            if (ctx->n[0] < 128)
                ctx->n[1]++;
            blake2b_compress(ctx, ctx->b, 0);
            ctx->i = 0;
        }
    }
    /* Process a full block as long as it is not the last. */
    while (len > 128)
    {
        ctx->n[0] += 128;
        if (ctx->n[0] < 128)
            ctx->n[1]++;
        blake2b_compress(ctx, data, 0);
        data += 128;
        len -= 128;
    }
    /* Cache the rest of the data. */
    for (i=0; i<len; i++)
        ctx->b[i] = data[i];
    ctx->i += len;
}

/**
 * Finalize the digest/MAX and generate output.
 *
 * @param [in] ctx     The BLAKE2b hash context.
 * @param [in] out     The digest/MAC ouput.
 * @param [in] outlen  The length of the digest/MAC output.
 */
static void blake2b_final(HASH_BLAKE2B *ctx, void *out, size_t outlen)
{
    size_t i;

    /* Calculate total count of message data bytes. */
    ctx->n[0] += ctx->i;
    if (ctx->n[0] < ctx->i)
        ctx->n[1]++;

    /* Final block of message data. */
    for (i=ctx->i; i<128; i++)
        ctx->b[i] = 0;
    blake2b_compress(ctx, ctx->b, -1);

    /* Little-endian output. */
#ifdef HASH_BENDIAN
    for (i=0; i<outlen; i++)
        ((uint8_t *)out)[i] = (ctx->h[i>>3] >> (8*(i&7))) & 0xFF;
#else
    for (i=0; i<outlen; i++)
        ((uint8_t *)out)[i] = ((uint8_t *)ctx->h)[i];
#endif
}

/**
 * Initialize a MAC operation for BLAKE2b with 224-bit output.
 *
 * @param [in] ctx     The BLAKE2b hash context.
 * @param [in] key     The key data.
 * @param [in] keylen  The length of the key data.
 * @return  0 when the key length is too big.<br>
 *          1 otherwise.
 */
int hash_blake2b_224_mac_init(HASH_BLAKE2B *ctx, const void *key, size_t len)
{
    return blake2b_mac_init(ctx, 28, key, len);
}
/**
 * Initialize a MAC operation for BLAKE2b with 256-bit output.
 *
 * @param [in] ctx     The BLAKE2b hash context.
 * @param [in] key     The key data.
 * @param [in] keylen  The length of the key data.
 * @return  0 when the key length is too big.<br>
 *          1 otherwise.
 */
int hash_blake2b_256_mac_init(HASH_BLAKE2B *ctx, const void *key, size_t len)
{
    return blake2b_mac_init(ctx, 32, key, len);
}
/**
 * Initialize a MAC operation for BLAKE2b with 384-bit output.
 *
 * @param [in] ctx     The BLAKE2b hash context.
 * @param [in] key     The key data.
 * @param [in] keylen  The length of the key data.
 * @return  0 when the key length is too big.<br>
 *          1 otherwise.
 */
int hash_blake2b_384_mac_init(HASH_BLAKE2B *ctx, const void *key, size_t len)
{
    return blake2b_mac_init(ctx, 48, key, len);
}
/**
 * Initialize a MAC operation for BLAKE2b with 512-bit output.
 *
 * @param [in] ctx     The BLAKE2b hash context.
 * @param [in] key     The key data.
 * @param [in] keylen  The length of the key data.
 * @return  0 when the key length is too big.<br>
 *          1 otherwise.
 */
int hash_blake2b_512_mac_init(HASH_BLAKE2B *ctx, const void *key, size_t len)
{
    return blake2b_mac_init(ctx, 64, key, len);
}

/**
 * Initialize a digest operation for BLAKE2b with 224-bit output.
 *
 * @param [in] ctx     The BLAKE2b hash context.
 * @return  1 to indicate success.
 */
int hash_blake2b_224_init(HASH_BLAKE2B *ctx)
{
    blake2b_init(ctx, 28);
    return 1;
}
/**
 * Initialize a digest operation for BLAKE2b with 256-bit output.
 *
 * @param [in] ctx     The BLAKE2b hash context.
 * @return  1 to indicate success.
 */
int hash_blake2b_256_init(HASH_BLAKE2B *ctx)
{
    blake2b_init(ctx, 32);
    return 1;
}
/**
 * Initialize a digest operation for BLAKE2b with 384-bit output.
 *
 * @param [in] ctx     The BLAKE2b hash context.
 * @return  1 to indicate success.
 */
int hash_blake2b_384_init(HASH_BLAKE2B *ctx)
{
    blake2b_init(ctx, 48);
    return 1;
}
/**
 * Initialize a digest operation for BLAKE2b with 512-bit output.
 *
 * @param [in] ctx     The BLAKE2b hash context.
 * @return  1 to indicate success.
 */
int hash_blake2b_512_init(HASH_BLAKE2B *ctx)
{
    blake2b_init(ctx, 64);
    return 1;
}

/**
 * Update the operation with message data.
 *
 * @param [in] ctx  The BLAKE2b hash context.
 * @param [in] in   The message data.
 * @param [in] len  The length of the message data.
 * @return  1 to indicate success.
 */
int hash_blake2b_update(HASH_BLAKE2B *ctx, const void *in, size_t len)
{
    blake2b_update(ctx, in, len);
    return 1;
}

/**
 * Finalize the digest/MAX and generate output of 224 bits.
 *
 * @param [in] ctx     The BLAKE2b hash context.
 * @param [in] out     The digest/MAC ouput.
 * @param [in] outlen  The length of the digest/MAC output.
 * @return  1 to indicate success.
 */
int hash_blake2b_224_final(void *out, HASH_BLAKE2B *ctx)
{
    blake2b_final(ctx, out, 24);
    return 1;
}
/**
 * Finalize the digest/MAX and generate output of 256 bits.
 *
 * @param [in] ctx     The BLAKE2b hash context.
 * @param [in] out     The digest/MAC ouput.
 * @param [in] outlen  The length of the digest/MAC output.
 * @return  1 to indicate success.
 */
int hash_blake2b_256_final(void *out, HASH_BLAKE2B *ctx)
{
    blake2b_final(ctx, out, 32);
    return 1;
}
/**
 * Finalize the digest/MAX and generate output of 384 bits.
 *
 * @param [in] ctx     The BLAKE2b hash context.
 * @param [in] out     The digest/MAC ouput.
 * @param [in] outlen  The length of the digest/MAC output.
 * @return  1 to indicate success.
 */
int hash_blake2b_384_final(void *out, HASH_BLAKE2B *ctx)
{
    blake2b_final(ctx, out, 48);
    return 1;
}
/**
 * Finalize the digest/MAX and generate output of 512 bits.
 *
 * @param [in] ctx     The BLAKE2b hash context.
 * @param [in] out     The digest/MAC ouput.
 * @param [in] outlen  The length of the digest/MAC output.
 * @return  1 to indicate success.
 */
int hash_blake2b_512_final(void *out, HASH_BLAKE2B *ctx)
{
    blake2b_final(ctx, out, 64);
    return 1;
}

