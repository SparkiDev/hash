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

/** The constants k to use with SHA-512 block operation (and SHA-384, etc.). */
static uint64_t hash_sha512_k[] =
{
    0x428a2f98d728ae22L, 0x7137449123ef65cdL,
    0xb5c0fbcfec4d3b2fL, 0xe9b5dba58189dbbcL,
    0x3956c25bf348b538L, 0x59f111f1b605d019L,
    0x923f82a4af194f9bL, 0xab1c5ed5da6d8118L,
    0xd807aa98a3030242L, 0x12835b0145706fbeL,
    0x243185be4ee4b28cL, 0x550c7dc3d5ffb4e2L,
    0x72be5d74f27b896fL, 0x80deb1fe3b1696b1L,
    0x9bdc06a725c71235L, 0xc19bf174cf692694L,
    0xe49b69c19ef14ad2L, 0xefbe4786384f25e3L,
    0x0fc19dc68b8cd5b5L, 0x240ca1cc77ac9c65L,
    0x2de92c6f592b0275L, 0x4a7484aa6ea6e483L,
    0x5cb0a9dcbd41fbd4L, 0x76f988da831153b5L,
    0x983e5152ee66dfabL, 0xa831c66d2db43210L,
    0xb00327c898fb213fL, 0xbf597fc7beef0ee4L,
    0xc6e00bf33da88fc2L, 0xd5a79147930aa725L,
    0x06ca6351e003826fL, 0x142929670a0e6e70L,
    0x27b70a8546d22ffcL, 0x2e1b21385c26c926L,
    0x4d2c6dfc5ac42aedL, 0x53380d139d95b3dfL,
    0x650a73548baf63deL, 0x766a0abb3c77b2a8L,
    0x81c2c92e47edaee6L, 0x92722c851482353bL,
    0xa2bfe8a14cf10364L, 0xa81a664bbc423001L,
    0xc24b8b70d0f89791L, 0xc76c51a30654be30L,
    0xd192e819d6ef5218L, 0xd69906245565a910L,
    0xf40e35855771202aL, 0x106aa07032bbd1b8L,
    0x19a4c116b8d2d0c8L, 0x1e376c085141ab53L,
    0x2748774cdf8eeb99L, 0x34b0bcb5e19b48a8L,
    0x391c0cb3c5c95a63L, 0x4ed8aa4ae3418acbL,
    0x5b9cca4f7763e373L, 0x682e6ff3d6b2b8a3L,
    0x748f82ee5defb2fcL, 0x78a5636f43172f60L,
    0x84c87814a1f0ab72L, 0x8cc702081a6439ecL,
    0x90befffa23631e28L, 0xa4506cebde82bde9L,
    0xbef9a3f7b2c67915L, 0xc67178f2e372532bL,
    0xca273eceea26619cL, 0xd186b8c721c0c207L,
    0xeada7dd6cde0eb1eL, 0xf57d4f7fee6ed178L,
    0x06f067aa72176fbaL, 0x0a637dc5a2c898a6L,
    0x113f9804bef90daeL, 0x1b710b35131c471bL,
    0x28db77f523047d84L, 0x32caab7b40c72493L,
    0x3c9ebe0a15c9bebcL, 0x431d67c49c100d4cL,
    0x4cc5d4becb3e42b6L, 0x597f299cfc657e2aL,
    0x5fcb6fab3ad6faecL, 0x6c44198c4a475817L
};

/**
 * Process one block of data (512 bits) for SHA-512.
 *
 * @param [in] ctx  The SHA-512 context object.
 */
static void hash_sha512_block(HASH_SHA512 *ctx)
{
    unsigned char i, j;
    uint8_t *m = ctx->m;
    uint64_t *h = ctx->h;
    uint64_t w[16];
    uint64_t t[8];

    memcpy(t, h, sizeof(t));
    for (i=0; i<16; i++)
    {
        w[i] = 0;
        for (j=0; j<8; j++)
            w[i] |= ((uint64_t)m[i*8+j]) << ((7-j)*8);
    }
    for (i=0; i<80; i++)
    {
        uint64_t s1, ch, t1, s0, maj, t2;

        if (i >= 16)
        {
            j = (i - 15) & 15;
            s0 = ROTR_64(w[j], 1) ^ ROTR_64(w[j], 8) ^ SHFTR(w[j], 7);
            j = (i - 2) & 15;
            s1 = ROTR_64(w[j], 19) ^ ROTR_64(w[j], 61) ^ SHFTR(w[j], 6);
            j = (i - 7) & 15;
            w[i & 15] += s0 + w[j] + s1;
        }

        s1 = ROTR_64(t[4], 14) ^ ROTR_64(t[4], 18) ^ ROTR_64(t[4], 41);
        ch = (t[4] & t[5]) ^ ((~t[4]) & t[6]);
        t1 = t[7] + s1 + ch + hash_sha512_k[i] + w[i & 15];
        s0 = ROTR_64(t[0], 28) ^ ROTR_64(t[0], 34) ^ ROTR_64(t[0], 39);
        maj = (t[0] & t[1]) ^ (t[0] & t[2]) ^ (t[1] & t[2]);
        t2 = s0 + maj;

        t[7] = t[6];
        t[6] = t[5];
        t[5] = t[4];
        t[4] = t[3] + t1;
        t[3] = t[2];
        t[2] = t[1];
        t[1] = t[0];
        t[0] = t1 + t2;
    }
    for (i=0; i<8; i++)
        h[i] += t[i];
}

/**
 * Process the unused message bytes.
 * Append 0x80 to add 1 bit after message.
 * Put the length in the last 128 bits of a block of 1024 bits even if we have
 * to make a new block.
 *
 * @param [in] ctx  The SHA-512 context object.
 */
static void hash_sha512_fin(HASH_SHA512 *ctx)
{
    uint8_t i;
    uint8_t *m = ctx->m;
    uint8_t o = ctx->o;
    uint64_t len_lo = ctx->len_lo << 3;
    uint64_t len_hi = (ctx->len_hi << 3)| (ctx->len_lo >> 61);

    m[o++] = 0x80;

    if (o > 112)
    {
        memset(&m[o], 0, 128 - o);
        hash_sha512_block(ctx);
        o = 0;
    }
    memset(&m[o], 0, 112-o);
    for (i=0; i<8; i++)
        m[112+i] = len_hi >> ((7-i)*8);
    for (i=0; i<8; i++)
        m[120+i] = len_lo >> ((7-i)*8);
    hash_sha512_block(ctx);
}

/** The initial h0 value for SHA-384. */
#define SHA384_H0	0xcbbb9d5dc1059ed8L
/** The initial h1 value for SHA-384. */
#define SHA384_H1	0x629a292a367cd507L
/** The initial h2 value for SHA-384. */
#define SHA384_H2	0x9159015a3070dd17L
/** The initial h3 value for SHA-384. */
#define SHA384_H3	0x152fecd8f70e5939L
/** The initial h4 value for SHA-384. */
#define SHA384_H4	0x67332667ffc00b31L
/** The initial h5 value for SHA-384. */
#define SHA384_H5	0x8eb44a8768581511L
/** The initial h6 value for SHA-384. */
#define SHA384_H6	0xdb0c2e0d64f98fa7L
/** The initial h7 value for SHA-384. */
#define SHA384_H7	0x47b5481dbefa4fa4L

/**
 * Initialize the hash object calculating a SHA-384 digest.
 *
 * @param [in] ctx  The SHA256 context object.
 * @return  1 to indicate success.
 */
int hash_sha384_init(HASH_SHA512 *ctx)
{
    ctx->h[0] = SHA384_H0;
    ctx->h[1] = SHA384_H1;
    ctx->h[2] = SHA384_H2;
    ctx->h[3] = SHA384_H3;
    ctx->h[4] = SHA384_H4;
    ctx->h[5] = SHA384_H5;
    ctx->h[6] = SHA384_H6;
    ctx->h[7] = SHA384_H7;

    ctx->o = 0;
    ctx->len_lo = 0;
    ctx->len_hi = 0;

    return 1;
}

/**
 * Finalize the message digest for SHA-384.
 * Output 384 bits or 48 bytes.
 *
 * @param [in] md   The message digest buffer.
 * @param [in] ctx  The SHA512 context object.
 * @return  1 to indicate success.
 */
int hash_sha384_final(unsigned char *md, HASH_SHA512 *ctx)
{
    uint8_t i, j;
    uint64_t *h = ctx->h;

    hash_sha512_fin(ctx);

    for (i=0; i<6; i++)
        for (j=0; j<8; j++)
            md[i*8+j] = h[i] >> ((7-j)*8);

    return 1;
}

/** The initial h0 value for SHA-512. */
#define SHA512_H0	0x6a09e667f3bcc908L
/** The initial h1 value for SHA-512. */
#define SHA512_H1	0xbb67ae8584caa73bL
/** The initial h2 value for SHA-512. */
#define SHA512_H2	0x3c6ef372fe94f82bL
/** The initial h3 value for SHA-512. */
#define SHA512_H3	0xa54ff53a5f1d36f1L
/** The initial h4 value for SHA-512. */
#define SHA512_H4	0x510e527fade682d1L
/** The initial h5 value for SHA-512. */
#define SHA512_H5	0x9b05688c2b3e6c1fL
/** The initial h6 value for SHA-512. */
#define SHA512_H6	0x1f83d9abfb41bd6bL
/** The initial h7 value for SHA-512. */
#define SHA512_H7	0x5be0cd19137e2179L

/**
 * Initialize the hash object calculating a SHA-512 digest.
 *
 * @param [in] ctx  The SHA256 context object.
 * @return  1 to indicate success.
 */
int hash_sha512_init(HASH_SHA512 *ctx)
{
    ctx->h[0] = SHA512_H0;
    ctx->h[1] = SHA512_H1;
    ctx->h[2] = SHA512_H2;
    ctx->h[3] = SHA512_H3;
    ctx->h[4] = SHA512_H4;
    ctx->h[5] = SHA512_H5;
    ctx->h[6] = SHA512_H6;
    ctx->h[7] = SHA512_H7;

    ctx->o = 0;
    ctx->len_lo = 0;
    ctx->len_hi = 0;

    return 1;
}

/**
 * Update the message digest with more data.
 *
 * @param [in] ctx   The SHA512 context object.
 * @param [in] data  The data to digest.
 * @param [in] len   The length of the data to digest.
 * @return  1 to indicate success.
 */
int hash_sha512_update(HASH_SHA512 *ctx, const void *data, size_t len)
{
    size_t l;
    uint8_t *m = ctx->m;
    uint8_t o = ctx->o;
    uint64_t len_lo = ctx->len_lo;
    const uint8_t *d = data;

    ctx->len_lo += len;
    if (ctx->len_lo < len_lo)
        ctx->len_hi++;

    while (1)
    {
        l = 128 - o;
        if (len < l) l = len;
        memcpy(&m[o], d, l);
        d += l;
        len -= l;
        o += l;

        if (o < 128)
            break;

        hash_sha512_block(ctx);
        o = 0;
    }

    ctx->o = o;

    return 1;
}

/**
 * Finalize the message digest for SHA-512.
 * Output 512 bits or 64 bytes.
 *
 * @param [in] md   The message digest buffer.
 * @param [in] ctx  The SHA512 context object.
 * @return  1 to indicate success.
 */
int hash_sha512_final(unsigned char *md, HASH_SHA512 *ctx)
{
    uint8_t i, j;
    uint64_t *h = ctx->h;

    hash_sha512_fin(ctx);

    for (i=0; i<8; i++)
        for (j=0; j<8; j++)
            md[i*8+j] = h[i] >> ((7-j)*8);

    return 1;
}

/** The initial h0 value for SHA-512_224. */
#define SHA512_224_H0	0x8C3D37C819544DA2L
/** The initial h1 value for SHA-512_224. */
#define SHA512_224_H1	0x73E1996689DCD4D6L
/** The initial h2 value for SHA-512_224. */
#define SHA512_224_H2	0x1DFAB7AE32FF9C82L
/** The initial h3 value for SHA-512_224. */
#define SHA512_224_H3	0x679DD514582F9FCFL
/** The initial h4 value for SHA-512_224. */
#define SHA512_224_H4	0x0F6D2B697BD44DA8L
/** The initial h5 value for SHA-512_224. */
#define SHA512_224_H5	0x77E36F7304C48942L
/** The initial h6 value for SHA-512_224. */
#define SHA512_224_H6	0x3F9D85A86A1D36C8L
/** The initial h7 value for SHA-512_224. */
#define SHA512_224_H7	0x1112E6AD91D692A1L

/**
 * Initialize the hash object calculating a SHA-512_224 digest.
 *
 * @param [in] ctx  The SHA256 context object.
 * @return  1 to indicate success.
 */
int hash_sha512_224_init(HASH_SHA512 *ctx)
{
    ctx->h[0] = SHA512_224_H0;
    ctx->h[1] = SHA512_224_H1;
    ctx->h[2] = SHA512_224_H2;
    ctx->h[3] = SHA512_224_H3;
    ctx->h[4] = SHA512_224_H4;
    ctx->h[5] = SHA512_224_H5;
    ctx->h[6] = SHA512_224_H6;
    ctx->h[7] = SHA512_224_H7;

    ctx->o = 0;
    ctx->len_lo = 0;
    ctx->len_hi = 0;

    return 1;
}

/**
 * Finalize the message digest for SHA-512_224.
 * Output 224 bits or 28 bytes.
 *
 * @param [in] md   The message digest buffer.
 * @param [in] ctx  The SHA512 context object.
 * @return  1 to indicate success.
 */
int hash_sha512_224_final(unsigned char *md, HASH_SHA512 *ctx)
{
    uint8_t i, j;
    uint64_t *h = ctx->h;

    hash_sha512_fin(ctx);

    for (i=0; i<3; i++)
        for (j=0; j<8; j++)
            md[i*8+j] = h[i] >> ((7-j)*8);
    for (j=0; j<4; j++)
        md[i*8+j] = h[i] >> ((7-j)*8);

    return 1;
}

/** The initial h0 value for SHA-512_256. */
#define SHA512_256_H0	0x22312194FC2BF72CL
/** The initial h1 value for SHA-512_256. */
#define SHA512_256_H1	0x9F555FA3C84C64C2L
/** The initial h2 value for SHA-512_256. */
#define SHA512_256_H2	0x2393B86B6F53B151L
/** The initial h3 value for SHA-512_256. */
#define SHA512_256_H3	0x963877195940EABDL
/** The initial h4 value for SHA-512_256. */
#define SHA512_256_H4	0x96283EE2A88EFFE3L
/** The initial h5 value for SHA-512_256. */
#define SHA512_256_H5	0xBE5E1E2553863992L
/** The initial h6 value for SHA-512_256. */
#define SHA512_256_H6	0x2B0199FC2C85B8AAL
/** The initial h7 value for SHA-512_256. */
#define SHA512_256_H7	0x0EB72DDC81C52CA2L

/**
 * Initialize the hash object calculating a SHA-512_224 digest.
 *
 * @param [in] ctx  The SHA256 context object.
 * @return  1 to indicate success.
 */
int hash_sha512_256_init(HASH_SHA512 *ctx)
{
    ctx->h[0] = SHA512_256_H0;
    ctx->h[1] = SHA512_256_H1;
    ctx->h[2] = SHA512_256_H2;
    ctx->h[3] = SHA512_256_H3;
    ctx->h[4] = SHA512_256_H4;
    ctx->h[5] = SHA512_256_H5;
    ctx->h[6] = SHA512_256_H6;
    ctx->h[7] = SHA512_256_H7;

    ctx->o = 0;
    ctx->len_lo = 0;
    ctx->len_hi = 0;

    return 1;
}

/**
 * Finalize the message digest for SHA-512_256.
 * Output 256 bits or 32 bytes.
 *
 * @param [in] md   The message digest buffer.
 * @param [in] ctx  The SHA512 context object.
 * @return  1 to indicate success.
 */
int hash_sha512_256_final(unsigned char *md, HASH_SHA512 *ctx)
{
    uint8_t i, j;
    uint64_t *h = ctx->h;

    hash_sha512_fin(ctx);

    for (i=0; i<4; i++)
        for (j=0; j<8; j++)
            md[i*8+j] = h[i] >> ((7-j)*8);

    return 1;
}

