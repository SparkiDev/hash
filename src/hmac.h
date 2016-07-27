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

/** The outer key mask. */
#define HMAC_OPAD_BYTE	0x5c
/** The inner key mask. */
#define HMAC_IPAD_BYTE	0x36

/** Performs the HMAC initialization with a digest. */
#define HMAC_INIT(ctx, key, len, dlen, init, update, fin)	\
do								\
{								\
    int i;							\
    unsigned char k[BLOCK_SIZE];				\
								\
    if (len > BLOCK_SIZE)					\
    {								\
        init(ctx);						\
        update(ctx, key, len);					\
        fin(k, ctx);						\
        len = dlen;						\
    }								\
    else							\
        memcpy(k, key, len);					\
    for (i=len; i<BLOCK_SIZE; i++)				\
        k[i] = 0;						\
								\
    init(ctx);							\
    for (i=0; i<BLOCK_SIZE; i++)				\
        k[i] ^= HMAC_IPAD_BYTE;					\
    update(ctx, k, BLOCK_SIZE);					\
								\
    init(&ctx[1]);						\
    for (i=0; i<BLOCK_SIZE; i++)				\
        k[i] ^= HMAC_IPAD_BYTE ^ HMAC_OPAD_BYTE;		\
    update(&ctx[1], k, BLOCK_SIZE);				\
}								\
while (0)

/** Performs the HMAC finalization with a digest. */
#define HMAC_FINAL(md, ctx, len, update, fin)			\
do								\
{								\
    unsigned char dgst[len];					\
    fin(dgst, ctx);						\
    update(&ctx[1], dgst, sizeof(dgst));			\
    fin(md, &ctx[1]);						\
}								\
while (0)


