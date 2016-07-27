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

/** The MAC algorithm identifier for HMAC-SHA-1. */
#define MAC_ID_SHA1			0
/** The MAC algorithm identifier for HMAC-SHA-224. */
#define MAC_ID_SHA224			1
/** The MAC algorithm identifier for HMAC-SHA-256. */
#define MAC_ID_SHA256			2
/** The MAC algorithm identifier for HMAC-SHA-384. */
#define MAC_ID_SHA384			3
/** The MAC algorithm identifier for HMAC-SHA-512. */
#define MAC_ID_SHA512			4
/** The MAC algorithm identifier for HMAC-SHA-512_224. */
#define MAC_ID_SHA512_224		5
/** The MAC algorithm identifier for HMAC-SHA-512_256. */
#define MAC_ID_SHA512_256		6

/** The MAC algorithm identifier for MAC-SHA3-224. */
#define MAC_ID_SHA3_224			7
/** The MAC algorithm identifier for MAC-SHA3-256. */
#define MAC_ID_SHA3_256			8
/** The MAC algorithm identifier for MAC-SHA3-384. */
#define MAC_ID_SHA3_384			9
/** The MAC algorithm identifier for MAC-SHA3-512. */
#define MAC_ID_SHA3_512			10

/** The MAC algorithm identifier for BLAKE2B with 224-bit output. */
#define MAC_ID_BLAKE2B_224		11
/** The MAC algorithm identifier for BLAKE2B with 256-bit output. */
#define MAC_ID_BLAKE2B_256		12
/** The MAC algorithm identifier for BLAKE2B with 384-bit output. */
#define MAC_ID_BLAKE2B_384		13
/** The MAC algorithm identifier for BLAKE2B with 512-bit output. */
#define MAC_ID_BLAKE2B_512		14

/** The MAC algorithm identifier for BLAKE2S with 224-bit output. */
#define MAC_ID_BLAKE2S_224		15
/** The MAC algorithm identifier for BLAKE2S with 256-bit output. */
#define MAC_ID_BLAKE2S_256		16


/** Flag indicates the method implementation is internal code. */
#define MAC_METH_FLAG_INTERNAL		0x01

 
/** The MAC algorithm identifier type. */
typedef int MAC_ID;

/** The MAC algorithm strucutre. */
typedef struct mac_st MAC;


int MAC_new(MAC_ID id, int flags, MAC **mac);
void MAC_free(MAC *mac);

int MAC_sign_init(MAC *mac, const unsigned char *key, int len);
int MAC_sign_update(MAC *mac, const unsigned char *msg, int len);
int MAC_sign_final(MAC *mac, unsigned char *data);

int MAC_verify_init(MAC *mac, const unsigned char *key, int len);
int MAC_verify_update(MAC *mac, const unsigned char *msg, int len);
int MAC_verify_final(MAC *mac, unsigned char *data, int *verified);

int MAC_get_len(MAC *mac, int *len);
int MAC_get_impl_name(MAC *mac, char **name);

