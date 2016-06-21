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

/* Error codes */
/** Failed to find the requested data. */
#define HASH_ERR_NOT_FOUND      1
/** The data passed in is invalid for the operation. */
#define HASH_ERR_BAD_DATA       2
/** The length passed in is invalid for the operation. */
#define HASH_ERR_BAD_LEN        3
/** A function call parameter is NULL when this is not valid. */
#define HASH_ERR_PARAM_NULL     4
/** The object was not initialized. */
#define HASH_ERR_INIT           10
/** Failure to allocate dynamic memory. */
#define HASH_ERR_ALLOC          20
/** Failed to generate require random data. */
#define HASH_ERR_RANDOM         30

/** The hash algorithm identifier for SHA-224. */
#define HASH_ID_SHA224			1
/** The hash algorithm identifier for SHA-256. */
#define HASH_ID_SHA256			2
/** The hash algorithm identifier for SHA-384. */
#define HASH_ID_SHA384			3
/** The hash algorithm identifier for SHA-512. */
#define HASH_ID_SHA512			4
/** The hash algorithm identifier for SHA-512_224. */
#define HASH_ID_SHA512_224		5
/** The hash algorithm identifier for SHA-512_256. */
#define HASH_ID_SHA512_256		6

/** The hash algorithm identifier for SHA3-224. */
#define HASH_ID_SHA3_224		7
/** The hash algorithm identifier for SHA3-256. */
#define HASH_ID_SHA3_256		8
/** The hash algorithm identifier for SHA3-384. */
#define HASH_ID_SHA3_384		9
/** The hash algorithm identifier for SHA3-512. */
#define HASH_ID_SHA3_512		10

/** The hash algorithm identifier for BLAKE2B with 224-bit output. */
#define HASH_ID_BLAKE2B_224		11
/** The hash algorithm identifier for BLAKE2B with 256-bit output. */
#define HASH_ID_BLAKE2B_256		12
/** The hash algorithm identifier for BLAKE2B with 384-bit output. */
#define HASH_ID_BLAKE2B_384		13
/** The hash algorithm identifier for BLAKE2B with 512-bit output. */
#define HASH_ID_BLAKE2B_512		14

/** The hash algorithm identifier for BLAKE2S with 224-bit output. */
#define HASH_ID_BLAKE2S_224		15
/** The hash algorithm identifier for BLAKE2S with 256-bit output. */
#define HASH_ID_BLAKE2S_256		16

/** Flag indicates the method implementation is internal code. */
#define HASH_METH_FLAG_INTERNAL		0x01
 
/** The hash algorithm identifier type. */
typedef int HASH_ID;

/** The hash algorithm strucutre. */
typedef struct hash_st HASH;


int HASH_METH_get_len(HASH_ID id, int *len);

int HASH_new(HASH_ID id, int flags, HASH **hash);
void HASH_free(HASH *hash);

int HASH_init(HASH *hash);
int HASH_update(HASH *hash, const unsigned char *msg, int len);
int HASH_final(HASH *hash, unsigned char *data);

int HASH_get_len(HASH *hash, int *len);
int HASH_get_impl_name(HASH *hash, char **name);

