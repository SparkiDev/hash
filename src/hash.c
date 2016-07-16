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

#include <stdlib.h>
#include <string.h>
#include "hash.h"
#ifdef OPT_HASH_OPENSSL
#include "openssl/sha.h"
#endif
#include "hash_sha1.h"
#include "hash_sha2.h"
#include "hash_sha3.h"
#include "hash_blake2b.h"
#include "hash_blake2s.h"

/** The hash initialization function prototype. */
typedef int HASH_INIT(void *);
/** The hash update function prototype. */
typedef int HASH_UPDATE(void *, const void *, size_t);
/** The hash final function prototype. */
typedef int HASH_FINAL(unsigned char *, void *);

/** The method table entry for hash functions. */
typedef struct hash_meth_st
{
    /** Name of implementation. */
    char *name;
    /** Flags of the implementaiton. */
    uint8_t flags;
    /** The hash algorithm identifier. */
    HASH_ID id;
    /** The length of the hash algorithm output. */
    int len;
    /** The length of the context required for the hash algorithm. */
    int ctx_len;
    /** The initialization function of the hash algorithm. */
    HASH_INIT *init;
    /** The update function of the hash algorithm. */
    HASH_UPDATE *update;
    /** The finalization function of the hash algorithm. */
    HASH_FINAL *final;
} HASH_METH;

/** The NTRU hash structure. */
struct hash_st
{
    /** The hash algorithm method. */
    HASH_METH *meth;
    /** The context to use with the hash algorithm. */
    void *ctx;
};

/**
 * The hash algorithm implementations.
 * The first entry with the matching identifier is used.
 */
static HASH_METH hash_meths[] =
{
#ifdef OPT_HASH_OPENSSL
    /* OpenSSL implementation of SHA-1. */
    { "SHA-224 OpenSSL", 0,
      HASH_ID_SHA1, 160/8, sizeof(SHA_CTX),
      (HASH_INIT *)&SHA1_Init, (HASH_UPDATE *)&SHA1_Update,
      (HASH_FINAL *)&SHA1_Final },
    /* OpenSSL implementation of SHA-224. */
    { "SHA-224 OpenSSL", 0,
      HASH_ID_SHA224, 224/8, sizeof(SHA256_CTX),
      (HASH_INIT *)&SHA224_Init, (HASH_UPDATE *)&SHA224_Update,
      (HASH_FINAL *)&SHA224_Final },
    /* OpenSSL implementation of SHA-256. */
    { "SHA-256 OpenSSL", 0,
      HASH_ID_SHA256, 256/8, sizeof(SHA256_CTX),
      (HASH_INIT *)&SHA256_Init, (HASH_UPDATE *)&SHA256_Update,
      (HASH_FINAL *)&SHA256_Final },
    /* OpenSSL implementation of SHA-384. */
    { "SHA-384 OpenSSL", 0,
      HASH_ID_SHA384, 384/8, sizeof(SHA512_CTX),
      (HASH_INIT *)&SHA384_Init, (HASH_UPDATE *)&SHA384_Update,
      (HASH_FINAL *)&SHA384_Final },
    /* OpenSSL implementation of SHA-512. */
    { "SHA-512 OpenSSL", 0,
      HASH_ID_SHA512, 512/8, sizeof(SHA512_CTX),
      (HASH_INIT *)&SHA512_Init, (HASH_UPDATE *)&SHA512_Update,
      (HASH_FINAL *)&SHA512_Final },
#endif
    /* Implementation of SHA-1. */
    { "SHA-1 C", HASH_METH_FLAG_INTERNAL,
      HASH_ID_SHA1, 160/8, sizeof(HASH_SHA1),
      (HASH_INIT *)&hash_sha1_init,
      (HASH_UPDATE *)&hash_sha1_update,
      (HASH_FINAL *)&hash_sha1_final },
    /* Implementation of SHA-224. */
    { "SHA-224 C", HASH_METH_FLAG_INTERNAL,
      HASH_ID_SHA224, 224/8, sizeof(HASH_SHA256),
      (HASH_INIT *)&hash_sha224_init,
      (HASH_UPDATE *)&hash_sha256_update,
      (HASH_FINAL *)&hash_sha224_final },
    /* Implementation of SHA-256. */
    { "SHA-256 C", HASH_METH_FLAG_INTERNAL,
      HASH_ID_SHA256, 256/8, sizeof(HASH_SHA256),
      (HASH_INIT *)&hash_sha256_init,
      (HASH_UPDATE *)&hash_sha256_update,
      (HASH_FINAL *)&hash_sha256_final },
    /* Implementation of SHA-384. */
    { "SHA-384 C", HASH_METH_FLAG_INTERNAL,
      HASH_ID_SHA384, 384/8, sizeof(HASH_SHA512),
      (HASH_INIT *)&hash_sha384_init,
      (HASH_UPDATE *)&hash_sha512_update,
      (HASH_FINAL *)&hash_sha384_final },
    /* Implementation of SHA-512. */
    { "SHA-512 C", HASH_METH_FLAG_INTERNAL,
      HASH_ID_SHA512, 512/8, sizeof(HASH_SHA512),
      (HASH_INIT *)&hash_sha512_init,
      (HASH_UPDATE *)&hash_sha512_update,
      (HASH_FINAL *)&hash_sha512_final },
    /* Implementation of SHA-512_224. */
    { "SHA-512_224 C", HASH_METH_FLAG_INTERNAL,
      HASH_ID_SHA512_224, 224/8, sizeof(HASH_SHA512),
      (HASH_INIT *)&hash_sha512_224_init,
      (HASH_UPDATE *)&hash_sha512_update,
      (HASH_FINAL *)&hash_sha512_224_final },
    /* Implementation of SHA-512_256. */
    { "SHA-512_256 C", HASH_METH_FLAG_INTERNAL,
      HASH_ID_SHA512_256, 256/8, sizeof(HASH_SHA512),
      (HASH_INIT *)&hash_sha512_256_init,
      (HASH_UPDATE *)&hash_sha512_update,
      (HASH_FINAL *)&hash_sha512_256_final },
    /* Implementation of SHA3-224. */
    { "SHA-3_224 C", HASH_METH_FLAG_INTERNAL,
      HASH_ID_SHA3_224, 224/8, sizeof(HASH_SHA3),
      (HASH_INIT *)&hash_sha3_init,
      (HASH_UPDATE *)&hash_sha3_224_update,
      (HASH_FINAL *)&hash_sha3_224_final },
    /* Implementation of SHA3-256. */
    { "SHA-3_256 C", HASH_METH_FLAG_INTERNAL,
      HASH_ID_SHA3_256, 256/8, sizeof(HASH_SHA3),
      (HASH_INIT *)&hash_sha3_init,
      (HASH_UPDATE *)&hash_sha3_256_update,
      (HASH_FINAL *)&hash_sha3_256_final },
    /* Implementation of SHA3-384. */
    { "SHA-3_384 C", HASH_METH_FLAG_INTERNAL,
      HASH_ID_SHA3_384, 384/8, sizeof(HASH_SHA3),
      (HASH_INIT *)&hash_sha3_init,
      (HASH_UPDATE *)&hash_sha3_384_update,
      (HASH_FINAL *)&hash_sha3_384_final },
    /* Implementation of SHA3-512. */
    { "SHA-3_512 C", HASH_METH_FLAG_INTERNAL,
      HASH_ID_SHA3_512, 512/8, sizeof(HASH_SHA3),
      (HASH_INIT *)&hash_sha3_init,
      (HASH_UPDATE *)&hash_sha3_512_update,
      (HASH_FINAL *)&hash_sha3_512_final },
    /* Implementation of BLAKE2B with 224-bit output. */
    { "BLAKE2b_224 C", HASH_METH_FLAG_INTERNAL,
      HASH_ID_BLAKE2B_224, 224/8, sizeof(HASH_BLAKE2B),
      (HASH_INIT *)&hash_blake2b_224_init,
      (HASH_UPDATE *)&hash_blake2b_update,
      (HASH_FINAL *)&hash_blake2b_224_final },
    /* Implementation of BLAKE2B with 256-bit output. */
    { "BLAKE2b_256 C", HASH_METH_FLAG_INTERNAL,
      HASH_ID_BLAKE2B_256, 256/8, sizeof(HASH_BLAKE2B),
      (HASH_INIT *)&hash_blake2b_256_init,
      (HASH_UPDATE *)&hash_blake2b_update,
      (HASH_FINAL *)&hash_blake2b_256_final },
    /* Implementation of BLAKE2B with 384-bit output. */
    { "BLAKE2b_384 C", HASH_METH_FLAG_INTERNAL,
      HASH_ID_BLAKE2B_384, 384/8, sizeof(HASH_BLAKE2B),
      (HASH_INIT *)&hash_blake2b_384_init,
      (HASH_UPDATE *)&hash_blake2b_update,
      (HASH_FINAL *)&hash_blake2b_384_final },
    /* Implementation of BLAKE2B with 512-bit output. */
    { "BLAKE2b_512 C", HASH_METH_FLAG_INTERNAL,
      HASH_ID_BLAKE2B_512, 512/8, sizeof(HASH_BLAKE2B),
      (HASH_INIT *)&hash_blake2b_512_init,
      (HASH_UPDATE *)&hash_blake2b_update,
      (HASH_FINAL *)&hash_blake2b_512_final },
    /* Implementation of BLAKE2S with 224-bit output. */
    { "BLAKE2s_224 C", HASH_METH_FLAG_INTERNAL,
      HASH_ID_BLAKE2S_224, 224/8, sizeof(HASH_BLAKE2S),
      (HASH_INIT *)&hash_blake2s_224_init,
      (HASH_UPDATE *)&hash_blake2s_update,
      (HASH_FINAL *)&hash_blake2s_224_final },
    /* Implementation of BLAKE2S with 256-bit output. */
    { "BLAKE2s_256 C", HASH_METH_FLAG_INTERNAL,
      HASH_ID_BLAKE2S_256, 256/8, sizeof(HASH_BLAKE2S),
      (HASH_INIT *)&hash_blake2s_256_init,
      (HASH_UPDATE *)&hash_blake2s_update,
      (HASH_FINAL *)&hash_blake2s_256_final },
};
/** The number of hash algorithm implementations. */
#define HASH_METHS_LEN   ((int)(sizeof(hash_meths)/sizeof(*hash_meths)))

/**
 * Get the hash algorithm method by id.
 *
 * @param [in]  id     The hash algorithm identifier.
 * @param [in]  flags  The method implementation flags required.
 * @parma [out] meth   The hash algorithm method.
 * @return  HASH_ERR_NOT_FOUND when there is no implementation for the hash
 *          algorithm.<br>
 *          0 otherwise.
 */
int hash_meth_get(HASH_ID id, int flags, HASH_METH **meth)
{
    int ret = 0;
    int i;

    *meth = NULL;
    /* Find the first matching method. */
    for (i=0; i<HASH_METHS_LEN; i++)
    {
        if ((hash_meths[i].id == id) &&
            ((hash_meths[i].flags & flags) == flags))
        {
            *meth = &hash_meths[i];
            break;
        }
    }

    if (*meth == NULL)
        ret = HASH_ERR_NOT_FOUND;

    return ret;
}

/**
 * Get the length of the digest that will be calculated using the hash
 * algorithm.
 *
 * @param [in]  hash  The hash algorithm identifier.
 * @param [out] len   The length of a message digest.
 * @return  HASH_ERR_PARAM_NULL when a parameter is NULL.<br>
 *          HASH_ERR_NOT_FOUND when there is no implementation for the hash
 *          algorithm.<br>
 *          0 otherwise.
 */
int HASH_METH_get_len(HASH_ID id, int *len)
{
    int ret = HASH_ERR_NOT_FOUND;
    int i;

    /* Find the first matching method. */
    for (i=0; i<HASH_METHS_LEN; i++)
    {
        if (hash_meths[i].id == id)
        {
            *len = hash_meths[i].len;
            ret = 0;
            break;
        }
    }

    return ret;
}

/**
 * Create an hash algorithm object.
 *
 * @param [in]  id     The hash algorithm identifier.
 * @param [in]  flags  The method implementation flags required.
 * @param [out] hash   The hash algorithm object.
 * @return  HASH_ERR_PARAM_NULL when hash is NULL.<br>
 *          HASH_ERR_ALLOC when allocating dynamic memory failed.<br>
 *          HASH_ERR_NOT_FOUND when there is no implementation for the
 *          algorithm.<br>
 *          0 otherwise.
 */
int HASH_new(HASH_ID id, int flags, HASH **hash)
{
    int ret = 0;
    HASH *nh = NULL;

    if (hash == NULL)
    {
        ret = HASH_ERR_PARAM_NULL;
        goto end;
    }

    /* Allocate memory for the general hash algorithm object. */
    nh = malloc(sizeof(*nh));
    if (nh == NULL)
    {
        ret = HASH_ERR_ALLOC;
        goto end;
    }

    memset(nh, 0, sizeof(*nh));

    ret = hash_meth_get(id, flags, &nh->meth);
    if (ret != 0)
        goto end;

    /* Allocate memory for the implementation to use. */
    nh->ctx = malloc(nh->meth->ctx_len);
    if (nh->ctx == NULL)
    {
        ret = HASH_ERR_ALLOC;
        goto end;
    }

    *hash = nh;
    nh = NULL;
end:
    HASH_free(nh);
    return ret;
}

/**
 * Free the hash algorithm object.
 *
 * @param [in] hash  The hash algorithm object.
 */
void HASH_free(HASH *hash)
{
    if (hash != NULL)
    {
        if (hash->ctx != NULL) free(hash->ctx);
        free(hash);
    }
}

/**
 * Initialize the hash operation for calculating a digest.
 *
 * @param [in] hash  The hash algorithm object.
 * @return  HASH_ERR_PARAM_NULL when hash is NULL.<br>
 *          HASH_ERR_BAD_DATA when the implementation failed to initialize.<br>
 *          0 otherwise.
 */
int HASH_init(HASH *hash)
{
    int ret = 0;

    if (hash == NULL)
    {
        ret = HASH_ERR_PARAM_NULL;
        goto end;
    }

    if (hash->meth->init(hash->ctx) == 0)
        ret = HASH_ERR_BAD_DATA;
end:
    return ret;
}

/**
 * Update the hash operation with data.
 *
 * @param [in] hash  The hash algorithm object.
 * @param [in] msg   The message data to digest.
 * @param [in] len   The length of the message data to digest.
 * @return  HASH_ERR_PARAM_NULL when a parameter is NULL.<br>
 *          HASH_ERR_BAD_DATA when the implementation failed to update.<br>
 *          0 otherwise.
 */
int HASH_update(HASH *hash, const unsigned char *msg, int len)
{
    int ret = 0;

    if ((hash == NULL) || (msg == NULL))
    {
        ret = HASH_ERR_PARAM_NULL;
        goto end;
    }

    if (hash->meth->update(hash->ctx, msg, len) == 0)
        ret = HASH_ERR_BAD_DATA;
end:
    return ret;
}

/**
 * Finalize the hash operation and output the digest.
 *
 * @param [in] hash  The hash algorithm object.
 * @param [in] data  The message digest.
 * @return  HASH_ERR_PARAM_NULL when a parameter is NULL.<br>
 *          HASH_ERR_BAD_DATA when the implementation failed to finalize.<br>
 *          0 otherwise.
 */
int HASH_final(HASH *hash, unsigned char *data)
{
    int ret = 0;

    if ((hash == NULL) || (data == NULL))
    {
        ret = HASH_ERR_PARAM_NULL;
        goto end;
    }

    if (hash->meth->final(data, hash->ctx) == 0)
        ret = HASH_ERR_BAD_DATA;
end:
    return ret;
}

/**
 * Get the length of the digest that will be calculated.
 *
 * @param [in] hash  The hash algorithm object.
 * @param [in] len   The length of the message digest.
 * @return  HASH_ERR_PARAM_NULL when a parameter is NULL.<br>
 *          0 otherwise.
 */
int HASH_get_len(HASH *hash, int *len)
{
    int ret = 0;

    if ((hash == NULL) || (len == NULL))
    {
        ret = HASH_ERR_PARAM_NULL;
        goto end;
    }

    *len = hash->meth->len;
end:
    return ret;
}

/**
 * Get the name of the implementation.
 *
 * @param [in] hash  The hash algorithm object.
 * @param [in] name  The name of the hash implementation.
 * @return  HASH_ERR_PARAM_NULL when a parameter is NULL.<br>
 *          0 otherwise.
 */
int HASH_get_impl_name(HASH *hash, char **name)
{
    int ret = 0;

    if ((hash == NULL) || (name == NULL))
    {
        ret = HASH_ERR_PARAM_NULL;
        goto end;
    }

    *name = hash->meth->name;
end:
    return ret;
}

