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
#include "mac.h"
#include "hash.h"
#include "hash_sha1.h"
#include "hash_sha2.h"
#include "hash_sha3.h"
#include "hash_blake2b.h"
#include "hash_blake2s.h"

/** The MAC initialization function prototype. */
typedef int MAC_INIT(void *, const void *, size_t);
/** The MAC update function prototype. */
typedef int MAC_UPDATE(void *, const void *, size_t);
/** The MAC final function prototype. */
typedef int MAC_FINAL(unsigned char *, void *);

/** The method table entry for MAC functions. */
typedef struct mac_meth_st
{
    /** Name of implementation. */
    char *name;
    /** Flags of the implementaiton. */
    uint8_t flags;
    /** The MAC algorithm identifier. */
    MAC_ID id;
    /** The length of the MAC algorithm output. */
    int len;
    /** The length of the context required for the MAC algorithm. */
    int ctx_len;
    /** The initialization function of the MAC algorithm. */
    MAC_INIT *init;
    /** The update function of the MAC algorithm. */
    MAC_UPDATE *update;
    /** The finalization function of the MAC algorithm. */
    MAC_FINAL *final;
} MAC_METH;

/** The MAC structure. */
struct mac_st
{
    /** The MAC algorithm method. */
    MAC_METH *meth;
    /** The context to use with the MAC algorithm. */
    void *ctx;
};

/**
 * The MAC algorithm implementations.
 * The first entry with the matching identifier is used.
 */
static MAC_METH mac_meths[] =
{
    /* Implementation of HMAC SHA-1. */
    { "HMAC-SHA-1 C", MAC_METH_FLAG_INTERNAL,
      MAC_ID_SHA1, HASH_SHA1_LEN, 2*sizeof(HASH_SHA1),
      (MAC_INIT *)&hmac_sha1_init,
      (MAC_UPDATE *)&hash_sha1_update,
      (MAC_FINAL *)&hmac_sha1_final },
    /* Implementation of HMAC SHA-224. */
    { "HMAC-SHA-224 C", MAC_METH_FLAG_INTERNAL,
      MAC_ID_SHA224, HASH_SHA224_LEN, 2*sizeof(HASH_SHA256),
      (MAC_INIT *)&hmac_sha224_init,
      (MAC_UPDATE *)&hash_sha256_update,
      (MAC_FINAL *)&hmac_sha224_final },
    /* Implementation of HMAC SHA-256. */
    { "HMAC-SHA-256 C", MAC_METH_FLAG_INTERNAL,
      MAC_ID_SHA256, HASH_SHA256_LEN, 2*sizeof(HASH_SHA256),
      (MAC_INIT *)&hmac_sha256_init,
      (MAC_UPDATE *)&hash_sha256_update,
      (MAC_FINAL *)&hmac_sha256_final },
    /* Implementation of HMAC SHA-384. */
    { "HMAC-SHA-384 C", MAC_METH_FLAG_INTERNAL,
      MAC_ID_SHA384, HASH_SHA384_LEN, 2*sizeof(HASH_SHA512),
      (MAC_INIT *)&hmac_sha384_init,
      (MAC_UPDATE *)&hash_sha512_update,
      (MAC_FINAL *)&hmac_sha384_final },
    /* Implementation of HMAC SHA-512. */
    { "HMAC-SHA-512 C", MAC_METH_FLAG_INTERNAL,
      MAC_ID_SHA512, HASH_SHA512_LEN, 2*sizeof(HASH_SHA512),
      (MAC_INIT *)&hmac_sha512_init,
      (MAC_UPDATE *)&hash_sha512_update,
      (MAC_FINAL *)&hmac_sha512_final },
    /* Implementation of HMAC SHA-512_224. */
    { "HMAC-SHA-512_224 C", MAC_METH_FLAG_INTERNAL,
      MAC_ID_SHA512_224, HASH_SHA512_224_LEN, 2*sizeof(HASH_SHA512),
      (MAC_INIT *)&hmac_sha512_224_init,
      (MAC_UPDATE *)&hash_sha512_update,
      (MAC_FINAL *)&hmac_sha512_224_final },
    /* Implementation of HMAC SHA-512_256. */
    { "HMAC-SHA-512_256 C", MAC_METH_FLAG_INTERNAL,
      MAC_ID_SHA512_256, HASH_SHA512_256_LEN, 2*sizeof(HASH_SHA512),
      (MAC_INIT *)&hmac_sha512_256_init,
      (MAC_UPDATE *)&hash_sha512_update,
      (MAC_FINAL *)&hmac_sha512_256_final },
    /* Implementation of SHA3-224. */
    { "SHA-3_224 C", MAC_METH_FLAG_INTERNAL,
      MAC_ID_SHA3_224, HASH_SHA3_224_LEN, sizeof(HASH_SHA3),
      (MAC_INIT *)&hash_sha3_224_mac_init,
      (MAC_UPDATE *)&hash_sha3_224_update,
      (MAC_FINAL *)&hash_sha3_224_final },
    /* Implementation of SHA3-256. */
    { "SHA-3_256 C", MAC_METH_FLAG_INTERNAL,
      MAC_ID_SHA3_256, HASH_SHA3_256_LEN, sizeof(HASH_SHA3),
      (MAC_INIT *)&hash_sha3_256_mac_init,
      (MAC_UPDATE *)&hash_sha3_256_update,
      (MAC_FINAL *)&hash_sha3_256_final },
    /* Implementation of SHA3-384. */
    { "SHA-3_384 C", MAC_METH_FLAG_INTERNAL,
      MAC_ID_SHA3_384, HASH_SHA3_384_LEN, sizeof(HASH_SHA3),
      (MAC_INIT *)&hash_sha3_384_mac_init,
      (MAC_UPDATE *)&hash_sha3_384_update,
      (MAC_FINAL *)&hash_sha3_384_final },
    /* Implementation of SHA3-512. */
    { "SHA-3_512 C", MAC_METH_FLAG_INTERNAL,
      MAC_ID_SHA3_512, HASH_SHA3_512_LEN, sizeof(HASH_SHA3),
      (MAC_INIT *)&hash_sha3_512_mac_init,
      (MAC_UPDATE *)&hash_sha3_512_update,
      (MAC_FINAL *)&hash_sha3_512_final },
    /* Implementation of BLAKE2B with 224-bit output. */
    { "BLAKE2b_224 C", MAC_METH_FLAG_INTERNAL,
      MAC_ID_BLAKE2B_224, HASH_BLAKE2B_224_LEN, sizeof(HASH_BLAKE2B),
      (MAC_INIT *)&hash_blake2b_224_mac_init,
      (MAC_UPDATE *)&hash_blake2b_update,
      (MAC_FINAL *)&hash_blake2b_224_final },
    /* Implementation of BLAKE2B with 256-bit output. */
    { "BLAKE2b_256 C", MAC_METH_FLAG_INTERNAL,
      MAC_ID_BLAKE2B_256, HASH_BLAKE2B_256_LEN, sizeof(HASH_BLAKE2B),
      (MAC_INIT *)&hash_blake2b_256_mac_init,
      (MAC_UPDATE *)&hash_blake2b_update,
      (MAC_FINAL *)&hash_blake2b_256_final },
    /* Implementation of BLAKE2B with 384-bit output. */
    { "BLAKE2b_384 C", MAC_METH_FLAG_INTERNAL,
      MAC_ID_BLAKE2B_384, HASH_BLAKE2B_384_LEN, sizeof(HASH_BLAKE2B),
      (MAC_INIT *)&hash_blake2b_384_mac_init,
      (MAC_UPDATE *)&hash_blake2b_update,
      (MAC_FINAL *)&hash_blake2b_384_final },
    /* Implementation of BLAKE2B with 512-bit output. */
    { "BLAKE2b_512 C", MAC_METH_FLAG_INTERNAL,
      MAC_ID_BLAKE2B_512, HASH_BLAKE2B_512_LEN, sizeof(HASH_BLAKE2B),
      (MAC_INIT *)&hash_blake2b_512_mac_init,
      (MAC_UPDATE *)&hash_blake2b_update,
      (MAC_FINAL *)&hash_blake2b_512_final },
    /* Implementation of BLAKE2S with 224-bit output. */
    { "BLAKE2s_224 C", MAC_METH_FLAG_INTERNAL,
      MAC_ID_BLAKE2S_224, HASH_BLAKE2S_224_LEN, sizeof(HASH_BLAKE2S),
      (MAC_INIT *)&hash_blake2s_224_mac_init,
      (MAC_UPDATE *)&hash_blake2s_update,
      (MAC_FINAL *)&hash_blake2s_224_final },
    /* Implementation of BLAKE2S with 256-bit output. */
    { "BLAKE2s_256 C", MAC_METH_FLAG_INTERNAL,
      MAC_ID_BLAKE2S_256, HASH_BLAKE2S_256_LEN, sizeof(HASH_BLAKE2S),
      (MAC_INIT *)&hash_blake2s_256_mac_init,
      (MAC_UPDATE *)&hash_blake2s_update,
      (MAC_FINAL *)&hash_blake2s_256_final },
};
/** The number of MAC algorithm implementations. */
#define MAC_METHS_LEN   ((int)(sizeof(mac_meths)/sizeof(*mac_meths)))

/**
 * Get the MAC algorithm method by id.
 *
 * @param [in]  id     The MAC algorithm identifier.
 * @param [in]  flags  The method implementation flags required.
 * @parma [out] meth   The MAC algorithm method.
 * @return  HASH_ERR_NOT_FOUND when there is no implementation for the MAC
 *          algorithm.<br>
 *          0 otherwise.
 */
int mac_meth_get(MAC_ID id, int flags, MAC_METH **meth)
{
    int ret = 0;
    int i;

    *meth = NULL;
    /* Find the first matching method. */
    for (i=0; i<MAC_METHS_LEN; i++)
    {
        if ((mac_meths[i].id == id) &&
            ((mac_meths[i].flags & flags) == flags))
        {
            *meth = &mac_meths[i];
            break;
        }
    }

    if (*meth == NULL)
        ret = HASH_ERR_NOT_FOUND;

    return ret;
}

/**
 * Get the length of the digest that will be calculated using the MAC
 * algorithm.
 *
 * @param [in]  mac  The MAC algorithm identifier.
 * @param [out] len  The length of a message digest.
 * @return  HASH_ERR_PARAM_NULL when a parameter is NULL.<br>
 *          HASH_ERR_NOT_FOUND when there is no implementation for the MAC
 *          algorithm.<br>
 *          0 otherwise.
 */
int MAC_METH_get_len(MAC_ID id, int *len)
{
    int ret = HASH_ERR_NOT_FOUND;
    int i;

    /* Find the first matching method. */
    for (i=0; i<MAC_METHS_LEN; i++)
    {
        if (mac_meths[i].id == id)
        {
            *len = mac_meths[i].len;
            ret = 0;
            break;
        }
    }

    return ret;
}

/**
 * Create a MAC algorithm object.
 *
 * @param [in]  id     The MAC algorithm identifier.
 * @param [in]  flags  The method implementation flags required.
 * @param [out] mac    The MAC algorithm object.
 * @return  HASH_ERR_PARAM_NULL when MAC is NULL.<br>
 *          HASH_ERR_ALLOC when allocating dynamic memory failed.<br>
 *          HASH_ERR_NOT_FOUND when there is no implementation for the
 *          algorithm.<br>
 *          0 otherwise.
 */
int MAC_new(MAC_ID id, int flags, MAC **mac)
{
    int ret = 0;
    MAC *nh = NULL;

    if (mac == NULL)
    {
        ret = HASH_ERR_PARAM_NULL;
        goto end;
    }

    /* Allocate memory for the general MAC algorithm object. */
    nh = malloc(sizeof(*nh));
    if (nh == NULL)
    {
        ret = HASH_ERR_ALLOC;
        goto end;
    }

    memset(nh, 0, sizeof(*nh));

    ret = mac_meth_get(id, flags, &nh->meth);
    if (ret != 0)
        goto end;

    /* Allocate memory for the implementation to use. */
    nh->ctx = malloc(nh->meth->ctx_len);
    if (nh->ctx == NULL)
    {
        ret = HASH_ERR_ALLOC;
        goto end;
    }

    *mac = nh;
    nh = NULL;
end:
    MAC_free(nh);
    return ret;
}

/**
 * Free the MAC algorithm object.
 *
 * @param [in] mac  The MAC algorithm object.
 */
void MAC_free(MAC *mac)
{
    if (mac != NULL)
    {
        if (mac->ctx != NULL) free(mac->ctx);
        free(mac);
    }
}

/**
 * Initialize the MAC operation with a key.
 *
 * @param [in] mac  The MAC algorithm object.
 * @param [in] key  The key to use in the MAC.
 * @param [in] len  The length of the key.
 * @return  HASH_ERR_PARAM_NULL when mac is NULL.<br>
 *          HASH_ERR_BAD_DATA when the implementation failed to initialize.<br>
 *          0 otherwise.
 */
static int mac_init(MAC *mac, const unsigned char *key, int len)
{
    int ret = 0;

    if (mac == NULL)
    {
        ret = HASH_ERR_PARAM_NULL;
        goto end;
    }

    if (mac->meth->init(mac->ctx, key, len) == 0)
        ret = HASH_ERR_BAD_DATA;
end:
    return ret;
}

/**
 * Update the MAC operation with data.
 *
 * @param [in] mac  The MAC algorithm object.
 * @param [in] msg  The message data to digest.
 * @param [in] len  The length of the message data to digest.
 * @return  HASH_ERR_PARAM_NULL when a parameter is NULL.<br>
 *          HASH_ERR_BAD_DATA when the implementation failed to update.<br>
 *          0 otherwise.
 */
static int mac_update(MAC *mac, const unsigned char *msg, int len)
{
    int ret = 0;

    if ((mac == NULL) || (msg == NULL))
    {
        ret = HASH_ERR_PARAM_NULL;
        goto end;
    }

    if (mac->meth->update(mac->ctx, msg, len) == 0)
        ret = HASH_ERR_BAD_DATA;
end:
    return ret;
}

/**
 * Initialize the sign operation for calculating the MAC.
 *
 * @param [in] mac  The MAC algorithm object.
 * @param [in] key  The key to use in the MAC.
 * @param [in] len  The length of the key.
 * @return  HASH_ERR_PARAM_NULL when mac is NULL.<br>
 *          HASH_ERR_BAD_DATA when the implementation failed to initialize.<br>
 *          0 otherwise.
 */
int MAC_sign_init(MAC *mac, const unsigned char *key, int len)
{
    return mac_init(mac, key, len);
}

/**
 * Update the MAC signing operation with data.
 *
 * @param [in] mac  The MAC algorithm object.
 * @param [in] msg  The message data to digest.
 * @param [in] len  The length of the message data to digest.
 * @return  HASH_ERR_PARAM_NULL when a parameter is NULL.<br>
 *          HASH_ERR_BAD_DATA when the implementation failed to update.<br>
 *          0 otherwise.
 */
int MAC_sign_update(MAC *mac, const unsigned char *msg, int len)
{
    return mac_update(mac, msg, len);
}

/**
 * Finalize the signing operation and output the MAC.
 *
 * @param [in] mac   The MAC algorithm object.
 * @param [in] data  The message digest.
 * @return  HASH_ERR_PARAM_NULL when a parameter is NULL.<br>
 *          HASH_ERR_BAD_DATA when the implementation failed to finalize.<br>
 *          0 otherwise.
 */
int MAC_sign_final(MAC *mac, unsigned char *data)
{
    int ret = 0;

    if ((mac == NULL) || (data == NULL))
    {
        ret = HASH_ERR_PARAM_NULL;
        goto end;
    }

    if (mac->meth->final(data, mac->ctx) == 0)
        ret = HASH_ERR_BAD_DATA;
end:
    return ret;
}

/**
 * Initialize the verification operation with a key.
 *
 * @param [in] mac  The MAC algorithm object.
 * @param [in] key  The key to use in the MAC.
 * @param [in] len  The length of the key.
 * @return  HASH_ERR_PARAM_NULL when mac is NULL.<br>
 *          HASH_ERR_BAD_DATA when the implementation failed to initialize.<br>
 *          0 otherwise.
 */
int MAC_verify_init(MAC *mac, const unsigned char *key, int len)
{
    return mac_init(mac, key, len);
}

/**
 * Update the MAC verification operation with data.
 *
 * @param [in] mac  The MAC algorithm object.
 * @param [in] msg  The message data to digest.
 * @param [in] len  The length of the message data to digest.
 * @return  HASH_ERR_PARAM_NULL when a parameter is NULL.<br>
 *          HASH_ERR_BAD_DATA when the implementation failed to update.<br>
 *          0 otherwise.
 */
int MAC_verify_update(MAC *mac, const unsigned char *msg, int len)
{
    return mac_update(mac, msg, len);
}

/**
 * Finalize the verification operation and compare with the passed in data.
 *
 * @param [in]  mac       The MAC algorithm object.
 * @param [in]  data      The message digest.
 * @param [out] verified  Whether the calculated MAC matches the passed in data.
 *                        Boolean value.
 * @return  HASH_ERR_PARAM_NULL when a parameter is NULL.<br>
 *          HASH_ERR_BAD_DATA when the implementation failed to finalize.<br>
 *          0 otherwise.
 */
int MAC_verify_final(MAC *mac, unsigned char *data, int *verified)
{
    int ret = 0;
    unsigned char cdata[64];

    if ((mac == NULL) || (data == NULL) || (verified == NULL))
    {
        ret = HASH_ERR_PARAM_NULL;
        goto end;
    }

    if (mac->meth->final(cdata, mac->ctx) == 0)
        ret = HASH_ERR_BAD_DATA;

    *verified = memcmp(cdata, data, mac->meth->len) == 0;
end:
    return ret;
}

/**
 * Get the length of the digest that will be calculated.
 *
 * @param [in] mac  The MAC algorithm object.
 * @param [in] len  The length of the message digest.
 * @return  HASH_ERR_PARAM_NULL when a parameter is NULL.<br>
 *          0 otherwise.
 */
int MAC_get_len(MAC *mac, int *len)
{
    int ret = 0;

    if ((mac == NULL) || (len == NULL))
    {
        ret = HASH_ERR_PARAM_NULL;
        goto end;
    }

    *len = mac->meth->len;
end:
    return ret;
}

/**
 * Get the name of the implementation.
 *
 * @param [in] mac   The MAC algorithm object.
 * @param [in] name  The name of the MAC implementation.
 * @return  HASH_ERR_PARAM_NULL when a parameter is NULL.<br>
 *          0 otherwise.
 */
int MAC_get_impl_name(MAC *mac, char **name)
{
    int ret = 0;

    if ((mac == NULL) || (name == NULL))
    {
        ret = HASH_ERR_PARAM_NULL;
        goto end;
    }

    *name = mac->meth->name;
end:
    return ret;
}

