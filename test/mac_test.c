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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>

#include "mac.h"
#include "hash.h"
#include "../src/random.h"

#ifdef CC_CLANG
#define PRIu64 "llu"
#else
#define PRIu64 "lu"
#endif

/* Number of cycles/sec. */
uint64_t cps = 0;

/* Message buffer to hash data from. */
static unsigned char msg[16384];
/* The message lengths to test in speed test. */
static int mlen[] = { 16, 64, 256, 1024, 8192, 16384 };

/* MAC algorithm identifiers to test. */
MAC_ID id[] =
{
    MAC_ID_SHA1,
    MAC_ID_SHA224, MAC_ID_SHA256, MAC_ID_SHA384, MAC_ID_SHA512,
    MAC_ID_SHA512_224, MAC_ID_SHA512_256,
    MAC_ID_SHA3_224, MAC_ID_SHA3_256, MAC_ID_SHA3_384, MAC_ID_SHA3_512,
    MAC_ID_BLAKE2B_512, MAC_ID_BLAKE2S_256,
};

/* Number of hash ids. */
#define NUM_ID	((int)(sizeof(id)/sizeof(*id)))

/*
 * Get the current cycle count from the CPU.
 *
 * @return  Cycle counter from CPU.
 */
uint64_t get_cycles()
{
    unsigned int hi, lo;

    asm volatile ("rdtsc\n\t" : "=a" (lo), "=d"(hi));
    return ((uint64_t)lo) | (((uint64_t)hi) << 32);
}

/*
 * Calculate the number of cycles/second.
 */
void calc_cps()
{
    uint64_t end, start = get_cycles();
    sleep(1);
    end = get_cycles();
    cps = end-start;
    printf("Cycles/sec: %"PRIu64"\n", cps);
}

/*
 * Determine the number of sign operations that can be performed per second.
 *
 * @param [in] mac   The mac object to use.
 * @param [in] key   The key.
 * @param [in] klen  The length of the key.
 * @param [in] msg   The data of the message.
 * @param [in] mlen  The length of the data.
 * @param [in] dgst  The MAC sign result.
 */
void mac_sign_cycles(MAC *mac, const unsigned char *key, int klen,
    unsigned char *msg, int mlen, unsigned char *dgst)
{
    int i;
    uint64_t start, end, diff;
    int num_ops;

    /* Prime the caches, etc */
    for (i=0; i<1000; i++)
    {
        MAC_sign_init(mac, key, klen);
        MAC_sign_update(mac, msg, mlen);
        MAC_sign_final(mac, dgst);
    }

    /* Approximate number of ops in a second. */
    start = get_cycles();
    for (i=0; i<200; i++)
    {
        MAC_sign_init(mac, key, klen);
        MAC_sign_update(mac, msg, mlen);
        MAC_sign_final(mac, dgst);
    }
    end = get_cycles();
    num_ops = cps/((end-start)/200);

    /* Perform about 1 seconds worth of operations. */
    start = get_cycles();
    for (i=0; i<num_ops; i++)
    {
        MAC_sign_init(mac, key, klen);
        MAC_sign_update(mac, msg, mlen);
        MAC_sign_final(mac, dgst);
    }
    end = get_cycles();

    diff = end - start;

    printf("%6d: %7d %2.3f  %7"PRIu64" %7"PRIu64" %7.2f %9.0f %8.3f\n",
        mlen, num_ops, diff/(cps*1.0), diff/num_ops, cps/(diff/num_ops),
        (double)diff/num_ops/mlen, cps/((double)diff/num_ops)*mlen,
        (cps/((double)diff/num_ops)*mlen)/1000000);
}

/*
 * Determine the number of verification operations that can be performed per
 * second.
 *
 * @param [in] mac   The mac object to use.
 * @param [in] key   The key.
 * @param [in] klen  The length of the key.
 * @param [in] msg   The data of the message.
 * @param [in] mlen  The length of the data.
 * @param [in] data  The expected MAC data.
 */
void mac_verify_cycles(MAC *mac, const unsigned char *key, int klen,
    unsigned char *msg, int mlen, unsigned char *data)
{
    int i;
    uint64_t start, end, diff;
    int num_ops;
    int verified;

    /* Prime the caches, etc */
    for (i=0; i<1000; i++)
    {
        MAC_verify_init(mac, key, klen);
        MAC_verify_update(mac, msg, mlen);
        MAC_verify_final(mac, data, &verified);
    }

    /* Approximate number of ops in a second. */
    start = get_cycles();
    for (i=0; i<200; i++)
    {
        MAC_verify_init(mac, key, klen);
        MAC_verify_update(mac, msg, mlen);
        MAC_verify_final(mac, data, &verified);
    }
    end = get_cycles();
    num_ops = cps/((end-start)/200);

    /* Perform about 1 seconds worth of operations. */
    start = get_cycles();
    for (i=0; i<num_ops; i++)
    {
        MAC_verify_init(mac, key, klen);
        MAC_verify_update(mac, msg, mlen);
        MAC_verify_final(mac, data, &verified);
    }
    end = get_cycles();

    diff = end - start;

    printf("%6d: %7d %2.3f  %7"PRIu64" %7"PRIu64" %7.2f %9.0f %8.3f\n",
        mlen, num_ops, diff/(cps*1.0), diff/num_ops, cps/(diff/num_ops),
        (double)diff/num_ops/mlen, cps/((double)diff/num_ops)*mlen,
        (cps/((double)diff/num_ops)*mlen)/1000000);
}

/*
 * MAC the message and verify.
 *
 * @param [in] mac   The MAC object to use.
 * @param [in] key   The key data.
 * @param [in] klen  The length of the key.
 * @param [in] msg   The data of the message.
 * @param [in] mlen  The length of the data.
 * @param [in] cnt   The number of times to process message.
 */
void mac_msg(MAC *mac, const unsigned char *key, size_t klen,
    const unsigned char *msg, size_t mlen, int cnt)
{
    int i;
    unsigned char dgst[64];
    int dlen;
    int verified;

    MAC_sign_init(mac, key, klen);
    for (i=0; i<cnt; i++)
        MAC_sign_update(mac, msg, mlen);
    MAC_sign_final(mac, dgst);

    MAC_get_len(mac, &dlen);
    for (i=0; i<dlen; i++)
        printf("%02x", dgst[i]);
    printf("\n");

    MAC_verify_init(mac, key, klen);
    for (i=0; i<cnt; i++)
        MAC_verify_update(mac, msg, mlen);
    MAC_verify_final(mac, dgst, &verified);

    printf("Verified: %s\n", verified ? "YES" : "NO");
}

/*
 * Test an implementation of a MAC.
 *
 * @param [in] id     The id of the MAC algorithm to test.
 * @param [in] flags  The method implementation flags required.
 * @param [in] speed  Whether to test the speed of the implementation.
 */
int test_mac(MAC_ID id, int flags, int speed, int verify)
{
    int i;
    MAC *mac;
    char *name = "";
    unsigned char dgst[64];
    const char *key_str = "abcdefghijklmnopqrstuvwxyz";
    int klen = strlen(key_str);
    const unsigned char *key = (const unsigned char *)key_str;
    static const char *msg_a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    MAC_new(id, flags, &mac);

    MAC_get_impl_name(mac, &name);
    printf("%s\n", name);

    if (speed)
    {
        printf("%6s  %7s %5s  %7s %7s %7s %9s %8s\n", "Op", "ops", "secs",
            "c/op", "ops/s", "c/B", "B/s", "mB/s");
        if (!verify)
        {
            for (i=0; i<(int)(sizeof(mlen)/sizeof(*mlen)); i++)
                mac_sign_cycles(mac, key, klen, msg, mlen[i], dgst);
        }
        else
        {
            for (i=0; i<(int)(sizeof(mlen)/sizeof(*mlen)); i++)
                mac_verify_cycles(mac, key, klen, msg, mlen[i], dgst);
        }
        goto end;
    }

    mac_msg(mac, NULL, 0, NULL, 0, 0);
    mac_msg(mac, (uint8_t *)"key", 3,
        (uint8_t *)"The quick brown fox jumps over the lazy dog", 43, 1);
    mac_msg(mac, key, klen, (unsigned char *)msg_a, 1, 32);
    mac_msg(mac, key, klen, (unsigned char *)msg_a, 32, 1);
    mac_msg(mac, key, klen, (unsigned char *)msg_a, 1, 63);
    mac_msg(mac, key, klen, (unsigned char *)msg_a, 63, 1);
    mac_msg(mac, key, klen, (unsigned char *)msg_a, 1, 64);
    mac_msg(mac, key, klen, (unsigned char *)msg_a, 64, 1);
    mac_msg(mac, key, klen, (unsigned char *)msg_a, 1, 127);
    mac_msg(mac, key, klen, (unsigned char *)msg_a, 127, 1);
    mac_msg(mac, key, klen, (unsigned char *)msg_a, 1, 128);
    mac_msg(mac, key, klen, (unsigned char *)msg_a, 128, 1);

    MAC_free(mac);
end:
    return 0;
}

/*
 * Main entry point of program.<br>
 *  -speed       Test the speed of operations in cycles and per second.<br>
 *  -sha3_224    Test the SHA-3 224 hash algorithm.<br>
 *  -sha3_256    Test the SHA-3_256 hash algorithm.<br>
 *  -sha3_384    Test the SHA-3 384 hash algorithm.<br>
 *  -sha3_512    Test the SHA-3_512 hash algorithm.<br>
 *  -sha224      Test the SHA224 hash algorithm.<br>
 *  -sha256      Test the SHA256 hash algorithm.<br>
 *  -sha384      Test the SHA384 hash algorithm.<br>
 *  -sha512      Test the SHA512 hash algorithm.<br>
 *  -sha512_224  Test the SHA512-224 hash algorithm.<br>
 *  -sha512_256  Test the SHA512-256 hash algorithm.<br>
 *  -blake2b     Test the BLAKE2b hash algorithm with 512 bits of output.<br>
 *  -blake2s     Test the BLAKE2s hash algorithm with 256 bits of output.<br>
 *  -int         Test internal implementations only.<br>
 *  -verify      Test the speed of verification rather than signing.<br>
 *
 * @param [in] argc  The count of command line arguments.
 * @param [in] argv  The command line arguments.
 * @return  0 on success.<br>
 *          1 on test failure.
 */
int main(int argc, char *argv[])
{
    int ret = 0;
    int speed = 0;
    int verify = 0;
    int which = 0;
    int flags = 0;
    int i;
    MAC_ID alg_id;

    while (--argc)
    {
        argv++;
        alg_id = -1;

        if (strcmp(*argv, "-speed") == 0)
            speed = 1;
        else if (strcmp(*argv, "-sha3_224") == 0)
            alg_id = MAC_ID_SHA3_224;
        else if (strcmp(*argv, "-sha3_256") == 0)
            alg_id = MAC_ID_SHA3_256;
        else if (strcmp(*argv, "-sha3_384") == 0)
            alg_id = MAC_ID_SHA3_384;
        else if (strcmp(*argv, "-sha3_512") == 0)
            alg_id = MAC_ID_SHA3_512;
        else if (strcmp(*argv, "-sha224") == 0)
            alg_id = MAC_ID_SHA224;
        else if (strcmp(*argv, "-sha256") == 0)
            alg_id = MAC_ID_SHA256;
        else if (strcmp(*argv, "-sha384") == 0)
            alg_id = MAC_ID_SHA384;
        else if (strcmp(*argv, "-sha512") == 0)
            alg_id = MAC_ID_SHA512;
        else if (strcmp(*argv, "-sha512_224") == 0)
            alg_id = MAC_ID_SHA512_224;
        else if (strcmp(*argv, "-sha512_256") == 0)
            alg_id = MAC_ID_SHA512_256;
        else if (strcmp(*argv, "-blake2b") == 0)
            alg_id = MAC_ID_BLAKE2B_512;
        else if (strcmp(*argv, "-blake2s") == 0)
            alg_id = MAC_ID_BLAKE2S_256;
        else if (strcmp(*argv, "-sha1") == 0)
            alg_id = MAC_ID_SHA1;
        else if (strcmp(*argv, "-int") == 0)
            flags = MAC_METH_FLAG_INTERNAL;
        else if (strcmp(*argv, "-verify") == 0)
            verify = 1;

        if (alg_id != -1)
        {
            for (i=0; i<NUM_ID; i++)
            {
                if (id[i] == alg_id)
                    which |= 1 << i;
            }
        }
    }

    if (speed)
    {
        calc_cps();
        pseudo_random(msg, sizeof(msg));
    }

    for (i=0; i<NUM_ID; i++)
    {
        if ((which == 0) || ((which & (1 << i)) != 0))
            ret |= test_mac(id[i], flags, speed, verify);
    }

    return (ret != 0);
}

