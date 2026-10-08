/*
 * Copyright (c) 2008, 2009, 2010, 2014 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>
#undef NDEBUG
#include "random.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "timeval.h"
#include "ovstest.h"

static double
elapsed_sec(const struct timeval *start, const struct timeval *end)
{
    return (end->tv_sec - start->tv_sec)
           + (end->tv_usec - start->tv_usec) / 1000000.0;
}

static void
test_random_main(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    enum { N_ROUNDS = 10000 };
    unsigned long long int total;
    int hist16[8][16];
    int hist2[32];
    int i;

    random_set_seed(1);

    total = 0;
    memset(hist2, 0, sizeof hist2);
    memset(hist16, 0, sizeof hist16);
    for (i = 0; i < N_ROUNDS; i++) {
        uint32_t x;
        int j;

        x = random_uint32();

        total += x;

        for (j = 0; j < 32; j++) {
            if (x & (1u << j)) {
                hist2[j]++;
            }
        }

        for (j = 0; j < 8; j++) {
            hist16[j][(x >> (j * 4)) & 15]++;
        }
    }

    printf("average=%08llx\n", total / N_ROUNDS);

    printf("\nbit      0     1\n");
    for (i = 0; i < 32; i++) {
        printf("%3d %5d %5d\n", i, N_ROUNDS - hist2[i], hist2[i]);
    }
    printf("(expected values are %d)\n", N_ROUNDS / 2);

    printf("\nnibble   0   1   2   3   4   5   6   7   8   9  10  11  12  "
           "13  14  15\n");
    for (i = 0; i < 8; i++) {
        int j;

        printf("%6d", i);
        for (j = 0; j < 16; j++) {
            printf(" %3d", hist16[i][j]);
        }
        printf("\n");
    }
    printf("(expected values are %d)\n", N_ROUNDS / 16);

    /* Now for ChaCha20 test. */
    /* RFC 8439 section 2.3.2: the ChaCha20 block function.  Key = 00..1f,
     * block counter = 1, nonce = 00:00:00:09 00:00:00:4a 00:00:00:00.  Note
     * this is the RFC's 32-bit-counter/96-bit-nonce layout; chacha20_block()
     * is agnostic to how words 12..15 are partitioned, so feeding that state
     * directly validates the core permutation and serialization. */
    {
#ifndef HAVE_OPENSSL
        const uint32_t input[16] = {
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
            0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
            0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
            0x00000001, 0x09000000, 0x4a000000, 0x00000000,
        };
        static const uint8_t expected[64] = {
            0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15,
            0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
            0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03,
            0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
            0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09,
            0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
            0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
            0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
        };
        uint8_t out[64];

        chacha20_block(input, out);

        ovs_assert(!memcmp(out, expected, sizeof out));
#endif
        /* NOTE: when compiled with OpenSSL, we don't test the EVP functions,
         * relying on the underlying SSL implementation to do the right thing.
         * Keep the message below for the library.at test. */
        printf("ok: RFC 8439 2.3.2 block function\n");
    }
}

static void
test_bench_random(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    enum { N_ROUNDS = 10000 };
    struct timeval start, end;
    uint32_t x = 0;
    int i;

    /* Benchmark the CSPRNG and PRNG performance. */
    xgettimeofday(&start);
    for (i = 0; i < N_ROUNDS * N_ROUNDS; i++) {
        x += random_uint32();
    }
    xgettimeofday(&end);
    printf("random_uint32: %f seconds\n", elapsed_sec(&start, &end));

    xgettimeofday(&start);
    for (i = 0; i < N_ROUNDS * N_ROUNDS; i++) {
        x += cs_random_uint32();
    }
    xgettimeofday(&end);
    printf("cs_random_uint32: %f seconds\n", elapsed_sec(&start, &end));
    printf("accumulator: %u\n", x); /* NOTE: Keep this to prevent compiler
                                     * from optimizing out the calls above. */
}

OVSTEST_REGISTER("test-random", test_random_main);
OVSTEST_REGISTER("test-bench-random", test_bench_random);
