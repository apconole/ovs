/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013 Nicira, Inc.
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
#include "random.h"

#include <errno.h>
#include <stdlib.h>
#include <sys/time.h>

#ifdef HAVE_OPENSSL
#include <openssl/evp.h>
#endif

#include "byte-order.h"
#include "entropy.h"
#include "hash.h"
#include "ovs-thread.h"
#include "timeval.h"
#include "util.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(random);

/* This is the 32-bit PRNG recommended in G. Marsaglia, "Xorshift RNGs",
 * _Journal of Statistical Software_ 8:14 (July 2003).  According to the paper,
 * it has a period of 2**32 - 1 and passes almost all tests of randomness.
 *
 * We use this PRNG instead of libc's rand() because rand() varies in quality
 * and because its maximum value also varies between 32767 and INT_MAX, whereas
 * we often want random numbers in the full range of uint32_t.
 *
 * This random number generator is intended for purposes that do not require
 * cryptographic-quality randomness. */

/* Current random state. */
DEFINE_STATIC_PER_THREAD_DATA(uint32_t, seed, 0);

static uint32_t random_next(void);

void
random_init(void)
{
    uint32_t *seedp = seed_get();
    while (!*seedp) {
        struct timeval tv;
        uint32_t entropy;
        pthread_t self;

        xgettimeofday(&tv);
        get_entropy_or_die(&entropy, 4);
        self = pthread_self();

        *seedp = (tv.tv_sec ^ tv.tv_usec ^ entropy
                  ^ hash_bytes(&self, sizeof self, 0));
    }
}

void
random_set_seed(uint32_t seed_)
{
    ovs_assert(seed_);
    *seed_get() = seed_;
}

void
random_bytes(void *p_, size_t n)
{
    uint8_t *p = p_;

    random_init();

    for (; n > 4; p += 4, n -= 4) {
        uint32_t x = random_next();
        memcpy(p, &x, 4);
    }

    if (n) {
        uint32_t x = random_next();
        memcpy(p, &x, n);
    }
}


uint32_t
random_uint32(void)
{
    random_init();
    return random_next();
}

uint64_t
random_uint64(void)
{
    uint64_t x;

    random_init();

    x = random_next();
    x |= (uint64_t) random_next() << 32;
    return x;
}

static uint32_t
random_next(void)
{
    uint32_t *seedp = seed_get_unsafe();

    *seedp ^= *seedp << 13;
    *seedp ^= *seedp >> 17;
    *seedp ^= *seedp << 5;

    return *seedp;
}


/* Cryptographic Secure Psuedo-Random Number Generator */

/* Refill a page worth of keystream at a time to amortize the block cost. */
#define CSPRNG_BUFSZ    4096

#define CHACHA_KEYLEN   32          /* 256-bit key. */

/* Reseed from the OS entropy pool after this many bytes served, matching
 * the arc4random policy of periodic reseeding. */
#define CSPRNG_RESEED   (1600 * 1024)

struct csprng {
#ifndef HAVE_OPENSSL
    uint32_t state[16];             /* ChaCha20 state:
                                     * constant|key|counter|nonce. */
#else
    EVP_CIPHER_CTX *state;          /* EVP instance for OpenSSL. */
#endif
    uint8_t buf[CSPRNG_BUFSZ];      /* Buffered keystream. */
    size_t pos;                     /* Next unused byte in 'buf'. */
    size_t served;                  /* Bytes served since last reseed. */
    int initialized;
};

#ifndef HAVE_OPENSSL
/* This is the 32-bit CSPRNG adapted from the ChaCha20 algorithm from
 * arc4random(3) and from the Linux kernel's get_random_u32().
 *
 * This is intended to provide a high-speed CSPRNG implementation that
 * can be used with some subsystems (such as conntrack) to generate
 * quality RNG values from a high quality source of entropy.
 */

#define CHACHA_ROUNDS   20

#define ROTL32(v, n)    (((v) << (n)) | ((v) >> (32 - (n))))

#define QUARTERROUND(a, b, c, d)                \
    a += b; d ^= a; d = ROTL32(d, 16);          \
    c += d; b ^= c; b = ROTL32(b, 12);          \
    a += b; d ^= a; d = ROTL32(d, 8);           \
    c += d; b ^= c; b = ROTL32(b, 7)

/* ChaCha20 constant: "expand 32-byte k". */
static const uint8_t chacha_sigma[CHACHA_K_INPUT + 1] = "expand 32-byte k";

/* Current random state. */
DEFINE_STATIC_PER_THREAD_DATA(struct csprng, cs_state, {0});

/* Produces one 64-byte ChaCha20 block from 'input' (16 words) into 'out'. */
void
chacha20_block(const uint32_t input[CHACHA_K_INPUT], uint8_t out[CHACHA_BLOCK])
{
    uint32_t x[CHACHA_K_INPUT];
    int i;

    for (i = 0; i < 16; i++) {
        x[i] = input[i];
    }

    for (i = 0; i < CHACHA_ROUNDS; i += 2) {
        /* Column rounds. */
        QUARTERROUND(x[0], x[4], x[8],  x[12]);
        QUARTERROUND(x[1], x[5], x[9],  x[13]);
        QUARTERROUND(x[2], x[6], x[10], x[14]);
        QUARTERROUND(x[3], x[7], x[11], x[15]);
        /* Diagonal rounds. */
        QUARTERROUND(x[0], x[5], x[10], x[15]);
        QUARTERROUND(x[1], x[6], x[11], x[12]);
        QUARTERROUND(x[2], x[7], x[8],  x[13]);
        QUARTERROUND(x[3], x[4], x[9],  x[14]);
    }

    for (i = 0; i < 16; i++) {
        ovs_store_le32(out + i * 4, x[i] + input[i]);
    }
}

/* (Re)keys the generator from 'key' (32 bytes) and resets the counter. */
static void
csprng_rekey(struct csprng *c, const uint8_t key[CHACHA_KEYLEN])
{
    int i;

    for (i = 0; i < 4; i++) {
        c->state[i] = ovs_load_le32(chacha_sigma + i * 4);
    }
    for (i = 0; i < 8; i++) {
        c->state[4 + i] = ovs_load_le32(key + i * 4);
    }
    /* Words 12..15: 64-bit counter + 64-bit nonce, all zeroed. */
    for (i = 12; i < 16; i++) {
        c->state[i] = 0;
    }
}

static void
csprng_seed(struct csprng *c)
{
    uint8_t key[CHACHA_KEYLEN];

    get_entropy_or_die(key, sizeof key);
    csprng_rekey(c, key);
    memset(key, 0, sizeof key);

    c->pos = sizeof c->buf;
    c->served = 0;
    c->initialized = 1;
}

/* Fills csprng with fresh keystream, reserving the first 32 bytes to re-key
 * the generator (fast key erasure / forward secrecy). */
static void
csprng_refill(struct csprng *c)
{
    size_t off;

    for (off = 0; off < sizeof c->buf; off += CHACHA_BLOCK) {
        chacha20_block(c->state, c->buf + off);
        /* Increment the 64-bit block counter (words 12..13). */
        if (++c->state[12] == 0) {
            c->state[13]++;
        }
    }

    /* Re-key from the first 32 bytes, then make them unavailable as output. */
    csprng_rekey(c, c->buf);
    memset(c->buf, 0, CHACHA_KEYLEN);
    c->pos = CHACHA_KEYLEN;
}
#else
/* This is the EVP based CSPRNG using the OpenSSL EVP framework to create a
 * long stream of bytes, and pull those.  The OpenSSL EVP manages the
 * underlying bytes, all this does is manage the policy.
 */

static void
csprng_state_destroy(void *ctx)
{
    struct csprng *csp = (struct csprng *) ctx;
    if (csp->state) {
        EVP_CIPHER_CTX_free(csp->state);
        csp->state = 0;
    }

    free(csp);
}

static struct csprng *
cs_state_get(void)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    static ovsthread_key_t cskey;

    struct csprng *csp;

    if (ovsthread_once_start(&once)) {
        ovsthread_key_create(&cskey, csprng_state_destroy);
        ovsthread_once_done(&once);
    }

    csp = ovsthread_getspecific(cskey);
    if (!csp) {
        csp = xzalloc(sizeof *csp);
        csp->state = EVP_CIPHER_CTX_new();
        if (!csp->state) {
            VLOG_FATAL("cs_random: Cipher creation error.");
        }
        ovsthread_setspecific(cskey, csp);
    }
    return csp;
}

static void
csprng_seed(struct csprng *c)
{
    uint8_t key[CHACHA_KEYLEN];
    uint8_t iv[CHACHA_K_INPUT];

    get_entropy_or_die(key, sizeof key);
    get_entropy_or_die(iv, sizeof iv);

    if (EVP_EncryptInit_ex(c->state, EVP_chacha20(), NULL, key, iv) != 1) {
        VLOG_FATAL("cs_random: EVP reseed failure.");
    }

    memset(key, 0, sizeof key);
    memset(iv, 0, sizeof iv);

    c->pos = sizeof c->buf;
    c->served = 0;
    c->initialized = 1;
}

static void
csprng_refill(struct csprng *c)
{
    static const uint8_t zero[4096];
    int outl;

    if (EVP_EncryptUpdate(c->state, c->buf, &outl, zero, sizeof c->buf) != 1 ||
        outl != sizeof c->buf) {
        VLOG_FATAL("cs_random: EVP fill failure.");
    }

    c->pos = 0;
}
#endif

uint32_t
cs_random_uint32(void)
{
    struct csprng *c = cs_state_get();
    uint32_t r;

    if (!c->initialized || c->served >= CSPRNG_RESEED) {
        csprng_seed(c);
    }

    if (c->pos + sizeof r > sizeof c->buf) {
        csprng_refill(c);
    }

    r = ovs_load_le32(c->buf + c->pos);

    /* Erase the served bytes so they cannot be recovered from the buffer.
     * See Ben Tasker's writing on backdooring a ChaCha20 CSPRNG. */
    memset(c->buf + c->pos, 0, sizeof r);

    c->pos += sizeof r;
    c->served += sizeof r;

    return r;
}
