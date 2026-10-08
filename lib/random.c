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
#include <stdbool.h>
#include <stdlib.h>
#include <sys/time.h>

#if defined(HAVE_OPENSSL) && !defined(OPENSSL_NO_CHACHA)
#include <openssl/evp.h>
#define HAVE_CHACHA20_EVP 1
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


/* Cryptographic secure pseudo-random number generator. */

/* Refill a page worth of keystream at a time to amortize the block cost. */
#define CSPRNG_BUFSZ    4096

#define CHACHA_KEYLEN   32          /* 256-bit key. */
#define CHACHA_IVLEN    16          /* ChaCha20 IV: counter and nonce. */

/* Reseed from the OS entropy pool after this many bytes served, matching
 * the arc4random policy of periodic reseeding. */
#define CSPRNG_RESEED   (1600 * 1024)

#ifdef HAVE_CHACHA20_EVP
/* The OpenSSL EVP backend consumes an IV in addition to a key. */
#define CSPRNG_SECRETS  (CHACHA_KEYLEN + CHACHA_IVLEN)
#else
#define CSPRNG_SECRETS  CHACHA_KEYLEN
#endif

struct csprng {
#ifdef HAVE_CHACHA20_EVP
    EVP_CIPHER_CTX *ctx;            /* OpenSSL EVP state, once created. */
    bool use_evp;                   /* Serve from OpenSSL rather than the
                                     * built-in implementation. */
#endif
    uint32_t state[16];             /* ChaCha20 state:
                                     * constant|key|counter|nonce. */
    uint8_t buf[CSPRNG_BUFSZ];      /* Buffered keystream. */
    size_t pos;                     /* Next unused byte in 'buf'. */
    size_t served;                  /* Bytes served since last reseed. */
    int initialized;
};

/* This is a 32-bit CSPRNG adapted from the ChaCha20 algorithm described in
 * RFC 7539 and RFC 8439, similar to arc4random(3) and the Linux kernel's
 * get_random_u32().
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

#ifndef HAVE_CHACHA20_EVP
/* Current random state. */
DEFINE_STATIC_PER_THREAD_DATA(struct csprng, cs_state, { .initialized = 0 });
#endif

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

    ovs_memzero(x, sizeof x);
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

/* Fills 'c' with fresh keystream, reserving the first 32 bytes to re-key the
 * generator (fast key erasure / forward secrecy). */
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
    ovs_memzero(c->buf, CHACHA_KEYLEN);
    c->pos = CHACHA_KEYLEN;
}

#ifdef HAVE_CHACHA20_EVP
/* This is the EVP based CSPRNG using the OpenSSL EVP framework to create a
 * long stream of bytes, and pull those.  The OpenSSL EVP manages the
 * underlying bytes, all this does is manage the policy.  It re-keys from the
 * beginning of every refill, as the built-in implementation above does, so
 * that both provide the same fast key erasure.
 */

static void
csprng_state_destroy(void *ctx)
{
    struct csprng *csp = ctx;

    if (csp->ctx) {
        EVP_CIPHER_CTX_free(csp->ctx);
        csp->ctx = NULL;
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
        csp->use_evp = true;
        ovsthread_setspecific(cskey, csp);
    }
    return csp;
}

/* (Re)keys the OpenSSL EVP state from 'key' (32 bytes) and 'iv' (16 bytes). */
static bool
csprng_evp_rekey(struct csprng *c, const uint8_t key[CHACHA_KEYLEN],
                 const uint8_t iv[CHACHA_IVLEN])
{
    return EVP_EncryptInit_ex(c->ctx, EVP_chacha20(), NULL, key, iv) == 1;
}

/* Seeds the OpenSSL EVP state from fresh entropy, returning false if OpenSSL
 * cannot provide ChaCha20. */
static bool
csprng_evp_seed(struct csprng *c, const uint8_t key[CHACHA_KEYLEN])
{
    uint8_t iv[CHACHA_IVLEN];
    bool ok;

    if (!c->ctx) {
        c->ctx = EVP_CIPHER_CTX_new();
        if (!c->ctx) {
            VLOG_WARN_ONCE("cs_random: cannot create cipher context.");
            return false;
        }
    }

    get_entropy_or_die(iv, sizeof iv);
    ok = csprng_evp_rekey(c, key, iv);
    ovs_memzero(iv, sizeof iv);

    if (!ok) {
        /* OpenSSL may not provide ChaCha20 at all, for example when it only
         * offers approved algorithms in FIPS mode.  Fall back to the built-in
         * implementation rather than failing to provide randomness. */
        VLOG_WARN_ONCE("cs_random: OpenSSL ChaCha20 unavailable, using the "
                       "built-in implementation.");
    }
    return ok;
}

/* Fills 'c' with fresh keystream from OpenSSL, reserving the first bytes to
 * re-key the generator (fast key erasure / forward secrecy). */
static void
csprng_evp_refill(struct csprng *c)
{
    static const uint8_t zero[CSPRNG_BUFSZ];
    int outl;

    if (EVP_EncryptUpdate(c->ctx, c->buf, &outl, zero, sizeof c->buf) != 1 ||
        outl != sizeof c->buf) {
        VLOG_FATAL("cs_random: EVP fill failure.");
    }

    csprng_evp_rekey(c, c->buf, c->buf + CHACHA_KEYLEN);
    ovs_memzero(c->buf, CSPRNG_SECRETS);
    c->pos = CSPRNG_SECRETS;
}
#endif /* HAVE_CHACHA20_EVP */

static void
csprng_seed(struct csprng *c)
{
    uint8_t key[CHACHA_KEYLEN];

    get_entropy_or_die(key, sizeof key);

#ifdef HAVE_CHACHA20_EVP
    if (c->use_evp && !csprng_evp_seed(c, key)) {
        c->use_evp = false;
    }
    if (!c->use_evp) {
        csprng_rekey(c, key);
    }
#else
    csprng_rekey(c, key);
#endif

    ovs_memzero(key, sizeof key);

    c->pos = sizeof c->buf;
    c->served = 0;
    c->initialized = 1;
}

void
cs_random_bytes(void *b, size_t l)
{
    struct csprng *c = cs_state_get();

    /* c->buf isn't fully available for reading because the first bytes of
     * every refill are consumed as the next key and IV. */
    ovs_assert(l <= sizeof c->buf - CSPRNG_SECRETS);

    if (!c->initialized || c->served >= CSPRNG_RESEED) {
        csprng_seed(c);
    }

    if (c->pos + l > sizeof c->buf) {
#ifdef HAVE_CHACHA20_EVP
        if (c->use_evp) {
            csprng_evp_refill(c);
        } else {
            csprng_refill(c);
        }
#else
        csprng_refill(c);
#endif
    }

    memcpy(b, c->buf + c->pos, l);
    ovs_memzero(c->buf + c->pos, l);
    c->pos += l;
    c->served += l;
}

uint32_t
cs_random_uint32(void)
{
    uint32_t r;
    cs_random_bytes(&r, sizeof r);
    return r;
}
