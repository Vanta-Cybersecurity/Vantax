/*
 * Vantax Falcon-512: a WebAssembly module with no imports around PQClean's
 * Falcon-padded-512 (clean). Keys and signatures are standard Falcon-512:
 * 897-byte public keys, 1281-byte secret keys, 666-byte padded signatures,
 * signed over the raw message (Falcon round 3: SHAKE256(nonce || message)).
 *
 * The module never gathers randomness itself. The caller passes 48 bytes
 * from crypto.getRandomValues for each key and each signature; they seed a
 * SHAKE256 stream that Falcon reads as randombytes().
 *
 * I/O goes through fixed buffers (seed, public key, secret key, signature)
 * and one message area:
 *
 *   seed = vantax_falcon_seed()          ; write 48 random bytes
 *   vantax_falcon_keygen()               ; → public key, secret key buffers
 *   msg  = vantax_falcon_message(len)    ; write the message
 *   n    = vantax_falcon_sign(len)       ; uses seed + secret key → signature
 *   ok   = vantax_falcon_verify(n, len)  ; uses public key + signature
 */
#include <stddef.h>
#include <stdint.h>

#include "api.h"
#include "fips202.h"
#include "randombytes.h"
#include "string.h"

#define PK_LEN  PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_PUBLICKEYBYTES
#define SK_LEN  PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_SECRETKEYBYTES
#define SIG_LEN PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_BYTES
#define SEED_LEN 48

unsigned char *vantax_falcon_message_area(size_t n);

static uint8_t io_seed[SEED_LEN];
static uint8_t io_pk[PK_LEN];
static uint8_t io_sk[SK_LEN];
static uint8_t io_sig[SIG_LEN];
static uint8_t *io_msg = 0;
static size_t io_msg_len = 0;

static shake256incctx stream;
static int stream_open = 0;

static void stream_start(const char *tag) {
    size_t n = 0;
    while (tag[n]) n++;
    shake256_inc_init(&stream);
    shake256_inc_absorb(&stream, (const uint8_t *)tag, n);
    shake256_inc_absorb(&stream, io_seed, SEED_LEN);
    shake256_inc_finalize(&stream);
    stream_open = 1;
}

static void stream_end(void) {
    if (stream_open) {
        shake256_inc_ctx_release(&stream);
        stream_open = 0;
    }
    memset(io_seed, 0, SEED_LEN);
}

/* PQClean's randombytes(): reads the seeded stream; traps if unseeded. */
int randombytes(uint8_t *out, size_t n) {
    if (!stream_open) __builtin_trap();
    shake256_inc_squeeze(out, n, &stream);
    return 0;
}

__attribute__((export_name("vantax_falcon_seed"))) uint8_t *seed_ptr(void) { return io_seed; }
__attribute__((export_name("vantax_falcon_public_key"))) uint8_t *pk_ptr(void) { return io_pk; }
__attribute__((export_name("vantax_falcon_secret_key"))) uint8_t *sk_ptr(void) { return io_sk; }
__attribute__((export_name("vantax_falcon_signature"))) uint8_t *sig_ptr(void) { return io_sig; }

/* A buffer for a message of n bytes (valid until the next call). */
__attribute__((export_name("vantax_falcon_message"))) uint8_t *msg_ptr(size_t n) {
    io_msg = vantax_falcon_message_area(n);
    io_msg_len = io_msg ? n : 0;
    return io_msg;
}

/* A key pair from the 48-byte seed. 0 on success. */
__attribute__((export_name("vantax_falcon_keygen"))) int keygen(void) {
    stream_start("vantax.falcon512.keygen.v1");
    int rc = PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_keypair(io_pk, io_sk);
    stream_end();
    return rc;
}

/* Sign the first mlen bytes of the message buffer with the secret key,
 * using the 48-byte seed as signing randomness. Returns the signature
 * length (666) or -1. */
__attribute__((export_name("vantax_falcon_sign"))) int sign(size_t mlen) {
    size_t siglen = 0;
    if (mlen > io_msg_len || (mlen > 0 && io_msg == 0)) return -1;
    stream_start("vantax.falcon512.sign.v1");
    int rc = PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_signature(io_sig, &siglen, io_msg, mlen, io_sk);
    stream_end();
    return rc == 0 ? (int)siglen : -1;
}

/* 1 if the first siglen bytes of the signature buffer are a valid signature
 * over the first mlen bytes of the message under the public key, else 0. */
__attribute__((export_name("vantax_falcon_verify"))) int verify(size_t siglen, size_t mlen) {
    if (siglen != SIG_LEN || mlen > io_msg_len || (mlen > 0 && io_msg == 0)) return 0;
    return PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_verify(io_sig, siglen, io_msg, mlen, io_pk) == 0;
}

__attribute__((export_name("vantax_falcon_sizes"))) int sizes(int which) {
    switch (which) {
        case 0: return PK_LEN;
        case 1: return SK_LEN;
        case 2: return SIG_LEN;
        default: return SEED_LEN;
    }
}
