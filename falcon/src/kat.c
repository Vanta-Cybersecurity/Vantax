/*
 * The NIST known-answer test, as PQClean's test/crypto_sign/nistkat.c
 * prints it, written into a buffer instead of stdout. Built only into
 * dist/falcon512-kat.wasm by `./build.sh kat`; its SHA-256 must equal
 * nistkat-sha256 in vendor/pqclean/falcon-padded-512/META.yml.
 */
#include <stddef.h>
#include <stdint.h>

#include "api.h"
#include "randombytes.h"
#include "string.h"

void nist_kat_init(uint8_t *entropy_input, const uint8_t *personalization_string, int security_strength);

static char out[16384];
static size_t pos = 0;

static void put(const char *s) {
    while (*s && pos < sizeof out) out[pos++] = *s++;
}

static void put_u(size_t v) {
    char tmp[24];
    int n = 0;
    do {
        tmp[n++] = (char)('0' + v % 10);
        v /= 10;
    } while (v);
    while (n) {
        char c[2] = {tmp[--n], 0};
        put(c);
    }
}

static void put_hex(const char *label, const uint8_t *a, size_t len) {
    static const char digits[] = "0123456789ABCDEF";
    put(label);
    for (size_t i = 0; i < len; i++) {
        char c[3] = {digits[a[i] >> 4], digits[a[i] & 15], 0};
        put(c);
    }
    if (len == 0) put("00");
    put("\n");
}

__attribute__((export_name("vantax_falcon_kat"))) char *kat(void) {
    uint8_t entropy[48], seed[48], m[33], sm[33 + PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_BYTES];
    uint8_t pk[PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_PUBLICKEYBYTES], sk[PQCLEAN_FALCONPADDED512_CLEAN_CRYPTO_SECRETKEYBYTES];
    size_t smlen = 0, mlen1 = 0;
    pos = 0;
    for (uint8_t i = 0; i < 48; i++) entropy[i] = i;
    nist_kat_init(entropy, NULL, 256);
    put("count = 0\n");
    randombytes(seed, 48);
    put_hex("seed = ", seed, 48);
    put("mlen = 33\n");
    randombytes(m, 33);
    put_hex("msg = ", m, 33);
    nist_kat_init(seed, NULL, 256);
    if (PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_keypair(pk, sk) != 0) return 0;
    put_hex("pk = ", pk, sizeof pk);
    put_hex("sk = ", sk, sizeof sk);
    if (PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign(sm, &smlen, m, 33, sk) != 0) return 0;
    put("smlen = ");
    put_u(smlen);
    put("\n");
    put_hex("sm = ", sm, smlen);
    if (PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_open(sm, &mlen1, sm, smlen, pk) != 0 || mlen1 != 33 || memcmp(m, sm, 33) != 0) return 0;
    out[pos < sizeof out ? pos : sizeof out - 1] = 0;
    return out;
}

__attribute__((export_name("vantax_falcon_kat_len"))) size_t kat_len(void) { return pos; }
