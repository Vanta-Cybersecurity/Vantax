/*
 * The little of the C library that Falcon needs, for a WebAssembly module
 * with no imports: memcpy, memmove, memset, memcmp, and malloc/free.
 *
 * Falcon only allocates SHAKE256 contexts (a couple of hundred bytes, always
 * released before an operation returns), so malloc is a bump allocator over
 * a fixed reserve that rewinds whenever nothing is live.
 */
#include <stddef.h>
#include <stdint.h>
#include "string.h"
#include "stdlib.h"

void *memcpy(void *dst, const void *src, size_t n) {
    unsigned char *d = dst;
    const unsigned char *s = src;
    while (n--) *d++ = *s++;
    return dst;
}

void *memmove(void *dst, const void *src, size_t n) {
    unsigned char *d = dst;
    const unsigned char *s = src;
    if (d == s || n == 0) return dst;
    if (d < s) {
        while (n--) *d++ = *s++;
    } else {
        d += n;
        s += n;
        while (n--) *--d = *--s;
    }
    return dst;
}

void *memset(void *dst, int c, size_t n) {
    unsigned char *d = dst;
    while (n--) *d++ = (unsigned char)c;
    return dst;
}

int memcmp(const void *a, const void *b, size_t n) {
    const unsigned char *x = a, *y = b;
    for (; n; n--, x++, y++) {
        if (*x != *y) return *x < *y ? -1 : 1;
    }
    return 0;
}

extern unsigned char __heap_base;

/* Room for Falcon's working allocations; the message buffer sits above it. */
#define HEAP_RESERVE (256u * 1024u)
static size_t heap_used = 0;
static unsigned live = 0;

static int ensure_memory(uintptr_t end) {
    uintptr_t have = (uintptr_t)__builtin_wasm_memory_size(0) * 65536u;
    if (end <= have) return 1;
    uintptr_t pages = (end - have + 65535u) / 65536u;
    return __builtin_wasm_memory_grow(0, pages) != (size_t)-1;
}

void *malloc(size_t n) {
    n = (n + 15u) & ~(size_t)15u;
    if (n > HEAP_RESERVE - heap_used) return NULL;
    unsigned char *p = &__heap_base + heap_used;
    if (!ensure_memory((uintptr_t)(p + n))) return NULL;
    heap_used += n;
    live++;
    return p;
}

void free(void *p) {
    if (p == NULL || live == 0) return;
    if (--live == 0) heap_used = 0;
}

_Noreturn void exit(int code) {
    (void)code;
    __builtin_trap();
}

/* The message buffer: above the allocator's reserve, grown on demand. */
unsigned char *vantax_falcon_message_area(size_t n) {
    unsigned char *base = &__heap_base + HEAP_RESERVE;
    if (!ensure_memory((uintptr_t)(base + n))) return NULL;
    return base;
}
