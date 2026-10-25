/* Minimal stdlib.h for the freestanding WebAssembly build. */
#ifndef VANTAX_FALCON_STDLIB_H
#define VANTAX_FALCON_STDLIB_H
#include <stddef.h>
void *malloc(size_t n);
void free(void *p);
_Noreturn void exit(int code);
#endif
