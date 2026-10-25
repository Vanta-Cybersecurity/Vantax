#!/usr/bin/env bash
# Build Falcon-512 for the browser: dist/falcon512.wasm (no imports).
#   ./build.sh        the module the site uses
#   ./build.sh kat    also dist/falcon512-kat.wasm, which reproduces the NIST
#                     known-answer test (see js/falcon.test.mjs)
# Needs clang and wasm-ld (LLVM 15 or later). No emscripten, no libc.
set -euo pipefail
cd "$(dirname "$0")"
CC="${CC:-clang}"
V=vendor/pqclean
FALCON="$V/falcon-padded-512/codec.c $V/falcon-padded-512/common.c $V/falcon-padded-512/fft.c $V/falcon-padded-512/fpr.c \
        $V/falcon-padded-512/keygen.c $V/falcon-padded-512/pqclean.c $V/falcon-padded-512/rng.c $V/falcon-padded-512/sign.c \
        $V/falcon-padded-512/vrfy.c $V/common/fips202.c"
FLAGS=(--target=wasm32-unknown-unknown -O2 -std=c11 -ffreestanding -nostdlib -fno-builtin -isystem src/libc -I"$V/common" -I"$V/falcon-padded-512"
       -Wall -Wno-unused-function -Wl,--no-entry -Wl,--stack-first -Wl,-z,stack-size=1048576
       -Wl,--initial-memory=2097152 -Wl,--strip-all)
mkdir -p dist
"$CC" "${FLAGS[@]}" -o dist/falcon512.wasm src/vantax_falcon.c src/libc/libc.c $FALCON
echo "dist/falcon512.wasm  $(wc -c < dist/falcon512.wasm) bytes  sha256 $(sha256sum dist/falcon512.wasm | cut -d' ' -f1)"
if [[ "${1:-}" == "kat" ]]; then
  "$CC" "${FLAGS[@]}" -o dist/falcon512-kat.wasm src/kat.c src/libc/libc.c $FALCON $V/common/aes.c $V/common/nistkatrng.c
  echo "dist/falcon512-kat.wasm  $(wc -c < dist/falcon512-kat.wasm) bytes"
fi
