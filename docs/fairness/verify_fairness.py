#!/usr/bin/env python3
"""Stand-alone Vantax fairness verifier (docs/FAIRNESS.md).

Recomputes a bet's outcome from the revealed server seed, the client seed and
the nonce, and checks the seed against its commitment. Python 3.8+ standard
library only, so anyone can run it without trusting Vantax or the operator.
Signature checks need an ML-DSA-87 implementation: use `vantax fairness verify`
or the browser verifier for those.

  python3 verify_fairness.py --seed <hex> --commitment <hex> \
      --client-seed "my seed" --nonce 7 --game crash --house-edge-bps 100

  python3 verify_fairness.py --vectors vectors.json      # self-test
"""
import argparse
import hashlib
import json
import struct
import sys

MASK = 0xFFFFFFFF


# ── ChaCha20 block function (RFC 8439, section 2.3) ─────────────────────────
def _rotl(v, c):
    return ((v << c) & MASK) | (v >> (32 - c))


def _qr(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & MASK; s[d] = _rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & MASK; s[b] = _rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & MASK; s[d] = _rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & MASK; s[b] = _rotl(s[b] ^ s[c], 7)


def chacha20_block(key, counter, nonce):
    state = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    state += list(struct.unpack("<8I", key)) + [counter] + list(struct.unpack("<3I", nonce))
    w = state[:]
    for _ in range(10):
        _qr(w, 0, 4, 8, 12); _qr(w, 1, 5, 9, 13); _qr(w, 2, 6, 10, 14); _qr(w, 3, 7, 11, 15)
        _qr(w, 0, 5, 10, 15); _qr(w, 1, 6, 11, 12); _qr(w, 2, 7, 8, 13); _qr(w, 3, 4, 9, 14)
    return [(w[i] + state[i]) & MASK for i in range(16)]


# ── The per-bet generator ────────────────────────────────────────────────────
def canonical(tag, *fields):
    """CanonicalMessage: u32 big-endian length-prefixed tag, then each field.
    bytes/str fields are length-prefixed; ints are u64 big-endian."""
    out = struct.pack(">I", len(tag)) + tag.encode()
    for f in fields:
        if isinstance(f, str):
            f = f.encode()
        if isinstance(f, bytes):
            out += struct.pack(">I", len(f)) + f
        else:
            out += struct.pack(">Q", f)
    return out


class FairRng:
    def __init__(self, server_seed, client_seed, nonce):
        msg = canonical("vantax.fairness.rng.v1", server_seed, client_seed, nonce)
        self.key = hashlib.sha256(msg).digest()
        self.counter = 0
        self.words = []

    def next_u32(self):
        if not self.words:
            self.words = chacha20_block(self.key, self.counter, b"\0" * 12)
            self.counter += 1
        return self.words.pop(0)

    def below(self, n):
        zone = (1 << 32) - ((1 << 32) % n)
        while True:
            x = self.next_u32()
            if x < zone:
                return x % n

    def bits52(self):
        hi = self.next_u32()
        lo = self.next_u32() >> 12
        return (hi << 20) | lo


# ── Games ────────────────────────────────────────────────────────────────────
def crash_multiplier(h, edge_bps):
    e = 1 << 52
    return max(100, ((10000 - edge_bps) * e) // (100 * (e - h)))


def play(game, rng):
    g = game["game"]
    if g == "dice":
        return {"type": "dice", "roll": rng.below(10000)}
    if g == "coin":
        return {"type": "coin", "heads": rng.below(2) == 0}
    if g == "range":
        return {"type": "range", "value": game["min"] + rng.below(game["max"] - game["min"] + 1)}
    if g == "crash":
        return {"type": "crash", "multiplier_x100": crash_multiplier(rng.bits52(), game["house_edge_bps"])}
    if g == "wheel":
        return {"type": "wheel", "segment": rng.below(game["segments"])}
    if g == "plinko":
        path = "".join("R" if rng.below(2) == 1 else "L" for _ in range(game["rows"]))
        return {"type": "plinko", "path": path, "bucket": path.count("R")}
    if g in ("mines", "keno"):
        n, k = (game["tiles"], game["mines"]) if g == "mines" else (game["pool"], game["draws"])
        items = list(range(n)) if g == "mines" else list(range(1, n + 1))
        for i in range(k):
            j = i + rng.below(n - i)
            items[i], items[j] = items[j], items[i]
        if g == "mines":
            return {"type": "mines", "positions": sorted(items[:k])}
        return {"type": "keno", "numbers": items[:k]}
    if g == "shuffle":
        order = list(range(game["cards"]))
        for i in range(len(order) - 1, 0, -1):
            j = rng.below(i + 1)
            order[i], order[j] = order[j], order[i]
        return {"type": "shuffle", "order": order}
    raise ValueError("unknown game " + g)


def derive(game, server_seed, client_seed, nonce):
    return play(game, FairRng(server_seed, client_seed, nonce))


# ── Command line ─────────────────────────────────────────────────────────────
def self_test(path):
    v = json.load(open(path))
    seed = bytes.fromhex(v["server_seed"])
    assert hashlib.sha256(seed).hexdigest() == v["commitment"], "commitment"
    rng = FairRng(seed, v["client_seed"], 0)
    assert rng.key.hex() == v["stream_key_nonce_0"], "stream key"
    assert [rng.next_u32() for _ in range(8)] == v["first_words_nonce_0"], "words"
    for case in v["cases"]:
        got = derive(case["game"], seed, v["client_seed"], case["nonce"])
        if got != case["outcome"]:
            print("MISMATCH", case["game"], case["nonce"], got, case["outcome"])
            return 1
    print(f"ok: {len(v['cases'])} outcomes match")
    return 0


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--vectors")
    p.add_argument("--seed", help="revealed server seed, hex")
    p.add_argument("--commitment", help="published commitment, hex")
    p.add_argument("--client-seed")
    p.add_argument("--nonce", type=int)
    p.add_argument("--game", help='dice, coin, crash, ... or a JSON object like \'{"game":"mines","tiles":25,"mines":3}\'')
    p.add_argument("--house-edge-bps", type=int, default=100)
    a = p.parse_args()
    if a.vectors:
        return self_test(a.vectors)
    if not (a.seed and a.client_seed is not None and a.nonce is not None and a.game):
        p.error("--seed, --client-seed, --nonce and --game are required")
    seed = bytes.fromhex(a.seed)
    game = json.loads(a.game) if a.game.startswith("{") else {"game": a.game}
    if game["game"] == "crash":
        game.setdefault("house_edge_bps", a.house_edge_bps)
    ok = True
    if a.commitment:
        ok = hashlib.sha256(seed).hexdigest() == a.commitment.lower()
        print("commitment:", "OK, the seed opens it" if ok else "DOES NOT MATCH")
    print("outcome:", json.dumps(derive(game, seed, a.client_seed, a.nonce)))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
