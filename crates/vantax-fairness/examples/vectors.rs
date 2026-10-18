//! Prints test vectors for independent implementations of the fairness
//! algorithm (docs/FAIRNESS.md): `cargo run -p vantax-fairness --example vectors`.

use vantax_fairness::{commit, derive, stream_key, FairRng, Game};

fn main() {
    let server_seed: [u8; 32] = core::array::from_fn(|i| i as u8);
    let client_seed = "vantax test vector";
    let games = [
        Game::Dice,
        Game::Coin,
        Game::Range {
            min: -1000,
            max: 1000,
        },
        Game::Crash {
            house_edge_bps: 100,
        },
        Game::Wheel { segments: 37 },
        Game::Plinko { rows: 16 },
        Game::Mines {
            tiles: 25,
            mines: 3,
        },
        Game::Keno {
            pool: 80,
            draws: 10,
        },
        Game::Shuffle { cards: 52 },
    ];
    let mut cases = Vec::new();
    for (i, game) in games.iter().enumerate() {
        for nonce in [0u64, 1, 7, 1_000_000] {
            let outcome = derive(game, &server_seed, client_seed, nonce + i as u64).unwrap();
            cases.push(serde_json::json!({
                "game": game,
                "nonce": nonce + i as u64,
                "outcome": outcome,
                "canonical": outcome.canonical(),
            }));
        }
    }
    let mut rng = FairRng::new(&server_seed, client_seed, 0);
    let words: Vec<u32> = (0..8).map(|_| rng.next_u32()).collect();
    let doc = serde_json::json!({
        "server_seed": hex::encode(server_seed),
        "commitment": commit(&server_seed),
        "client_seed": client_seed,
        "stream_key_nonce_0": hex::encode(stream_key(&server_seed, client_seed, 0)),
        "first_words_nonce_0": words,
        "cases": cases,
    });
    println!("{}", serde_json::to_string_pretty(&doc).unwrap());
}
